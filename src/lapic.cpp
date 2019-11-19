/*
 * Local Advanced Programmable Interrupt Controller (Local APIC)
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012-2013 Udo Steinberg, Intel Corporation.
 * Copyright (C) 2014 Udo Steinberg, FireEye, Inc.
 *
 * This file is part of the NOVA microhypervisor.
 *
 * NOVA is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * NOVA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License version 2 for more details.
 */

#include "acpi.hpp"
#include "cmdline.hpp"
#include "ec.hpp"
#include "lapic.hpp"
#include "msr.hpp"
#include "rcu.hpp"
#include "stdio.hpp"
#include "timeout.hpp"
#include "vectors.hpp"
#include "vmx.hpp"
#include "pending_int.hpp"
#include "pe.hpp"

unsigned    Lapic::freq_tsc;
unsigned    Lapic::freq_bus;
uint64 Lapic::counter = 0, Lapic::prev_counter, Lapic::max_tsc = 0, Lapic::start_counter, 
        Lapic::perf_max_count, Lapic::counter_read_value; 
uint32 Lapic::tour = 0, Lapic::tour1 = 0;
const uint32 Lapic::max_info = 100000;
uint64 Lapic::perf_compteur[max_info][2];
mword Lapic::info[max_info][4];

void Lapic::init_cpuid()
{
    Paddr apic_base = Msr::read<Paddr>(Msr::IA32_APIC_BASE);

    Pd::kern.Space_mem::delreg (Pd::kern.quota, Pd::kern.mdb_cache, apic_base & ~PAGE_MASK);
    Hptp (Hpt::current()).update (Pd::kern.quota, CPU_LOCAL_APIC, 0, Hpt::HPT_NX | Hpt::HPT_G | Hpt::HPT_UC | Hpt::HPT_W | Hpt::HPT_P, apic_base & ~PAGE_MASK);

    Cpu::id = Cpu::find_by_apic_id (Lapic::id());
}

void Lapic::init(bool invariant_tsc)
{
    Paddr apic_base = Msr::read<Paddr>(Msr::IA32_APIC_BASE);
    Msr::write (Msr::IA32_APIC_BASE, apic_base | 0x800);

    uint32 svr = read (LAPIC_SVR);
    if (!(svr & 0x100))
        write (LAPIC_SVR, svr | 0x100);

    bool dl = Cpu::feature (Cpu::FEAT_TSC_DEADLINE) && !Cmdline::nodl;

    switch (lvt_max()) {
        default:
            set_lvt (LAPIC_LVT_THERM, DLV_FIXED, VEC_LVT_THERM);
        case 4:
            set_lvt (LAPIC_LVT_PERFM, DLV_FIXED, VEC_LVT_PERFM);
        case 3:
            set_lvt (LAPIC_LVT_ERROR, DLV_FIXED, VEC_LVT_ERROR);
        case 2:
            set_lvt (LAPIC_LVT_LINT1, DLV_NMI, 0);
        case 1:
            set_lvt (LAPIC_LVT_LINT0, DLV_EXTINT, 0, 1U << 16);
        case 0:
            set_lvt (LAPIC_LVT_TIMER, DLV_FIXED, VEC_LVT_TIMER, dl ? 2U << 17 : 0);
    }

    write (LAPIC_TPR, 0x10);
    write (LAPIC_TMR_DCR, 0xb);

    if ((Cpu::bsp = apic_base & 0x100)) {
        uint64 ratio = 0;

        /* read out tsc freq if supported */
        if (Cpu::vendor == Cpu::Vendor::INTEL && Cpu::family[Cpu::id] == 6) {
            unsigned const model = Cpu::model[Cpu::id];
            if ((model == 0x2a || model == 0x2d || /* Sandy Bridge */
                model >= 0x3a) && Msr::peek(Msr::MSR_PLATFORM_INFO) == ~0UL) { /* Ivy Bridge and later */
                ratio = static_cast<unsigned>(Msr::read<uint64>(Msr::MSR_PLATFORM_INFO) >> 8) & 0xff;
                freq_tsc = static_cast<unsigned>(ratio * 100000);
                freq_bus = dl ? 0 : 100000;
            }
            if (model == 0x1a || model == 0x1e || model == 0x1f || model == 0x2e || /* Nehalem */
                model == 0x25 || model == 0x2c || model == 0x2f) { /* Xeon Westmere */
                ratio = static_cast<unsigned>(Msr::read<uint64>(Msr::MSR_PLATFORM_INFO) >> 8) & 0xff;
                freq_tsc = static_cast<unsigned>(ratio * 133330);
                freq_bus = dl ? 0 : 133330;
            }
            if (model == 0x17 || model == 0xf) { /* Core 2 */
                freq_bus = Msr::read<uint64>(Msr::MSR_FSB_FREQ) & 0x7;
                switch (freq_bus) {
                    case 0b101: freq_bus = 100000; break;
                    case 0b001: freq_bus = 133330; break;
                    case 0b011: freq_bus = 166670; break;
                    case 0b010: freq_bus = 200000; break;
                    case 0b000: freq_bus = 266670; break;
                    case 0b100: freq_bus = 333330; break;
                    case 0b110: freq_bus = 400000; break;
                    default:    freq_bus = 0;      break;
                }

                ratio = (Msr::read<uint64>(Msr::IA32_PLATFORM_ID) >> 8) & 0x1f;

                freq_tsc  = static_cast<unsigned>(freq_bus * ratio);
            }
        }
        
//        send_ipi (0, 0, DLV_INIT, DSH_EXC_SELF);

        if (!freq_tsc) {
            uint32 const delay = (dl || !invariant_tsc) ? 10 : 500;

            write (LAPIC_TMR_ICR, ~0U);

            uint32 v1 = read (LAPIC_TMR_CCR);
            uint32 t1 = static_cast<uint32>(rdtsc());
            Acpi::delay (delay);
            uint32 v2 = read (LAPIC_TMR_CCR);
            uint32 t2 = static_cast<uint32>(rdtsc());

            freq_tsc = (t2 - t1) / delay;
            freq_bus = (v1 - v2) / delay;
        }

        trace (0, "TSC:%u kHz BUS:%u kHz%s%s", freq_tsc, freq_bus, !ratio ? " (measured)" : "", dl ? " DL" : "");

//        send_ipi (0, AP_BOOT_PADDR >> PAGE_BITS, DLV_SIPI, DSH_EXC_SELF);
//        Acpi::delay (1);
//        send_ipi (0, AP_BOOT_PADDR >> PAGE_BITS, DLV_SIPI, DSH_EXC_SELF);
    }

    write (LAPIC_TMR_ICR, 0);
    
    perf_max_count = (1ull<<Cpu::perf_bit_size);

    trace (TRACE_APIC, "APIC:%#lx ID:%#x VER:%#x LVT:%#x (%s Mode)", apic_base & ~PAGE_MASK, id(), version(), lvt_max(), freq_bus ? "OS" : "DL");
}

void Lapic::send_ipi (unsigned cpu, unsigned vector, Delivery_mode dlv, Shorthand dsh){
    while (EXPECT_FALSE (read (LAPIC_ICR_LO) & 1U << 12))
        pause();

    write (LAPIC_ICR_HI, Cpu::apic_id[cpu] << 24);
    write (LAPIC_ICR_LO, dsh | 1U << 14 | dlv | vector);
}

void Lapic::therm_handler() {
    Console::print("TERMAL INTERRUPT ");
}

void Lapic::perfm_handler() {
    eoi(); 
    Ec::check_memory(Ec::PES_PMI);
}

void Lapic::error_handler(){
    write (LAPIC_ESR, 0);
    write (LAPIC_ESR, 0);
}

void Lapic::timer_handler(){
    bool expired = (freq_bus ? read (LAPIC_TMR_CCR) : Msr::read<uint64>(Msr::IA32_TSC_DEADLINE)) == 0;
    if (expired)
       Timeout::check(); 

    Rcu::update();
}

void Lapic::lvt_vector (unsigned vector){    
    if(vector == VEC_LVT_PERFM){
        Counter::print<1,16> (++Counter::lvt[vector - VEC_LVT][Pe::run_number], Console_vga::COLOR_LIGHT_BLUE, vector - VEC_LVT + SPN_LVT);
        perfm_handler();
        return;
    }
    if(Ec::is_idle()){
        exec_lvt(vector, false);
    }else{
        Pending_int::add_pending_interrupt(Pending_int::INT_LAPIC, vector);
        eoi();
    }    
}

void Lapic::exec_lvt(unsigned vector, bool pending){
    unsigned lvt = vector - VEC_LVT;
    
    switch (vector) {
        case VEC_LVT_TIMER: timer_handler(); if(!pending) eoi(); break;
        case VEC_LVT_ERROR: error_handler(); if(!pending) eoi(); break;
        case VEC_LVT_PERFM: Console::panic("VEC_LVT_PERFM here"); //No VEC_LVT_PERFM here
        case VEC_LVT_THERM: therm_handler(); if(!pending) eoi(); break;
    }    
 
    Counter::print<1,16> (++Counter::lvt[lvt][Pe::run_number], Console_vga::COLOR_LIGHT_BLUE, lvt + SPN_LVT);    
}

void Lapic::ipi_vector (unsigned vector){
    unsigned ipi = vector - VEC_IPI;

    switch (vector) {
        case VEC_IPI_RRQ: Sc::rrq_handler(); break;
        case VEC_IPI_RKE: Sc::rke_handler(); break;
        case VEC_IPI_IDL: Ec::idl_handler(); break;
    }

    eoi();

    Counter::print<1,16> (++Counter::ipi[ipi][Pe::run_number], Console_vga::COLOR_LIGHT_GREEN, ipi + SPN_IPI);
}
/**
 * Called only from entry.S
 * Only used in case of virtualization
 */
void Lapic::save_counter(){
    unsigned bias = Pe::vmlaunch ? 44 : 10; // Pour calculer ces nombres, il faut activer le MTF (enable_mtf()).
    // le compteur contient alors le nombre d'instructions en mode privilegié + 1 instruction en machine virtuelle
    counter_read_value = Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0); 
    uint64 deduced_cmpteurValue = counter_read_value - bias;
    counter = counter_read_value>start_counter? deduced_cmpteurValue : 
        counter_read_value < bias ? perf_max_count + counter_read_value - bias : deduced_cmpteurValue; 
    
    Msr::write(Msr::MSR_PERF_FIXED_CTR0, counter); //0x44 is the number of hypervisor's instruction for now
    Ec::last_rip = Vmcs::read(Vmcs::GUEST_RIP);
    Ec::last_rcx = Ec::current->get_regsRCX();
}    

void Lapic::activate_pmi() {
    uint64 msr_glb = Msr::read<uint64>(Msr::MSR_PERF_GLOBAL_CTRL);
    Msr::write(Msr::MSR_PERF_GLOBAL_CTRL, msr_glb | (1ull<<32));
    Msr::write(Msr::MSR_PERF_GLOBAL_OVF_CTRL, Msr::read<uint64>(Msr::MSR_PERF_GLOBAL_OVF_CTRL) & ~(1UL<<32));
    program_pmi();
}

uint64 Lapic::read_instCounter() {
    return Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0); 
}

/**
 * This pmi programming take as parameter the number of instruction to retrieve 
 * from MAX_INSTRUCTION before PMI
 * @param number
 */
void Lapic::program_pmi(uint64 number) {
    start_counter = number ? perf_max_count - number : perf_max_count - MAX_INSTRUCTION;
//    set_lvt(LAPIC_LVT_PERFM, DLV_FIXED, VEC_LVT_PERFM);
    Msr::write(Msr::MSR_PERF_FIXED_CTR0, start_counter);
    //Qemu oddities : MSR_PERF_FIXED_CTRL must be the last PMU instruction to be 
    //executed and be updated with a dummy value
    Msr::write(Msr::MSR_PERF_FIXED_CTRL, 0x0);    
    Msr::write(Msr::MSR_PERF_FIXED_CTRL, 0xa);
    tour = 0;
    prev_counter = start_counter;
}

/**
 * This pmi programming take as parameter the exact number of instruction that 
 * must be executed before PMI
 * @param number
 */
void Lapic::program_pmi2(uint64 number) {
    start_counter = perf_max_count - number;    
//    set_lvt(LAPIC_LVT_PERFM, DLV_FIXED, VEC_LVT_PERFM);
    Msr::write(Msr::MSR_PERF_FIXED_CTR0, start_counter);
    Msr::write(Msr::MSR_PERF_FIXED_CTRL, 0x0);    
    Msr::write(Msr::MSR_PERF_FIXED_CTRL, 0xa);
    prev_counter = start_counter;
}

/**
 * cancel by writing 1 to pmc
 * We change it to program normal PMI. 
 * De toute facon, il ne risque pas d'arriver avant le prochain check_memory
 */
void Lapic::cancel_pmi() {
    start_counter = perf_max_count - MAX_INSTRUCTION;
//    set_lvt(LAPIC_LVT_PERFM, DLV_FIXED, VEC_LVT_PERFM);
    Msr::write(Msr::MSR_PERF_FIXED_CTR0, start_counter);
    Msr::write(Msr::MSR_PERF_FIXED_CTRL, 0x0);    
    Msr::write(Msr::MSR_PERF_FIXED_CTRL, 0xa);
    prev_counter = start_counter;
}

void Lapic::print_compteur(){
    Console::print(" tour %u tour1 %u\n     Compteur1    run  EIP   Reason     #Instr1     ExpectedCmpt   |    Compteur2  run  EIP  Reason  #Instr2", tour, tour1);
    uint32 half = tour1;
    if(tour<half)
        return;
    for(uint32 i=0; i<tour-half; i++){
        Console::print("[%3u] %12llx %3lx %6lx %6ld   %10lu    %12llx   | %12llx   %lx   %6lx   %ld    %10lu", i, perf_compteur[i][0], 
                info[i][0], info[i][1], info[i][2], info[i][3], perf_compteur[i][1], perf_compteur[i+half][0], info[i+half][0], info[i+half][1], info[i+half][2], info[i+half][3]);
        perf_compteur[i][0] = info[i][0] = info[i][1] = info[i][2] = info[i][3] = perf_compteur[i][1] = perf_compteur[i+half][0] = info[i+half][0] = info[i+half][1] = info[i+half][2] = info[i+half][3] = 0;
    }
    if(tour%2 != 0 && tour > 2*tour1){
        Console::print("[%3u] %12llx %3lx %6lx %6ld   %10lu    %12llx", half+1, perf_compteur[half+1][0], 
                info[half+1][0], info[half+1][1], info[half+1][2], info[half+1][3], perf_compteur[half+1][1]);
        perf_compteur[half+1][0] = info[half+1][0] = info[half+1][1] = info[half+1][2] = info[half+1][3] = perf_compteur[half+1][1] = 0;
    }
    if(tour1 > tour/2)
        for(uint32 i=tour-half; i<half; i++){
            Console::print("[%3u] %12llx %3lx %6lx %6ld   %10lu    %12llx", i, perf_compteur[i][0], 
                info[i][0], info[i][1], info[i][2], info[half+1][3], perf_compteur[i][1]);
            perf_compteur[i][0] = info[i][0] = info[i][1] = info[i][2] = info[half+1][3] = perf_compteur[i][1] = 0;
        }
}

void Lapic::write_perf(mword reason){
    perf_compteur[tour][0] = counter;
    info[tour][0] = Pe::run_number;
    info[tour][1] = Ec::last_rip;
    info[tour][2] = reason;
    info[tour][3] = diff_counter();
    tour++;
    prev_counter = counter;
}

void Lapic::stop_kernel_counting(){
    Msr::write(Msr::MSR_PERF_FIXED_CTRL, 0xa);    
}

void Lapic::compute_expected_info(uint32 exc_count, int pmi){
//    Console::print("compute_expected_info: Tour %u exc_count %u pmi %d", tour, exc_count, pmi);
    uint32 i = tour - exc_count;
    for(uint32 j=i; j<tour-1; j++){
        switch(pmi){
            case 3002:
                perf_compteur[j][1] = perf_compteur[j][0];
                break;
            case 5972:
                perf_compteur[j][1] = perf_max_count - perf_compteur[tour-1][0] + perf_compteur[j][0];
                break;
            default:
                ;
        }
    }
    if(tour == exc_count)
        tour1 = tour;
    else{
        tour1 = exc_count;
//        Console::print("Tour n'est pas egal a exc_count");
    }
}

bool Lapic::too_few_instr(){
    return (read_instCounter() - prev_counter) < MAX_INSTRUCTION/10;
}

uint64 Lapic::nb_executed_instr(){
    uint64 compteur_value = Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0);
    return compteur_value >= start_counter ? compteur_value - start_counter : perf_max_count - start_counter + compteur_value; 
}

uint32 Lapic::diff_counter(){
    if(counter>prev_counter){
        if(counter<start_counter || prev_counter>=start_counter) return static_cast<uint32>(counter-prev_counter);
        else if(prev_counter<start_counter) return static_cast<uint32>(counter-start_counter); // no way to make counter - prev_counter
        else Console::print("counter>prev_counter %llx %llx %llx", prev_counter, counter, start_counter);
    }else if(counter<prev_counter){
        if(prev_counter<start_counter || counter>start_counter)  Console::print("Aberation counter<prev_counter %llx %llx %llx", prev_counter, counter, start_counter);
        else if(counter<start_counter) return static_cast<uint32>(perf_max_count - prev_counter + counter); 
        else Console::print("counter<prev_counter %llx %llx %llx", prev_counter, counter, start_counter);
    }else //counter == prev_counter
        return 0; // No instruction was executed, probability to stop at the same number consecutively is weak
    
    return 0;
}

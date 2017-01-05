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

unsigned    Lapic::freq_tsc;
unsigned    Lapic::freq_bus;
uint64    Lapic::prev_tsc;
uint64    Lapic::begin_time;

void Lapic::init()
{
    Paddr apic_base = Msr::read<Paddr>(Msr::IA32_APIC_BASE);

    Pd::kern.Space_mem::delreg (Pd::kern.quota, apic_base & ~PAGE_MASK);
    Hptp (Hpt::current()).update (Pd::kern.quota, CPU_LOCAL_APIC, 0, Hpt::HPT_NX | Hpt::HPT_G | Hpt::HPT_UC | Hpt::HPT_W | Hpt::HPT_P, apic_base & ~PAGE_MASK);

    Msr::write (Msr::IA32_APIC_BASE, apic_base | 0x800);

    uint32 svr = read (LAPIC_SVR);
    if (!(svr & 0x100))
        write (LAPIC_SVR, svr | 0x100);

    bool dl = Cpu::feature (Cpu::FEAT_TSC_DEADLINE) && !Cmdline::nodl;

    switch (lvt_max()) {
        default:
            set_lvt (LAPIC_LVT_THERM, DLV_FIXED, VEC_LVT_THERM);
        case 4:
            set_lvt (LAPIC_LVT_PERFM, DLV_NMI, VEC_LVT_PERFM);
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

    Cpu::id = Cpu::find_by_apic_id (id());

    if ((Cpu::bsp = apic_base & 0x100)) {

        send_ipi (0, 0, DLV_INIT, DSH_EXC_SELF);

        write (LAPIC_TMR_ICR, ~0U);

        uint32 v1 = read (LAPIC_TMR_CCR);
        uint32 t1 = static_cast<uint32>(rdtsc());
        Acpi::delay (10);
        uint32 v2 = read (LAPIC_TMR_CCR);
        uint32 t2 = static_cast<uint32>(rdtsc());

        freq_tsc = (t2 - t1) / 10;
        freq_bus = (v1 - v2) / 10;

        trace (TRACE_APIC, "TSC:%u kHz BUS:%u kHz", freq_tsc, freq_bus);

        send_ipi (0, 1, DLV_SIPI, DSH_EXC_SELF);
        Acpi::delay (1);
        send_ipi (0, 1, DLV_SIPI, DSH_EXC_SELF);
    }

    write (LAPIC_TMR_ICR, 0);

    trace (TRACE_APIC, "APIC:%#lx ID:%#x VER:%#x LVT:%#x (%s Mode)", apic_base & ~PAGE_MASK, id(), version(), lvt_max(), freq_bus ? "OS" : "DL");
}

void Lapic::send_ipi (unsigned cpu, unsigned vector, Delivery_mode dlv, Shorthand dsh)
{
    while (EXPECT_FALSE (read (LAPIC_ICR_LO) & 1U << 12))
        pause();

    write (LAPIC_ICR_HI, Cpu::apic_id[cpu] << 24);
    write (LAPIC_ICR_LO, dsh | 1U << 14 | dlv | vector);
}

void Lapic::therm_handler() {
    Console::print("TERMAL INTERRUPT ");
}

void Lapic::perfm_handler() {
}

void Lapic::error_handler()
{
    write (LAPIC_ESR, 0);
    write (LAPIC_ESR, 0);
    Console::print("ERROR INTERRUPT");
}

void Lapic::timer_handler()
{
//    uint64 now = rdtsc();
//    if((now - begin_time) > max_time * freq_tsc/1000)
//    Console::print("Timer interrupt %llu", (now - begin_time)*1000000/freq_tsc);
//        Ec::check_memory(1251);
    bool expired = (freq_bus ? read (LAPIC_TMR_CCR) : Msr::read<uint64>(Msr::IA32_TSC_DEADLINE)) == 0;
    if (expired)
        Timeout::check();        

    Rcu::update();
//    if (expired){
//        eoi();
//        Ec::check_memory(1251);
//    }
}

void Lapic::lvt_vector (unsigned vector)
{
//    if(Ec::current->one_run_ok())
//        Ec::lvt_counter2++;
//    else
//        Ec::lvt_counter1++;
    
    unsigned lvt = vector - VEC_LVT;

    switch (vector) {
        case VEC_LVT_TIMER: timer_handler(); break;
        case VEC_LVT_ERROR: error_handler(); break;
        case VEC_LVT_PERFM: perfm_handler(); break;
        case VEC_LVT_THERM: therm_handler(); break;
    }

    eoi();
    uint64 now = rdtsc();
    if((now - begin_time) > max_time * freq_tsc/1000)
        Ec::check_memory(1251);
    Counter::print<1,16> (++Counter::lvt[lvt], Console_vga::COLOR_LIGHT_BLUE, lvt + SPN_LVT);
}

void Lapic::ipi_vector (unsigned vector)
{
//    if(Ec::current->one_run_ok())
//        Ec::ipi_counter2++;
//    else
//        Ec::ipi_counter1++;
    unsigned ipi = vector - VEC_IPI;

    switch (vector) {
        case VEC_IPI_RRQ: Sc::rrq_handler(); break;
        case VEC_IPI_RKE: Sc::rke_handler(); break;
        case VEC_IPI_IDL: Ec::idl_handler(); break;
    }

    eoi();

    Counter::print<1,16> (++Counter::ipi[ipi], Console_vga::COLOR_LIGHT_GREEN, ipi + SPN_IPI);
}

void Lapic::set_pmi(unsigned count)
{
    if(count==0)
        return;
    set_lvt(LAPIC_LVT_PERFM, DLV_NMI, VEC_LVT_PERFM);
    Msr::write(Msr::IA32_PERF_GLOBAL_OVF_CTRL, 1ull << 32);
    Msr::write(Msr::MSR_PERF_FIXED_CTR0, -count | 0xFFFF00000000);
    Console::print("MSR_PERF_FIXED_CTR0 %llx", Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0));
}

void Lapic::activate_pmi() {
    Msr::write(Msr::MSR_PERF_GLOBAL_CTRL, 0x700000003);
    Msr::write(Msr::MSR_PERF_FIXED_CTRL, 0xa);
    Msr::write (Msr::IA32_PMC0, 0x0);
    Msr::write(Msr::IA32_PERFEVTSEL0, 0x004100c0);
}

void Lapic::reset_counter(){
    Msr::write(Msr::MSR_PERF_FIXED_CTR0, 0x0);
    
    Msr::write(Msr::IA32_PERFEVTSEL0, 0x000100c0);
    Msr::write(Msr::IA32_PMC0, 0x0);
    Msr::write(Msr::IA32_PERFEVTSEL0, 0x004100c0);
}

/*
 * Execution Context
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012 Udo Steinberg, Intel Corporation.
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

#include "dmar.hpp"
#include "ec.hpp"
#include "gsi.hpp"
#include "lapic.hpp"
#include "vectors.hpp"
#include "vmx.hpp"
#include "vtlb.hpp"

void Ec::vmx_exception()
{
    mword vect_info = Vmcs::read (Vmcs::IDT_VECT_INFO);

    if (vect_info & 0x80000000) {

        Vmcs::write (Vmcs::ENT_INTR_INFO, vect_info & ~0x1000);

        if (vect_info & 0x800)
            Vmcs::write (Vmcs::ENT_INTR_ERROR, Vmcs::read (Vmcs::IDT_VECT_ERROR));

        if ((vect_info >> 8 & 0x7) >= 4 && (vect_info >> 8 & 0x7) <= 6)
            Vmcs::write (Vmcs::ENT_INST_LEN, Vmcs::read (Vmcs::EXI_INST_LEN));
    };

    mword intr_info = Vmcs::read (Vmcs::EXI_INTR_INFO);
    Pe_state::set_current_pe_sub_reason(intr_info & 0x7ff);
    if((intr_info & 0x7ff) == 0x30e && // Page fault
            current->regs.vtlb->is_cow(Vmcs::read (Vmcs::EXI_QUALIFICATION), Vmcs::read (Vmcs::EXI_INTR_ERROR))){
            ret_user_vmresume();
    } else {
        check_memory(PES_VMX_EXC);
    }
    
    switch (intr_info & 0x7ff) {

        default:
            current->regs.dst_portal = Vmcs::VMX_EXC_NMI;
            break;

        case 0x202:         // NMI
            asm volatile ("int $0x2" : : : "memory");
            ret_user_vmresume();

        case 0x307:         // #NM
            handle_exc_nm();
            ret_user_vmresume();

        case 0x30e:         // #PF
            mword err = Vmcs::read (Vmcs::EXI_INTR_ERROR);
            mword cr2 = Vmcs::read (Vmcs::EXI_QUALIFICATION);
            
            switch (Vtlb::miss (&current->regs, cr2, err)) {

                case Vtlb::GPA_HPA:
                    current->regs.dst_portal = Vmcs::VMX_EPT_VIOLATION;
                    break;

                case Vtlb::GLA_GPA:
                    current->regs.cr2 = cr2;
                    Vmcs::write (Vmcs::ENT_INTR_INFO,  intr_info & ~0x1000);
                    Vmcs::write (Vmcs::ENT_INTR_ERROR, err);

                case Vtlb::SUCCESS:
                    ret_user_vmresume();
            }
    }

    send_msg<ret_user_vmresume>();
}

void Ec::vmx_extint()
{
    unsigned vector = Vmcs::read (Vmcs::EXI_INTR_INFO) & 0xff;
    Pe_state::set_current_pe_sub_reason(vector);
    if (vector >= VEC_IPI)
        Lapic::ipi_vector (vector);
    else if (vector >= VEC_MSI)
        Dmar::vector (vector);
    else if (vector >= VEC_LVT)
        Lapic::lvt_vector (vector);
    else if (vector >= VEC_GSI)
        Gsi::vector (vector);
    
    ret_user_vmresume();
}

void Ec::vmx_invlpg()
{
    current->regs.tlb_flush<Vmcs>(Vmcs::read (Vmcs::EXI_QUALIFICATION));
    Vmcs::adjust_rip();
    ret_user_vmresume();
}

void Ec::vmx_cr()
{
    mword qual = Vmcs::read (Vmcs::EXI_QUALIFICATION);

    unsigned gpr = qual >> 8 & 0xf;
    unsigned acc = qual >> 4 & 0x3;
    unsigned cr  = qual      & 0xf;

    switch (acc) {
        case 0:     // MOV to CR
        {
            if (cr == 8) {
                /* Let the VMM handle CR8 */
                current->regs.dst_portal = Vmcs::VMX_CR;
                send_msg<ret_user_vmresume>();
            }

            mword old_cr0 = current->regs.read_cr<Vmcs>(0);
            mword old_cr4 = current->regs.read_cr<Vmcs>(4);

            current->regs.write_cr<Vmcs> (cr, current->regs.vmx_read_gpr (gpr));

            /*
             * Let the VMM update the PDPTE registers if necessary.
             *
             * Intel manual sections 4.4.1 of Vol. 3A and 26.3.2.4 of Vol. 3C
             * indicate the conditions when this is the case.
             */

            /* no update needed if nested paging is not enabled */
            if (!current->regs.nst_on)
                break;

            mword cr0 = current->regs.read_cr<Vmcs>(0);
            mword cr4 = current->regs.read_cr<Vmcs>(4);

            /* no update needed if not in protected mode with paging and PAE enabled */
            if (!((cr0 & Cpu::CR0_PE) &&
                  (cr0 & Cpu::CR0_PG) &&
                  (cr4 & Cpu::CR4_PAE)))
                break;

            /* no update needed if no relevant bits of CR0 or CR4 have changed */
            if ((cr != 3) &&
                ((cr0 & Cpu::CR0_CD) == (old_cr0 & Cpu::CR0_CD)) &&
                ((cr0 & Cpu::CR0_NW) == (old_cr0 & Cpu::CR0_NW)) &&
                ((cr0 & Cpu::CR0_PG) == (old_cr0 & Cpu::CR0_PG)) &&
                ((cr4 & Cpu::CR4_PAE) == (old_cr4 & Cpu::CR4_PAE)) &&
                ((cr4 & Cpu::CR4_PGE) == (old_cr4 & Cpu::CR4_PGE)) &&
                ((cr4 & Cpu::CR4_PSE) == (old_cr4 & Cpu::CR4_PSE)) &&
                ((cr4 & Cpu::CR4_SMEP) == (old_cr4 & Cpu::CR4_SMEP)))
               break;

            /* PDPTE register update necessary */
            current->regs.dst_portal = Vmcs::VMX_CR;
            send_msg<ret_user_vmresume>();

            break;
        }
        case 1:     // MOV from CR

            if (cr == 8) {
                /* Let the VMM handle CR8 */
                current->regs.dst_portal = Vmcs::VMX_CR;
                send_msg<ret_user_vmresume>();
            }

            assert (cr != 0 && cr != 4);
            current->regs.vmx_write_gpr (gpr, current->regs.read_cr<Vmcs> (cr));
            break;
        case 2:     // CLTS
            current->regs.write_cr<Vmcs> (cr, current->regs.read_cr<Vmcs> (cr) & ~Cpu::CR0_TS);
            break;
        default:
            UNREACHED;
    }

    Vmcs::adjust_rip();
    ret_user_vmresume();
}

void Ec::handle_vmx()
{
    Cpu::hazard = (Cpu::hazard | HZD_DS_ES | HZD_TR) & ~HZD_FPU;

    mword reason = Vmcs::read (Vmcs::EXI_REASON) & 0xff;

    Counter::vmi[reason]++;
//    if(reason == Vmcs::VMX_EXTINT){
//        unsigned vector = Vmcs::read (Vmcs::EXI_INTR_INFO) & 0xff;
//        trace(TRACE_VMX, "VMExit reason %ld:%d Guest rip %lx run %d counter %llx:%llx rcx %lx", reason, vector, Vmcs::read (Vmcs::GUEST_RIP), run_number, Lapic::read_instCounter(), Lapic::counter_read_value, current->regs.REG(cx));
//    } 
//    else if (reason == Vmcs::VMX_EXC_NMI){
//        mword intr_info = Vmcs::read (Vmcs::EXI_INTR_INFO);
//        if((intr_info & 0x7ff) == 0x30e) {       // #PF
//            mword err = Vmcs::read (Vmcs::EXI_INTR_ERROR);
//            mword cr2 = Vmcs::read (Vmcs::EXI_QUALIFICATION);
//            trace(0, "VMExit reason %ld:%lx:%lx Guest rip %lx run %d counter %llx rcx %lx", reason, cr2, err, Vmcs::read (Vmcs::GUEST_RIP), run_number, Lapic::read_instCounter(), current->regs.REG(cx));    
//        } 
//    }
//    else
//        trace(TRACE_VMX, "VMExit reason %ld Guest rip %lx run %d counter %llx:%llx rcx %lx", reason, Vmcs::read (Vmcs::GUEST_RIP), run_number, Lapic::read_instCounter(), Lapic::counter_read_value, current->regs.REG(cx));
    
    Pe_state::add_pe_state(new(Pd::kern.quota) Pe_state(&current->regs, Lapic::read_instCounter(), run_number, reason));

    switch (reason) {
        case Vmcs::VMX_EXC_NMI:     vmx_exception();
        case Vmcs::VMX_EXTINT:      vmx_extint();
        case Vmcs::VMX_INVLPG:      check_memory(PES_VMX_INVLPG); vmx_invlpg();
        case Vmcs::VMX_RDTSC:       
            if(run_number == 0)
                tsc1 = rdtsc();
            check_memory(PES_VMX_RDTSC); 
            vmx_resolve_rdtsc();
        case Vmcs::VMX_CR:          check_memory(PES_VMX_CR); vmx_cr();
        case Vmcs::VMX_MTF:         vmx_disable_single_step();
        case Vmcs::VMX_EPT_VIOLATION:
            check_memory(PES_VMX_EPT_VIOL); 
            current->regs.nst_error = Vmcs::read (Vmcs::EXI_QUALIFICATION);
            current->regs.nst_fault = Vmcs::read (Vmcs::INFO_PHYS_ADDR);
            break;
        case Vmcs::VMX_RDTSCP:      
            if(run_number == 0)
                tsc1 = rdtscp(tscp_rcx1);
            check_memory(PES_VMX_RDTSCP); 
            vmx_resolve_rdtsc(true);
            break;
    }
    check_memory(PES_VMX_EXIT);     
    current->regs.dst_portal = reason;

    send_msg<ret_user_vmresume>();
}

void Ec::vmx_disable_single_step() {
    switch(step_reason){
        case SR_RDTSC:
            disable_mtf();
            disable_rdtsc();
            step_reason = SR_NIL;
            break;
        case SR_PMI: {
            ++Counter::pmi_ss;
            nb_inst_single_step++;
            mword current_rip = Vmcs::read(Vmcs::GUEST_RIP);
            if(Lapic::read_instCounter() > (Lapic::perf_max_count - MAX_INSTRUCTION + 300)){
                prepare_checking();    
                Pe::print_current(true);
                Pe_state::dump();
                Console::panic("SR_PMI Too much single stepping GuestRIP %lx nbSS %llx ", current_rip, nb_inst_single_step);
            }
            if (nbInstr_to_execute > 0)
                nbInstr_to_execute--;
            if (prev_rip == current_rip) { // Rep Prefix
                nb_inst_single_step--;
                nbInstr_to_execute++; // Re-adjust the number of instruction                  
                // Console::print("EIP: %lx  prev_rip: %lx MSR_PERF_FIXED_CTR0: %lld instr: %lx", 
                // current->regs.REG(ip), prev_rip, Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), *reinterpret_cast<mword *>(current->regs.REG(ip)));
                // It may happen that this is the final instruction
                if (!current->compare_regs_mute()) {
                    //                                check_instr_number_equals(1);
                    disable_mtf();
                    check_memory(PES_SINGLE_STEP);
                }
            }
            prev_rip = current_rip;
            // No need to compare if nbInstr_to_execute > 3 
            if (nbInstr_to_execute > 3) {
                vmx_enable_single_step(SR_PMI);
                ret_user_vmresume();
            }
            if (!current->compare_regs_mute()) {
                //                            check_instr_number_equals(2);
                disable_mtf();
                check_memory(PES_SINGLE_STEP);
            } else {
                vmx_enable_single_step(SR_PMI);
                nbInstr_to_execute = 1;
                ret_user_vmresume();
            }
            break;
        }
        case SR_EQU: {
            ++Counter::pmi_ss;
            nb_inst_single_step++;
            mword current_rip = Vmcs::read(Vmcs::GUEST_RIP);
            if(Lapic::read_instCounter() > (Lapic::perf_max_count - MAX_INSTRUCTION + 300)){
                prepare_checking();    
                Pe::print_current(true);
                Pe_state::dump();
                Console::panic("SR_EQU Too much single stepping GuestRIP %lx nbSS %llx ", current_rip, nb_inst_single_step);
            }
            if (nbInstr_to_execute > 0)
                nbInstr_to_execute--;
            if (prev_rip == current_rip) { // Rep Prefix
                nb_inst_single_step--;
                nbInstr_to_execute++; // Re-adjust the number of instruction                  
                // Console::print("EIP: %lx  prev_rip: %lx MSR_PERF_FIXED_CTR0: %lld instr: %lx", 
                // current->regs.REG(ip), prev_rip, Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), *reinterpret_cast<mword *>(current->regs.REG(ip)));
                // It may happen that this is the final instruction
                if (!current->compare_regs_mute()) {
                    //                                check_instr_number_equals(3);
                    disable_mtf();
                    check_memory(PES_SINGLE_STEP);
                }
            }
            //here, single stepping 2nd run should be ok
            if (!current->compare_regs_mute()) {// if ok?
                //                            check_instr_number_equals(4);
                disable_mtf();
                check_memory(PES_SINGLE_STEP);
            } else {
                if (nbInstr_to_execute == 0) { // single stepping the first run with 2 credits instructions
                    current->restore_state1();
                    nbInstr_to_execute = distance_instruction + nb_inst_single_step + 1;
                    nb_inst_single_step = 0;
                    first_run_advanced = true;
                    vmx_enable_single_step(SR_EQU);
                    ret_user_vmresume();
                } else { // relaunch the first run without restoring the second execution state
                    vmx_enable_single_step(SR_EQU);
                    ret_user_vmresume();
                }
            }
            break;
        }
        default:
            Console::panic("No step Reason");
    }
    ret_user_vmresume();
}

void Ec::vmx_resolve_io(){
    if (Vmcs::has_mtf()) {// if the CPU honors the monitor trap flag
        enable_mtf();
        step_reason = SR_VMIO;
        current->regs.vmcs->make_current();
    } else
        vmx_emulate_io();
    ret_user_vmresume();
}

void Ec::vmx_emulate_io(){
    Console::panic("VMX_IO and monitor trap not supported : IO Emulation required");
}

void Ec::vmx_resolve_rdtsc(bool is_rdtscp) {
    if (Vmcs::has_mtf()) {// if the CPU honors the monitor trap flag
        enable_mtf();
        enable_rdtsc();
        step_reason = SR_RDTSC;
        current->regs.vmcs->make_current();
    } else
        vmx_emulate_rdtsc(is_rdtscp);
    ret_user_vmresume();
}

void Ec::vmx_enable_single_step(Step_reason reason) {
    if (Vmcs::has_mtf()) {// if the CPU honors the monitor trap flag
        enable_mtf();
        step_reason = reason;
        current->regs.vmcs->make_current();
    } else {
        Console::panic("VM Single step required and monitor trap not supported : IO Emulation required");        
    }
    ret_user_vmresume();    
}

void Ec::vmx_emulate_rdtsc(bool is_rdtscp) {
    tsc2 = is_rdtscp ? rdtscp(tscp_rcx2) : rdtsc();
    bool is_tsc_scale_defined = (Vmcs::read(Vmcs::CPU_EXEC_CTRL1) & Vmcs::CPU_TSC_MUL),
           is_tsc_offset_defined = (Vmcs::read(Vmcs::CPU_EXEC_CTRL0) & Vmcs::CPU_TSC_OFFSET);
    if(is_tsc_scale_defined || is_tsc_offset_defined){
        mword h = 0, l = 0, aux = 0;
        mword inst_addr = Vmcs::read(Vmcs::GUEST_RIP);
        mword inst_off = inst_addr & PAGE_MASK;
        uint64 entry = 0;
        Paddr physic;
        mword attrib;
        if (!current->regs.vtlb->vtlb_lookup(inst_addr, physic, attrib)) {
            Console::print("Instr_addr not found %lx", inst_addr);
        }
        uint8 *ptr = reinterpret_cast<uint8 *> (Hpt::remap_cow(Pd::current->quota, entry & ~PAGE_MASK));  
        uint16 *inst_val = reinterpret_cast<uint16 *>(ptr + inst_off);
        mword off = 0, off_hi = 0, mul = 0, mul_hi = 0;
        mul =  is_tsc_scale_defined? Vmcs::read(Vmcs::TSC_MUL) : 1;
        mul_hi = is_tsc_scale_defined ? Vmcs::read(Vmcs::TSC_MUL_HI) : 1;

        switch(*inst_val){
            case 0x310f:
                asm volatile ("rdtsc" : "=a" (l), "=d" (h));
                break;
            case 0xf901:
                asm volatile ("rdtscp" : "=a" (l), "=d" (h), "=c" (aux));
                current->regs.REG(cx) = off + aux*mul;            
                break;
            default:
                Console::print("Instr_val not found inst_addr %lx entry %llx ptr %p inst_off %lx inst_val %x", inst_addr, entry, ptr, inst_off, *inst_val);
        }       
        if (is_tsc_offset_defined) {
            off = Vmcs::read(Vmcs::TSC_OFFSET);
            off_hi = Vmcs::read(Vmcs::TSC_OFFSET_HI);
        }
        mword delta_tsc = (tsc2 - tsc1)/2;
        current->regs.REG(ax) = off + l*mul + (delta_tsc & 0xffffffff); //Consider using current->regs.vmx_write_gpr(gpr, regs_number) if there is a problem;
        current->regs.REG(dx) = off_hi + h*mul_hi + (delta_tsc >> 32);

        //    Console::print("rdtsc tsc1 %lu tsc2 %lu delta %lu ax %lu dx %lu", tscm1, tscm2, tscm2 - tscm1, current->regs.REG(ax), current->regs.REG(dx));
        current->regs.vmcs->adjust_rip();
    } else {
        mword tsc = (tsc1 + tsc2)/2;
        current->regs.REG(ax) = tsc & 0xffffffff;
        current->regs.REG(dx) = tsc >> 32;
        if(is_rdtscp)
            current->regs.REG(cx) = (tscp_rcx1 + tscp_rcx2)/2;
        //    Console::print("rdtsc tsc1 %llu tsc2 %llu delta %llu ax %lu dx %lu", tsc1, tsc2, tsc2 - tsc1, current->regs.REG(ax), current->regs.REG(dx));
        current->regs.vmcs->adjust_rip();
    }
}

void Ec::enable_rdtsc() {
    mword val = Vmcs::read(Vmcs::CPU_EXEC_CTRL0);
    val &= ~Vmcs::CPU_RDTSC;
    Vmcs::write(Vmcs::CPU_EXEC_CTRL0, val);
}

void Ec::disable_rdtsc() {
    mword val = Vmcs::read(Vmcs::CPU_EXEC_CTRL0);
    val |= Vmcs::CPU_RDTSC;
    Vmcs::write(Vmcs::CPU_EXEC_CTRL0, val);
}

void Ec::enable_mtf() {
    if (!Vmcs::has_mtf()) return;
    mword val = Vmcs::read(Vmcs::CPU_EXEC_CTRL0);
    val |= Vmcs::CPU_MONITOR_TRAP_FLAG;
    Vmcs::write(Vmcs::CPU_EXEC_CTRL0, val);
}

void Ec::disable_mtf() {
    mword val = Vmcs::read(Vmcs::CPU_EXEC_CTRL0);
    val &= ~Vmcs::CPU_MONITOR_TRAP_FLAG;
    Vmcs::write(Vmcs::CPU_EXEC_CTRL0, val);
    step_reason = SR_NIL;
}


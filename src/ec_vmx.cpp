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
#include "log.hpp"
#include "pe.hpp"
#include "log_store.hpp"
#include "pending_int.hpp"

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
            if (current->regs.nst_on) {
                current->regs.dst_portal = 0x30e;
                break;
            }

            mword err = Vmcs::read (Vmcs::EXI_INTR_ERROR);
            mword cr2 = Vmcs::read (Vmcs::EXI_QUALIFICATION);
            
            switch (Vtlb::miss (&current->regs, cr2, err, &current->cow_fields)) {

                case Vtlb::GPA_HPA:
                    current->regs.dst_portal = Vmcs::VMX_EPT_VIOLATION;
                    break;

                case Vtlb::GLA_GPA:
                    current->regs.cr2 = cr2;
                    Vmcs::write (Vmcs::ENT_INTR_INFO,  intr_info & ~0x1000);
                    Vmcs::write (Vmcs::ENT_INTR_ERROR, err);

                    [[fallthrough]];

                case Vtlb::SUCCESS:
                    ret_user_vmresume();
            }
    }

    check_memory(Ec::PES_VMX_EXC);
    send_msg<ret_user_vmresume>();
}

void Ec::vmx_extint()
{
    unsigned vector = Vmcs::read (Vmcs::EXI_INTR_INFO) & 0xff;

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
    check_memory(PES_VMX_INVLPG); 
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

void Ec::trace_vmexit(mword reason) {
    mword nst_error = 0, nst_fault = 0;
    char counter_buff[STR_MIN_LENGTH];
    uint64 counter_value = Lapic::read_instCounter();
    if(counter_value >= Lapic::perf_max_count - MAX_INSTRUCTION)
        String::print(counter_buff, "%#llx", counter_value);
    else
        String::print(counter_buff, "%llu", counter_value);
    mword guest_eip = Vmcs::read(Vmcs::GUEST_RIP);
    Paddr vtlb_hpa;
    mword vtlb_attr;
    Vtlb *guest_eip_tlb = nullptr;
    char rip_instruction[STR_MIN_LENGTH];
    if(guest_eip &&  
        current->regs.vtlb->lookup(guest_eip, vtlb_hpa, vtlb_attr, guest_eip_tlb)){
        uint8 *rip_map = reinterpret_cast<uint8*> 
            (Hpt::remap_cow(Pd::kern.quota, vtlb_hpa, 3, sizeof(mword)));
        String::print(rip_instruction, "%x %x", *rip_map, *(rip_map+1));
    } else {
        String::print(rip_instruction, "No instruction");
    }
    char next_fault[2*STR_MIN_LENGTH];
    mword next_fault_addr = (pe_guest_rsp & ~PAGE_MASK) + 0xFE0;
    if(pe_guest_rsp &&
        current->regs.vtlb->lookup(next_fault_addr, vtlb_hpa, vtlb_attr, guest_eip_tlb)) {
        mword* fault_addr_map = reinterpret_cast<mword*> 
                (Hpt::remap_cow(Pd::kern.quota, vtlb_hpa, 3, sizeof(mword)));
        String::print(next_fault, "next_fault %lx (%lx)", next_fault_addr, *fault_addr_map);
    } else {
        String::print(rip_instruction, "No next_fault");
    }
    char detail[STR_MIN_LENGTH];
    if(reason == Vmcs::VMX_EXTINT) {
        String::print(detail, "vec %lu", Vmcs::read(Vmcs::EXI_INTR_INFO) & 0xff);
    } else if(reason == Vmcs::VMX_EXC_NMI) {
        mword intr_info = Vmcs::read (Vmcs::EXI_INTR_INFO);
        switch(intr_info & 0x7ff) {
            case 0x202: // NMI
                String::print(detail, "NMI");
                break;
            case 0x307: // #NM
                String::print(detail, "NM");
                break;
            case 0x30e: // #PF
                String::print(detail, "PF %lx:%lx ", Vmcs::read(Vmcs::EXI_QUALIFICATION), 
                    Vmcs::read(Vmcs::EXI_INTR_ERROR));    
                break;
            default:
                String::print(detail, "Don't know this VMX_EXC %lx", intr_info & 0x7ff);
        } 
    } else if (reason == Vmcs::VMX_CR) {
        mword qual = Vmcs::read (Vmcs::EXI_QUALIFICATION);
        unsigned cr  = qual      & 0xf;        
        call_log_funct(Logstore::append_entry_in_buffer, 0, "VMX_CR %u", cr);
    } else if (reason == Vmcs::VMX_EPT_VIOLATION) {
        nst_error = Vmcs::read (Vmcs::EXI_QUALIFICATION); 
        nst_fault = Vmcs::read (Vmcs::INFO_PHYS_ADDR);
        call_log_funct(Logstore::append_entry_in_buffer, 1, "%lx:%lx ", nst_error, 
            nst_fault);
    } else if (reason == Vmcs::VMX_MTF) {
        call_log_funct(Logstore::append_entry_in_buffer, 0, "VMX_MTF");
    }
    call_log_funct(Logstore::add_entry_in_buffer, 1, "VMEXIT PE %llu rip %lx:%lx "
        "(%s) rsp %lx flags %lx CS %lx run %u counter %s reason %s %s %s, %s", Counter::nb_pe,
        guest_start_rip, guest_eip, rip_instruction, Vmcs::read(Vmcs::GUEST_RSP), 
        Vmcs::read(Vmcs::GUEST_RFLAGS), Vmcs::read(Vmcs::GUEST_SEL_CS), Pe::run_number, 
        counter_buff, Vmcs::reason[reason], detail, next_fault, vmlaunch ? "VMLAUNCH" :
        "VMRESUME");
}

void Ec::handle_vmx()
{
    Cpu::hazard = (Cpu::hazard | HZD_DS_ES | HZD_TR) & ~HZD_FPU;

    mword reason = Vmcs::read (Vmcs::EXI_REASON) & 0xff, nst_error = 0, nst_fault = 0;
    keep_cow = false;    
    Counter::vmi[reason][Pe::run_number]++;

    char counter_buff[STR_MIN_LENGTH];
    uint64 counter_value = Lapic::read_instCounter();
    if(counter_value >= Lapic::perf_max_count - MAX_INSTRUCTION)
        String::print(counter_buff, "%#llx", counter_value);
    else
        String::print(counter_buff, "%llu", counter_value);
    mword guest_eip = Vmcs::read(Vmcs::GUEST_RIP);
    Paddr hpa;
    mword attr;
    char rip_instruction[STR_MIN_LENGTH];
    if(guest_eip && current->lookup(guest_eip, hpa, attr)){
        uint8 *rip_map = reinterpret_cast<uint8*> 
            (Hpt::remap_cow(Pd::kern.quota, hpa, 3, sizeof(mword)));
        String::print(rip_instruction, "%x %x", *rip_map, *(rip_map+1));
    } else {
        String::print(rip_instruction, "No instruction");
    }
    char detail[STR_MIN_LENGTH];
    if(reason == Vmcs::VMX_EXTINT) {
        String::print(detail, "vec %lu", Vmcs::read(Vmcs::EXI_INTR_INFO) & 0xff);
    } else if(reason == Vmcs::VMX_EXC_NMI) {
        mword intr_info = Vmcs::read (Vmcs::EXI_INTR_INFO);
        switch(intr_info & 0x7ff) {
            case 0x202: // NMI
                String::print(detail, "NMI");
                break;
            case 0x307: // #NM
                String::print(detail, "NM");
                break;
            case 0x30e: // #PF
                String::print(detail, "PF %lx:%lx ", Vmcs::read(Vmcs::EXI_QUALIFICATION), 
                    Vmcs::read(Vmcs::EXI_INTR_ERROR));    
                break;
            default:
                String::print(detail, "Don't know this VMX_EXC %lx", intr_info & 0x7ff);
        } 
    } else if (reason == Vmcs::VMX_CR) {
        mword qual = Vmcs::read (Vmcs::EXI_QUALIFICATION);
        unsigned cr  = qual      & 0xf;        
        String::print(detail, "VMX_CR %u", cr);
    } else if (reason == Vmcs::VMX_INTR_WINDOW) {
        uint32 val = static_cast<uint32>(Vmcs::read (Vmcs::CPU_EXEC_CTRL0));
        String::print(detail, "val %x %s", val, val & Vmcs::CPU_INTR_WINDOW ? "YES " : "NO");
    } else if (reason == Vmcs::VMX_EPT_VIOLATION) {
        nst_error = Vmcs::read (Vmcs::EXI_QUALIFICATION); 
        nst_fault = Vmcs::read (Vmcs::INFO_PHYS_ADDR);
        String::print(detail, "%lx:%lx ", nst_error, nst_fault);
    } else if (reason == Vmcs::VMX_MTF) {
        String::print(detail, "VMX_MTF");
    } else {
        String::print(detail, " ");
    }
    call_log_funct(Logstore::add_entry_in_buffer, 0, "VMEXIT PE %llu rip %lx:%lx "
        "(%s) rsp %lx flags %lx CS %lx run %u counter %s reason %s %s %s", Counter::nb_pe,
        guest_start_rip, guest_eip, rip_instruction, Vmcs::read(Vmcs::GUEST_RSP), 
        Vmcs::read(Vmcs::GUEST_RFLAGS), Vmcs::read(Vmcs::GUEST_SEL_CS), Pe::run_number, 
        counter_buff, Vmcs::reason[reason], detail, vmlaunch ? "VMLAUNCH" :
        "VMRESUME");
   
    if(Pe::run_number == 1 && vmx_step_reason == SR_NIL && run1_reason == PES_PMI && 
        reason != Vmcs::VMX_EXTINT) {
// What are your doing here? Actually, it means 2nd run exceeds 1st run and trigger exception
// In this case, PMI must be pending and should be served just after IRET
//        if(reason == Vmcs::VMX_EPT_VIOLATION) {
//         Very bad second run, the 2nd run has surely exceeded the 1st
//            current->rollback();
//            launch_state = UNLAUNCHED;
//            reset_all();
//            ret_user_vmresume();
//        But if the first run was stopped by PMI, it may be better to stop the 
//        2nd run here and single stepp the 1st run to catch up with the 2nd
//        }
        call_log_funct(Logstore::add_entry_in_buffer, 1, "Warning : An interrupt "
                "other VMX_EXTINT (PMI and Timer) happens in 2nd run when 1st run "
                "was stopped by PMI. Reason %s %s", Vmcs::reason[reason], detail);
        ret_user_vmresume();
    }

    switch (reason) {
        case Vmcs::VMX_EXC_NMI:     vmx_exception();
        case Vmcs::VMX_EXTINT:      vmx_extint();
//        case Vmcs::VMX_INTR_WINDOW: 
//            if(Ec::is_idle()){
//                break;
//            } else {
//                Pending_int::add_pending_interrupt(Vmcs::VMX_INTR_WINDOW + VEC_VMX);
//                uint32 val = static_cast<uint32>(Vmcs::read (Vmcs::CPU_EXEC_CTRL0));
//                trace(0, "val %x Interrupt Window %s", val, val & Vmcs::CPU_INTR_WINDOW ? "YES " : "NO");
//                current->regs.vmx_set_cpu_ctrl0 (val & ~Vmcs::CPU_INTR_WINDOW);
//                ret_user_vmresume();
//            }
        case Vmcs::VMX_INVLPG:
            if (!current->regs.nst_on) vmx_invlpg();
            else break;
//        case Vmcs::VMX_RDTSC:       
//            if(Pe::run_number == 0)
//                tsc1 = rdtsc();
//            keep_cow = true;
//            check_memory(PES_VMX_RDTSC); 
//            vmx_resolve_rdtsc();
        case Vmcs::VMX_CR:          check_memory(PES_VMX_CR); vmx_cr();
        case Vmcs::VMX_MTF:         
            if(vmx_step_reason == SR_VMIW) 
                check_memory(PES_VMX_MTF); 
            vmx_disable_single_step();
        case Vmcs::VMX_EPT_VIOLATION:
            if(Pd::current->ept.is_cow_fault(nst_fault)) {
                ret_user_vmresume();
            }
            current->regs.nst_error = nst_error;
            current->regs.nst_fault = nst_fault;
            break;
//        case Vmcs::VMX_RDTSCP:      
//            if(Pe::run_number == 0)
//                tsc1 = rdtscp(tscp_rcx1);
//            keep_cow = true;
//            check_memory(PES_VMX_RDTSCP); 
//            vmx_resolve_rdtsc(true);
//            break;
    }
    if(reason == Vmcs::VMX_IO)
        keep_cow = true;    
    if(reason == Vmcs::VMX_INTR_WINDOW && (
            (counter_value == (Lapic::perf_max_count - MAX_INSTRUCTION)) ||
            (guest_eip == pe_start_rip))) {
        if(counter_value != (Lapic::perf_max_count - MAX_INSTRUCTION))
            call_log_funct(Logstore::add_entry_in_buffer, 1, "Warning : Interrupt "
            "Window on 1st PE instruction but counter is not 0. EIP Start %lx "
            "Current %lx counter %s", guest_start_rip, guest_eip, counter_buff);
        assert(Pe::run_number == 0);
        abort_pe(PES_VMX_EXIT);
        ept_backup = true;
        current->regs.vmcs->write_eptp(Pd::current->ept_backup.root(Pd::current->quota));
        resolve_intr_window();
        ret_user_vmresume();
//        current->regs.dst_portal = reason;
//        send_msg<ret_user_vmresume>();
    } else {
        check_memory(PES_VMX_EXIT);     
    
        current->regs.dst_portal = reason;
        if (reason == Vmcs::VMX_INTR_WINDOW) { 
            // Guest OS first instruction after INTR_WINDOW must never page fault
            ept_backup = true;
            current->regs.vmcs->write_eptp(Pd::current->ept_backup.root(Pd::current->quota));
            resolve_intr_window();
        }
        send_msg<ret_user_vmresume>();
    }
}

void Ec::exec_pending(unsigned reason) {
    trace(0, "Exec %s", Vmcs::reason[reason]);
    current->regs.dst_portal = reason;
    uint32 val = static_cast<uint32>(Vmcs::read (Vmcs::CPU_EXEC_CTRL0));
    current->regs.vmx_set_cpu_ctrl0 (val | Vmcs::CPU_INTR_WINDOW);
    send_msg<ret_user_vmresume>();
}

void Ec::vmx_disable_single_step() {
    switch(vmx_step_reason){
        case SR_RDTSC:
            disable_mtf();
            disable_rdtsc();
            vmx_step_reason = SR_NIL;
            break;
        case SR_PMI: {
            ++Counter::pmi_ss;
            nb_inst_single_step++;
            mword current_rip = Vmcs::read(Vmcs::GUEST_RIP);
            if(nb_inst_single_step > nbInstr_to_execute + 5) {
                call_log_funct_with_buffer(Logstore::add_entry_in_buffer, 2, 
                    "SR_PMI Run %d Lost in Single stepping nb_inst_single_step %llu "
                    "nbInstr_to_execute %llu first_run_instr_number %llu "
                    "second_run_instr_number %llu Pd %s Ec %s", Pe::run_number, 
                    nb_inst_single_step, nbInstr_to_execute, first_run_instr_number, 
                    second_run_instr_number, Pd::current->get_name(), Ec::current->get_name());
            }
//            if (nbInstr_to_execute > 0)
//                nbInstr_to_execute--;
            if (prev_rip == current_rip) { // Rep Prefix
                nb_inst_single_step--;
//                nbInstr_to_execute++; // Re-adjust the number of instruction                  
                
                Register cmp = current->compare_regs();
                // It may happen that this is the final instruction
                if (cmp) {
                    call_log_funct_with_buffer(Logstore::add_entry_in_buffer, 0, 
                    "SR_PMI Run %d REP_PREF %s is different %lx:%lx:%lx:%lx nbSS "
                    "%llu nbInstToExec %llu Pd %s Ec %s", Pe::run_number, 
                    reg_names[cmp], current->get_reg(cmp, 0), current->get_reg(cmp, 1), 
                    current->get_reg(cmp, 2), current->get_reg(cmp), 
                    nb_inst_single_step, nbInstr_to_execute, Pd::current->get_name(), 
                    Ec::current->get_name());
                } else {
                    disable_mtf();
                    if(Pe::inState1) {
                        current->restore_state2();
                    }
                    check_memory(PES_SINGLE_STEP);
                    ret_user_vmresume();
                }
            }
            prev_rip = current_rip;
            // No need to compare if nbInstr_to_execute > 3 
            if (nb_inst_single_step < nbInstr_to_execute - 2) {
                vmx_enable_single_step(SR_PMI);
                ret_user_vmresume();
            } else {
                Register cmp = current->compare_regs();
                if (cmp) {
                    call_log_funct_with_buffer(Logstore::add_entry_in_buffer, 0, 
                    "SR_PMI Run %d : %s is different %lx:%lx:%lx:%lx nbSS %llu "
                    "nbInstToExec %llu Pd %s Ec %s", Pe::run_number, 
                    reg_names[cmp], current->get_reg(cmp, 0), current->get_reg(cmp, 1), 
                    current->get_reg(cmp, 2), current->get_reg(cmp), 
                    nb_inst_single_step, nbInstr_to_execute, Pd::current->get_name(), 
                    Ec::current->get_name());
                    vmx_enable_single_step(SR_PMI);
//                    nbInstr_to_execute = 1;
                    ret_user_vmresume();
                } else {
                    disable_mtf();
                    if(Pe::inState1) {
                        current->restore_state2();
                    }
                    check_memory(PES_SINGLE_STEP);
                }
            }
            break;
        }
        case SR_DBG:
            if (Pe::run_number == 0) {
                if (nb_inst_single_step < nbInstr_to_execute) {
                    nb_inst_single_step++;
                } else {
                    Console::print("Relaunching for the second run");
                    current->restore_state0();
                    nb_inst_single_step = 0;
                    Pe::run_number++;
                }
            } else {
                if (nb_inst_single_step < nbInstr_to_execute) {
                    nb_inst_single_step++;
                } else {
                    Console::panic("SR_DBG Finish");
                }
            }
            vmx_enable_single_step(SR_DBG);
        break;
        case SR_EQU: {
            ++Counter::pmi_ss;
            nb_inst_single_step++;
            mword current_rip = Vmcs::read(Vmcs::GUEST_RIP);
            if(nb_inst_single_step > nbInstr_to_execute) {
                call_log_funct_with_buffer(Logstore::add_entry_in_buffer, 2, 
                "SR_EQU Run %d Lost in Single stepping nb_inst_single_step %llu "
                "nbInstr_to_execute %llu first_run_instr_number %llu "
                "second_run_instr_number %llu Pd %s Ec %s", Pe::run_number, 
                nb_inst_single_step, nbInstr_to_execute, first_run_instr_number, 
                second_run_instr_number, Pd::current->get_name(), 
                Ec::current->get_name());
            }
//            if (nbInstr_to_execute > 0)
//                nbInstr_to_execute--;
            if (prev_rip == current_rip) { // Rep Prefix
                nb_inst_single_step--;
//                nbInstr_to_execute++; // Re-adjust the number of instruction                  
                
                // It may happen that this is the final instruction
                Register cmp = current->compare_regs();
                if (cmp) {
                    call_log_funct_with_buffer(Logstore::add_entry_in_buffer, 0, 
                    "SR_EQU && REP_PREF Run %d %s is different %lx:%lx:%lx:%lx "
                    "nbSS %llu nbInstToExec %llu Pd %s Ec %s", Pe::run_number, 
                    reg_names[cmp], current->get_reg(cmp, 0), current->get_reg(cmp, 1), 
                    current->get_reg(cmp, 2), current->get_reg(cmp), 
                    nb_inst_single_step, nbInstr_to_execute, Pd::current->get_name(), 
                    Ec::current->get_name());
                 } else {
                    disable_mtf();
                    if(Pe::inState1) {
                        current->restore_state2();
                    }
                    check_memory(PES_SINGLE_STEP);                    
                    ret_user_vmresume();
                }
            }
            //here, single stepping 2nd run should be ok
            Register cmp = current->compare_regs();
            if (cmp) {
                call_log_funct_with_buffer(Logstore::add_entry_in_buffer, 0, 
                "SR_EQU Run %d %s is different %lx:%lx:%lx:%lx nbSS %llu "
                "nbInstToExec %llu Pd %s Ec %s", Pe::run_number, reg_names[cmp], 
                current->get_reg(cmp, 0), current->get_reg(cmp, 1), current->get_reg(cmp, 2), 
                current->get_reg(cmp), nb_inst_single_step, nbInstr_to_execute, 
                Pd::current->get_name(), Ec::current->get_name());
                // single stepping the first run with 2 credits instructions
                if (nb_inst_single_step == nbInstr_to_execute) { 
                    if(!run_switched) {
                        if(Pe::inState1)
                            current->restore_state2();
                        else 
                            current->restore_state1();   
                        nbInstr_to_execute *= 2;
                        nb_inst_single_step = 0;
//                        nbInstr_to_execute = distance_instruction + nb_inst_single_step + 1;
//                        nb_inst_single_step = 0;
                        run_switched = true;
                        enable_mtf();
                    } else {
                        call_log_funct_with_buffer(Logstore::add_entry_in_buffer, 2, 
                        "SR_EQU Run %d run_switched but %s is different %lx:%lx:%lx:%lx "
                        "nb_inst_single_step %llu nbInstr_to_execute %llu "
                        "first_run_instr_number %llu second_run_instr_number %llu "
                        "Pd %s Ec %s", Pe::run_number, reg_names[cmp], 
                        current->get_reg(cmp, 0), current->get_reg(cmp, 1), 
                        current->get_reg(cmp, 1), current->get_reg(cmp), 
                        nb_inst_single_step, nbInstr_to_execute, first_run_instr_number, 
                        second_run_instr_number, Pd::current->get_name(),
                        Ec::current->get_name());                      
                    }
                    ret_user_vmresume();
                } else { // relaunch the first run without restoring the second execution state
                    enable_mtf();
                    ret_user_vmresume();
                }
            } else {
                disable_mtf();
                if(Pe::inState1) {
                    current->restore_state2();
                }
                check_memory(PES_SINGLE_STEP);     
                ret_user_vmresume();                
            }
            break;
        }
        case SR_RFLAG: {
            mword guest_rsp = Vmcs::read(Vmcs::GUEST_RSP);
            char inst_type[STR_MIN_LENGTH];
            if(guest_rsp < guest_single_step_rsp) {
                String::print(inst_type, "PUSH");
            } else {
                String::print(inst_type, "POP");
            }
            mword rsp_top = (guest_rsp & ~PAGE_MASK) + PAGE_SIZE - 4;
            Paddr rsp_phys = (guest_rsp_phys & ~PAGE_MASK) + (guest_rsp & PAGE_MASK);
            call_log_funct(Logstore::add_entry_in_buffer, 0, "%s: PE %llu "
                "rsp %lx phys %lx", inst_type, Counter::nb_pe, guest_rsp, rsp_phys);            
            mword* rsp_map = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, 
                    rsp_phys, 3, sizeof(mword)));
            int i = 3;
            while (i && (guest_rsp <= rsp_top)) {
                call_log_funct(Logstore::append_entry_in_buffer, 0, "%p: %lx ", 
                    rsp_map, *rsp_map);
                rsp_map++; i--;
                guest_rsp += sizeof(mword);
            } 
            
            mword guest_sysenter_esp = Vmcs::read(Vmcs::GUEST_SYSENTER_ESP);
            Paddr vtlb_hpa;
            mword vtlb_attr;
            mword* sys_enter_rsp_map; 
            Vtlb *tlb = nullptr;
            if(guest_sysenter_esp &&  
                current->regs.vtlb->lookup(guest_sysenter_esp, vtlb_hpa, vtlb_attr, tlb)){
                mword rsp_bottom = (guest_sysenter_esp & ~PAGE_MASK) - PAGE_SIZE + 4;
                sys_enter_rsp_map = reinterpret_cast<mword*> 
                    (Hpt::remap_cow(Pd::kern.quota, vtlb_hpa, 3, sizeof(mword)));
                call_log_funct(Logstore::add_entry_in_buffer, 0, "guest_sysenter_esp");
                i = 3;
                while (i && (guest_sysenter_esp >= rsp_bottom)) {
                    call_log_funct(Logstore::append_entry_in_buffer, 0, "%p: %lx ", 
                        sys_enter_rsp_map, *sys_enter_rsp_map);
                    sys_enter_rsp_map--; i--;
                    guest_sysenter_esp -= sizeof(mword);
                } 
            }
    
            if(guest_single_step_rsp == guest_rsp + 0xc){
                rsp_map = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, 
                    guest_rsp_phys - 0x4, 3, sizeof(mword)));
                *rsp_map = (*rsp_map) & ~Cpu::EFL_RF;
                call_log_funct(Logstore::add_entry_in_buffer, 0, 
                    "Resume flag removed after one instruction PUSH : PE %llu "
                    "rsp %lx", Counter::nb_pe, guest_single_step_rsp - 0xc);
            } else if (guest_single_step_rsp == guest_rsp - 0xc) { // this should not happen, but ...
                rsp_map = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, 
                    guest_rsp_phys + 0x8, 3, sizeof(mword)));
                *rsp_map = (*rsp_map) & ~Cpu::EFL_RF;
                call_log_funct(Logstore::add_entry_in_buffer, 0, 
                    "Resume flag removed after one instruction POP : PE %llu "
                    "rsp %lx", Counter::nb_pe, guest_single_step_rsp + 0xc);
            }
            disable_mtf();
            break;
        }
        case SR_VMIW:
            ept_backup = false;
            current->regs.vmcs->write_eptp(Pd::current->ept.root(Pd::current->quota));            
            vmx_step_reason = SR_NIL;
            disable_mtf();
            break;
        default:
            Console::panic("No step Reason");
    }
    ret_user_vmresume();
}

void Ec::vmx_resolve_io(){
    if (Vmcs::has_mtf()) {// if the CPU honors the monitor trap flag
        enable_mtf();
        vmx_step_reason = SR_VMIO;
        current->regs.vmcs->make_current();
    } else
        vmx_emulate_io();
    ret_user_vmresume();
}
void Ec::resolve_intr_window(){
    enable_mtf();
    vmx_step_reason = SR_VMIW;
}

void Ec::vmx_emulate_io(){
    Console::panic("VMX_IO and monitor trap not supported : IO Emulation required");
}

void Ec::vmx_resolve_rdtsc(bool is_rdtscp) {
    if (Vmcs::has_mtf()) {// if the CPU honors the monitor trap flag
        enable_mtf();
        enable_rdtsc();
        vmx_step_reason = SR_RDTSC;
        current->regs.vmcs->make_current();
    } else
        vmx_emulate_rdtsc(is_rdtscp);
    ret_user_vmresume();
}

void Ec::vmx_enable_single_step(Step_reason reason) {
    if (Vmcs::has_mtf()) {// if the CPU honors the monitor trap flag
        enable_mtf();
        vmx_step_reason = reason;
        current->regs.vmcs->make_current();
    } else {
        Console::panic("VM Single step required and monitor trap not supported : IO Emulation required");        
    }
    if(reason == SR_DBG){
        Paddr hpa_guest_rip;
        mword guest_rip = Vmcs::read(Vmcs::GUEST_RIP), attr;
        current->lookup(guest_rip, hpa_guest_rip, attr);
        void *rip_ptr = reinterpret_cast<char*>(Hpt::remap_cow(Pd::kern.quota, hpa_guest_rip, 3)) + 
            (hpa_guest_rip & PAGE_MASK);
        char instr_buff[STR_MIN_LENGTH];
        instruction_in_hex(*reinterpret_cast<mword*>(rip_ptr), instr_buff);
        
        Paddr hpa_miss_match_addr;
        current->lookup(Pe::missmatch_addr, hpa_miss_match_addr, attr);
        mword offset = hpa_miss_match_addr & PAGE_MASK, mod = offset % sizeof(mword);
        offset = (mod == 0) ? offset : offset - mod;
        void *mm_ptr = reinterpret_cast<char*>(Hpt::remap_cow(Pd::kern.quota, hpa_miss_match_addr, 
                4)) + offset;
        Console::print("nb_inst_single_step %llu rip %lx hpa_guest_rip %lx %s hpa_miss %lx:%lx:%lx", 
                nb_inst_single_step, guest_rip, hpa_guest_rip, instr_buff, 
                Pe::missmatch_addr, hpa_miss_match_addr, *reinterpret_cast<mword*>(mm_ptr));
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
        if (!current->lookup(inst_addr, physic, attrib)) {
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
//    assert(Vmcs::has_mtf());
    mword val = Vmcs::read(Vmcs::CPU_EXEC_CTRL0);
    val |= Vmcs::CPU_MONITOR_TRAP_FLAG;
    Vmcs::write(Vmcs::CPU_EXEC_CTRL0, val);
}

void Ec::disable_mtf() {
    mword val = Vmcs::read(Vmcs::CPU_EXEC_CTRL0);
    val &= ~Vmcs::CPU_MONITOR_TRAP_FLAG;
    Vmcs::write(Vmcs::CPU_EXEC_CTRL0, val);
    vmx_step_reason = SR_NIL;
}

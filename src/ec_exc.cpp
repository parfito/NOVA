/*
 * Execution Context
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012 Udo Steinberg, Intel Corporation.
 * Copyright (C) 2013-2018 Alexander Boettcher, Genode Labs GmbH.
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

#include "ec.hpp"
#include "gdt.hpp"
#include "mca.hpp"
#include "stdio.hpp"
#include "msr.hpp"
#include "utcb.hpp"
#include "lapic.hpp"
#include "vmx.hpp"
#include "gsi.hpp"
#include "pending_int.hpp"
#include "cow_elt.hpp"

void Ec::load_fpu() {
    if (!Cmdline::fpu_eager && !utcb)
        regs.fpu_ctrl(true);

    if (EXPECT_FALSE(!fpu)) {
        if (Cmdline::fpu_eager && !utcb)
            regs.fpu_ctrl(true);

        Fpu::init();
    } else
        fpu->load();
}

void Ec::save_fpu() {
    if (!Cmdline::fpu_eager && !utcb)
        regs.fpu_ctrl(false);

    if (EXPECT_FALSE(!fpu))
        fpu = new (*pd) Fpu;

    fpu->save();
}

void Ec::transfer_fpu(Ec *ec) {
    assert(!idle_ec());

    if (!(Cpu::hazard & HZD_FPU)) {

        Fpu::enable();

        if (fpowner != this) {
            if (fpowner)
                fpowner->save_fpu();
            load_fpu();
        }
    }

    if (fpowner && fpowner->del_rcu()) {
        Ec * last = fpowner;
        fpowner = nullptr;
        Rcu::call(last);
    }

    fpowner = ec;
    bool ok = fpowner->add_ref();
    assert(ok);
}

void Ec::handle_exc_nm() {
    if (Cmdline::fpu_eager)
        die("FPU fault");

    Fpu::enable();

    if (current == fpowner) {
        if (!current->utcb && !current->regs.fpu_on)
            current->regs.fpu_ctrl(true);
        return;
    }

    if (fpowner)
        fpowner->save_fpu();

    current->load_fpu();

    if (fpowner && fpowner->del_rcu()) {
        Ec * last = fpowner;
        fpowner = nullptr;
        Rcu::call(last);
    }

    fpowner = current;
    bool ok = fpowner->add_ref();
    assert(ok);
}

bool Ec::handle_exc_ts(Exc_regs *r) {
    if (r->user()) {
        return false;
    }
    // SYSENTER with EFLAGS.NT=1 and IRET faulted
    r->REG(fl) &= ~Cpu::EFL_NT;

    return true;
}

bool Ec::handle_exc_gp(Exc_regs *r) {
    mword eip = r->REG(ip);
    //    if(r->user() && !fixup (r->REG(ip)) && !current->is_temporal_exc() && !current->is_io_exc()){
    //        if(step_reason == SR_NIL){
    //            Console::print("GP_DB End %lx %lx", eip, r->REG(ax));
    //            step_reason = SR_GP;
    //            current->regs.REG(fl) |= Cpu::EFL_TF;
    //        }else{
    //            step_reason = SR_NIL;
    //            current->regs.REG(fl) &= ~Cpu::EFL_TF;            
    //        }
    //    }
    if (Cpu::hazard & HZD_TR) {
        Cpu::hazard &= ~HZD_TR;
        Gdt::unbusy_tss();
        asm volatile ("ltr %w0" : : "r" (SEL_TSS_RUN));
        return true;
    }

    if (fixup(r->REG(ip))) {
        r->REG(ax) = r->cr2;
        return true;
    }
    Ec* ec = current;
    if (r->user()) {
        if (ec->is_temporal_exc()) {
            ec->enable_step_debug(SR_RDTSC);
            return true;
        } else if (ec->is_io_exc()) {
            ++Counter::pio;
            ++Counter::io;
            ec->resolve_PIO_execption();
            return true;
        }
    }

    Console::print("eip0: %lx(%#lx)  rax_0: %lx", regs_0.REG(ip), regs_0.REG(cx), regs_0.REG(ax));
    Console::print("eip1: %lx(%#lx)  rax_1: %lx", regs_1.REG(ip), regs_1.REG(cx), regs_1.REG(ax));
    Console::print("eip2: %lx(%#lx)  rax_2: %lx", regs_2.REG(ip), regs_2.REG(cx), regs_2.REG(ax));
    char buff[MAX_STR_LENGTH];
    instruction_in_hex(*(reinterpret_cast<mword *> (eip)), buff);
    Console::print("GP Here: Ec: %s  Pd: %s ip %lx(%#lx) val: %s Lapic::counter %llx user %s",
            ec->get_name(), ec->getPd()->get_name(), eip, r->ARG_IP, buff, Lapic::read_instCounter(), r->user() ? "true" : "false");
    Counter::dump();
    Pe::dump(true);
    ec->start_debugging(Debug_type::STORE_RUN_STATE);
    if (!ec->utcb) {
        mword inst_addr = Vmcs::read(Vmcs::GUEST_RIP);
        mword inst_off = inst_addr & PAGE_MASK;
        uint64 entry = 0;
        if (!current->regs.vtlb_lookup(inst_addr, entry)) {
            Console::print("Instr_addr not found %lx", inst_addr);
        }
        uint8 *ptr = reinterpret_cast<uint8 *> (Hpt::remap_cow(Pd::kern.quota, entry & ~PAGE_MASK));
        uint64 *inst_val = reinterpret_cast<uint64 *> (ptr + inst_off);
        Console::print("VMip: %lx VMcx %lx val %llx", inst_addr, ec->regs.REG(cx), *inst_val);
    }
    return false;
}

void Ec::handle_exc_db(Exc_regs *r) {
    if (get_dr6() & 0x1) { // debug register 0
        Console::print("Debug register 0 Ec %s Pd %s eip %lx", current->get_name(), current->getPd()->get_name(), current->regs.REG(ip));
        mword *p = reinterpret_cast<mword*> (0x18028);
        Paddr physical_addr;
        mword attribut;
        size_t is_mapped = current->getPd()->loc[Cpu::id].lookup(0x18028, physical_addr, attribut);
        if (is_mapped)
            Console::print("Debug breakpoint at value phys %lx 18028:%lx", physical_addr, *p);
        return;
    }
    if (r->user()) {
        switch (step_reason) {
            case SR_MMIO:
            case SR_PIO:
            case SR_RDTSC:
                //                        Console::print("EXC_DB step_reason: %d", step_reason);
                if (not_nul_cowlist && step_reason != SR_PIO) {
                    Console::print("cow_list not null was noticed Pd: %s", current->getPd()->get_name());
                    not_nul_cowlist = false;
                }
                if (!Cow_elt::is_empty()) {
                    if (step_reason != SR_PIO)
                        Console::print("cow_list not null, noticed! Pd: %s", current->getPd()->get_name());
                    else {
                        not_nul_cowlist = true;
                    }
                }
                current->disable_step_debug();
                launch_state = UNLAUNCHED;
                reset_all();
                return;
            case SR_PMI:
            {
                ++Counter::pmi_ss;
                nb_inst_single_step++;
                if (nbInstr_to_execute > 0)
                    nbInstr_to_execute--;
                if (prev_rip == current->regs.REG(ip)) { // Rep Prefix
                    nb_inst_single_step--;
                    nbInstr_to_execute++; // Re-adjust the number of instruction                  
                    // Console::print("EIP: %lx  prev_rip: %lx MSR_PERF_FIXED_CTR0: %lld instr: %lx", 
                    // current->regs.REG(ip), prev_rip, Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), *reinterpret_cast<mword *>(current->regs.REG(ip)));
                    // It may happen that this is the final instruction
                    if (!current->compare_regs_mute()) {
                        //                                check_instr_number_equals(1);
                        current->disable_step_debug();
                        check_memory(PES_SINGLE_STEP);
                        return;
                    }
                }
                prev_rip = current->regs.REG(ip);
                // No need to compare if nbInstr_to_execute > 3 
                if (nbInstr_to_execute > 3) {
                    current->regs.REG(fl) |= Cpu::EFL_TF;
                    return;
                }
                if (!current->compare_regs_mute()) {
                    //                            check_instr_number_equals(2);
                    current->disable_step_debug();
                    check_memory(PES_SINGLE_STEP);
                    return;
                } else {
                    current->regs.REG(fl) |= Cpu::EFL_TF;
                    nbInstr_to_execute = 1;
                    return;
                }
                break;
            }
            case SR_GP:
                return;
                break;
            case SR_DBG:
                if (nbInstr_to_execute > 0) {
                    current->regs.REG(fl) |= Cpu::EFL_TF;
                    debug_record_info();
                    nbInstr_to_execute--;
                    single_step_number++;
                    return;
                } else {
                    if (run_number == 0) {
                        Console::print("Relaunching for the second run");
                        current->restore_state();
                        nbInstr_to_execute = MAX_INSTRUCTION + counter2 - exc_counter2;
                        run_number++;
                        check_exit();
                    } else {
                        Console::panic("Finish");
                    }
                }
                break;
            case SR_EQU:
                ++Counter::pmi_ss;
                nb_inst_single_step++;
                if (nbInstr_to_execute > 0)
                    nbInstr_to_execute--;
                if (prev_rip == current->regs.REG(ip)) { // Rep Prefix
                    nb_inst_single_step--;
                    nbInstr_to_execute++; // Re-adjust the number of instruction                  
                    // Console::print("EIP: %lx  prev_rip: %lx MSR_PERF_FIXED_CTR0: %lld instr: %lx", 
                    // current->regs.REG(ip), prev_rip, Msr::read<uint64>(Msr::MSR_PERF_FIXED_CTR0), *reinterpret_cast<mword *>(current->regs.REG(ip)));
                    // It may happen that this is the final instruction
                    if (!current->compare_regs_mute()) {
                        //                                check_instr_number_equals(3);
                        current->disable_step_debug();
                        check_memory(PES_SINGLE_STEP);
                        return;
                    }
                }
                //here, single stepping 2nd run should be ok
                if (!current->compare_regs_mute()) {// if ok?
                    //                            check_instr_number_equals(4);
                    current->disable_step_debug();
                    check_memory(PES_SINGLE_STEP);
                    return;
                } else {
                    if (nbInstr_to_execute == 0) { // single stepping the first run with 2 credits instructions
                        current->restore_state1();
                        nbInstr_to_execute = distance_instruction + nb_inst_single_step + 1;
                        nb_inst_single_step = 0;
                        first_run_advanced = true;
                        current->regs.REG(fl) |= Cpu::EFL_TF;
                        return;
                    } else { // relaunch the first run without restoring the second execution state
                        current->regs.REG(fl) |= Cpu::EFL_TF;
                        return;
                    }
                }
                break;
            default:
                Console::panic("No step Reason");
        }
    } else {
        die("Debug in kernel");
    }
}

void Ec::handle_deterministic_exception(Exc_regs *r) {
    if (r->user() && ((r->vec == Cpu::EXC_NM) || (r->vec == Cpu::EXC_TS) ||
            (r->vec == Cpu::EXC_GP) || (r->vec == Cpu::EXC_AC) || (r->vec == Cpu::EXC_MC))) {
        PE_stopby check_reason = PES_DEFAULT;
        switch (r->vec) {
            case Cpu::EXC_NM:
                check_reason = PES_DEV_NOT_AVAIL;
                break;
            case Cpu::EXC_TS:
                check_reason = PES_INVALID_TSS;
                break;
            case Cpu::EXC_GP:
                check_reason = PES_GP_FAULT;
                break;
            case Cpu::EXC_AC:
                check_reason = PES_ALIGNEMENT_CHECK;
                break;
            case Cpu::EXC_MC:
                check_reason = PES_MACHINE_CHECK;
                break;
            default :
                Console::panic("Check reason not handled");
        }
        check_memory(check_reason);
    }

}

bool Ec::handle_exc_pf(Exc_regs *r) {
    mword addr = r->cr2;

    //    if(((addr & ~PAGE_MASK) >= 0x9800000) && ((addr & ~PAGE_MASK) <= 0x9a00000))
    //        Console::print("addr 0x9800000");
    if ((r->err & Hpt::ERR_U) && Pd::current->Space_mem::loc[Cpu::id].is_cow_fault(Pd::current->quota, addr, r->err))
        return true;
    if (r->cs & 3)
        check_memory(PES_PAGE_FAULT);

    if (r->err & Hpt::ERR_U)
        return addr < USER_ADDR && Pd::current->Space_mem::loc[Cpu::id].sync_from(Pd::current->quota, Pd::current->Space_mem::hpt, addr, USER_ADDR, r->err);

    if (addr < USER_ADDR) {

        if (Pd::current->Space_mem::loc[Cpu::id].sync_from(Pd::current->quota, Pd::current->Space_mem::hpt, addr, USER_ADDR, r->err))
            return true;

        if (fixup(r->REG(ip))) {
            r->REG(ax) = addr;
            return true;
        }
    }

    if (addr >= LINK_ADDR && addr < CPU_LOCAL && Pd::current->Space_mem::loc[Cpu::id].sync_from(Pd::current->quota, Hptp(reinterpret_cast<mword> (&PDBR)), addr, CPU_LOCAL, r->err))
        return true;

    // Kernel fault in I/O space
    if (addr >= SPC_LOCAL_IOP && addr <= SPC_LOCAL_IOP_E) {
        Space_pio::page_fault(addr, r->err);
        return true;
    }

    // Kernel fault in OBJ space
    if (addr >= SPC_LOCAL_OBJ) {
        Space_obj::page_fault(addr, r->err);
        return true;
    }
    die("#PF (kernel)", r);
}

void Ec::handle_exc(Exc_regs *r) {
    Counter::exc[r->vec]++;

    handle_deterministic_exception(r);
    switch (r->vec) {
        case Cpu::EXC_DB:
            handle_exc_db(r);
            return;
        case Cpu::EXC_NMI:
            Console::panic("NMI not handled yet");
            return;

        case Cpu::EXC_NM:
            handle_exc_nm();
            return;

        case Cpu::EXC_TS:
            if (handle_exc_ts(r))
                return;
            break;

        case Cpu::EXC_GP:
            if (handle_exc_gp(r))
                return;
            break;

        case Cpu::EXC_PF:
            if (handle_exc_pf(r))
                return;
            break;

        case Cpu::EXC_AC:
            Console::print("Alignement check exception");

        case Cpu::EXC_MC:
            Mca::vector();
            break;
    }

    if (r->user()) {
        if (!is_idle() || !Cow_elt::is_empty())
            check_memory(PES_SEND_MSG);
        send_msg<ret_user_iret>();
    }

    if (Ec::current->idle_ec())
        return;

    die("EXC", r);
}
/**
 * This function is called at the end of every processing element
 * @param from : where it is called from
 */
void Ec::check_memory(PE_stopby from) {
   //    if (is_idle())
    //        Console::print("TCHA HOHO Must not be idle here, sth wrong. pmi: %d cowlist: %p Pd: %s", pmi, current->getPd()->cow_list, current->getPd()->get_name());
    if (Cow_elt::is_empty()) {
        launch_state = UNLAUNCHED;
        reset_all();
        return;
    }
    
    Ec *ec = current;
    Pd *pd = ec->getPd();
    //  Console::print("EIP = check_memory utcb %p run %d pmi %d counter %llx exc %lld rcx %lx eip %lx", ec->utcb, run_number, pmi, Lapic::read_instCounter(), exc_counter, current->regs.REG(cx), current->regs.REG(ip));
    switch (run_number) {
        case 0:
            prev_reason = from;
            ec->restore_state();
            counter1 = Lapic::read_instCounter(); // to be removed after we found the cause of "Attention : reason >< prevreason 1:22 counter1 160e7b counter2 ffffffffffbd "
            if (from == PES_PMI) {
                end_rip = last_rip;
                end_rcx = last_rcx;
                exc_counter1 = exc_counter;
                counter1 = Lapic::read_instCounter();
                /*
                 * Here we assume that Lapic::start_counter = (Lapic::perf_max_count - MAX_INSTRUCTION) ie 0xFFFFFFF00000
                 * So when counter overflows, counter1 will NEVER be > Lapic::start_counter.
                 */
                first_run_instr_number = counter1 < Lapic::start_counter ? 
                    MAX_INSTRUCTION + counter1 - exc_counter1 : counter1 - (Lapic::perf_max_count - MAX_INSTRUCTION);
                assert(first_run_instr_number < Lapic::perf_max_count);
                if (current->utcb) {
                    uint8 *ptr = reinterpret_cast<uint8 *> (end_rip);
                    if (*ptr == 0xf3 || *ptr == 0xf2) {
                        char buff[MAX_STR_LENGTH];
                        instruction_in_hex(*(reinterpret_cast<mword *> (end_rip)), buff);
                        Console::print("Rep prefix in Run1 %lx: %s rcx %lx", end_rip, buff, end_rcx);
                        in_rep_instruction = true;
                        Cpu::disable_fast_string();
                    }
                }/*else{
                    Paddr inst_phys;
                    mword inst_attr;
                    if (!current->regs.vtlb->vtlb_lookup(end_rip, inst_phys, inst_attr)) {
                        Console::print("Instr_addr not found %lx", end_rip);
                    }
                    mword inst_off = end_rip & PAGE_MASK;
                    uint8 *ptr = reinterpret_cast<uint8 *> (Hpt::remap_cow(Pd::kern.quota, inst_phys & ~PAGE_MASK));  
                    uint16 *inst_val = reinterpret_cast<uint16 *>(ptr + inst_off);
                    if (*inst_val == 0xf3 || *inst_val == 0xf2) {
                        char buff[MAX_STR_LENGTH];
                        instruction_in_hex(*(reinterpret_cast<mword *> (end_rip)), buff);
                        Console::print("VMX Rep prefix in Run1 %lx: %s rcx %lx", end_rip, buff, end_rcx);
                        in_rep_instruction = true;
                        Cpu::disable_fast_string();
                    }
                }*/
                
                /* Currently, this only happens on vmx execution on qemu.
                 * must be dug deeper
                 */
                if(first_run_instr_number > (MAX_INSTRUCTION + 300)){
                    Console::panic("PMI not served early counter1 %llx \nMust be dug deeper", counter1);
                    Lapic::program_pmi2(first_run_instr_number);
                } 
                Lapic::program_pmi();
            } else {
                Lapic::cancel_pmi();
            }
            run_number++;
            exc_counter = 0;
            check_exit();
            break;
        case 1:
            /* If from is not PES_PMI nor PES_SINGLE_STEP and prev_reason == PES_PMI, 
             * surely the second run exceeds the first in a way the second run 
             * encounter an exception not found during the first run. So we have to 
             * single step the first run to catch up the second.
             * 
             */
            if (from == PES_PMI || (prev_reason == PES_PMI && from != PES_SINGLE_STEP)) {
                if (prev_reason != PES_PMI) {
                    /* This means that the second run lasts more than the first. 
                     * It may also result from a simultaneous PMI with another exception which was prioritized
                     * In this case, current pmi does not matter. Just go on with the second run.*/
                    
                    // If simulatneous PMI and exception, Lapic::read_instCounter() must be 0xFFFFFFF00001
                    if(Lapic::read_instCounter() == Lapic::perf_max_count - MAX_INSTRUCTION + 1)
                        check_exit();
                    
                    Pe::print_current(ec->utcb ? false : true);
                    Pe_state::dump();
                    Console::print("Attention : from >< prevreason %d:%d counter1 %llx counter2 %llx ", 
                        prev_reason, from, counter1, Lapic::read_instCounter());
                    
                    
                }
                exc_counter2 = exc_counter;
                counter2 = Lapic::read_instCounter();
                Lapic::cancel_pmi();
                /*
                 * Here we assume that Lapic::start_counter = (Lapic::perf_max_count - MAX_INSTRUCTION) ie 0xFFFFFFF00000
                 * So when counter overflows, counter2 will NEVER be > Lapic::start_counter.
                 */
                second_run_instr_number = counter2 < Lapic::start_counter ? 
                    MAX_INSTRUCTION + counter2 - exc_counter2 : counter2 - (Lapic::perf_max_count - MAX_INSTRUCTION);
                assert(second_run_instr_number < Lapic::perf_max_count);
                if(second_run_instr_number > (MAX_INSTRUCTION + 300)){
                    Console::panic("PMI not served early counter2 %llx \nMust be dug deeper", counter2);
                } 
                distance_instruction = distance(first_run_instr_number, second_run_instr_number);
                if(!ec->utcb)
                    trace(0, "restoring %d count1 %llx count2 %llx counter %llx", distance_instruction <= 2 ? 0 : 
                        first_run_instr_number > second_run_instr_number ? 2 : 1, first_run_instr_number, 
                        second_run_instr_number, Lapic::read_instCounter());
                if (distance_instruction <= 2) {
                    if (ec->compare_regs_mute()) {
                        nbInstr_to_execute = distance_instruction + 1;
                        if(ec->utcb){
                            prev_rip = current->regs.REG(ip);
                            ec->enable_step_debug(SR_EQU);
                            ret_user_iret();
                        } else {
                            prev_rip = Vmcs::read(Vmcs::GUEST_RIP);
                            vmx_enable_single_step(SR_EQU);
                        }
                    } else {
                        //                        check_instr_number_equals(5);                        
                    }
                } else if (first_run_instr_number > second_run_instr_number) {
                    nbInstr_to_execute = first_run_instr_number - second_run_instr_number;
                    if(ec->utcb){
                        prev_rip = current->regs.REG(ip);
                        ec->enable_step_debug(SR_PMI);
                        ret_user_iret();
                    } else {
                        prev_rip = Vmcs::read(Vmcs::GUEST_RIP);
                        vmx_enable_single_step(SR_PMI);
                    }
                } else if (first_run_instr_number < second_run_instr_number) {
                    ec->restore_state1();
                    nbInstr_to_execute = second_run_instr_number - first_run_instr_number;
                    if(ec->utcb){
                        prev_rip = current->regs.REG(ip);
                        ec->enable_step_debug(SR_PMI);
                        ret_user_iret();
                    } else {
                        prev_rip = Vmcs::read(Vmcs::GUEST_RIP);
                        vmx_enable_single_step(SR_PMI);
                    }
                }
            }
        {
            prepare_checking();    
            reg_diff = ec->compare_regs(from);
            if (Cow_elt::compare_and_commit() ||reg_diff) {
                Pe::print_current(ec->utcb ? false : true);
                Pe_state::dump();
                Console::panic("Checking failed : Ec %s  Pd: %s From: %d:%d launch_state: %d", ec->get_name(), pd->get_name(), prev_reason, from, launch_state);
                ec->rollback();
                ec->reset_all();
                ec->save_state();
                //                    current->pd->cow_list = nullptr;
                //                    run_number = 0;
                //                    nbInstr_to_execute = first_run_instr_number;
                //                    current->save_state();
                //                    launch_state = Ec::IRET;
                //                    current->enable_step_debug(SR_DBG);
                check_exit();
            } else {
                ++Counter::nb_pe;
                launch_state = UNLAUNCHED;
                reset_all();
                return;
            }
        }
        default:
            Console::panic("run_number must be 0 or 1. Current run_number is %d", run_number);
    }
}

void Ec::check_exit() {
    switch (launch_state) {
        case SYSEXIT:
            ret_user_sysexit();
            break;
        case IRET:
            ret_user_iret();
            break;
        case VMRESUME:
            ret_user_vmresume();
            break;
        case VMRUN:
            ret_user_vmrun();
            break;
        case UNLAUNCHED:
            Console::panic("Bad Run launch_state %u", launch_state);
    }
}

void Ec::reset_counter() {
    exc_counter = counter1 = counter2 = exc_counter1 = exc_counter2 = nb_inst_single_step = 0;
    distance_instruction = first_run_instr_number = second_run_instr_number = 0;
    Pe::reset_counter();
    Lapic::program_pmi();
}

void Ec::reset_all() {
    run_number = 0;
    reset_counter();
    prev_reason = 0;
    no_further_check = false;
    Pending_int::exec_pending_interrupt();
    Pe_state::free_recorded_pe_state();
}

void Ec::start_debugging(Debug_type dt) {
    debug_type = dt;
    rollback();
    //                ec->reset_all();
    //                check_exit();
    run_number = 0;
    nbInstr_to_execute = first_run_instr_number;
    save_state();
    launch_state = Ec::IRET;
    enable_step_debug(SR_DBG);
    check_exit();
}

void Ec::debug_record_info() {
    switch (debug_type) {
        case CMP_TWO_RUN:

            break;
        case STORE_RUN_STATE:
            current->take_snaphot();
            break;
        default:
            Console::panic("Undefined debug type %u", debug_type);
    }
}

void Ec::prepare_checking(){
    Cpu_regs regs = current->regs;
    if (Pe::inState1){
        current->regs_1 = regs;
        Pe::c_regs[1] = regs;    
        if(!current->utcb){
            Pe::vmcsRIP_1 = Vmcs::read(Vmcs::GUEST_RIP);        
            Pe::vmcsRSP_1 = Vmcs::read(Vmcs::GUEST_RSP);  
        }
    } else {
        current->regs_2 = regs;
        Pe::c_regs[3] = regs;            
        if(!current->utcb){
            Pe::vmcsRIP_2 = Vmcs::read(Vmcs::GUEST_RIP);        
            Pe::vmcsRSP_2 = Vmcs::read(Vmcs::GUEST_RSP);   
        }
    }
}
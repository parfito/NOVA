/*
 * Execution Context
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012 Udo Steinberg, Intel Corporation.
 * Copyright (C) 2013-2018 Alexander Boettcher, Genode Labs GmbH.
 * Copyright (C) 2016-2019 Parfait Tokponnon, UCLouvain.
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
#include "pe_stack.hpp"
#include "log.hpp"
#include "pe.hpp"
#include "log_store.hpp"

ALIGNED(16) static Fpu empty;

void Fpu::init()
{
    empty.load();
    asm volatile ("fninit");
}

void Ec::load_fpu()
{
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

/**
 * Handle device (floating point unit) not available exception
 */
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

/**
 * Handle General Protection fault
 * @param r
 * @return true if the kernel can handle this
 */
bool Ec::handle_exc_gp(Exc_regs *r) {
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

    /**
     * If we get here, something went seriously wrong
     * The following are for debugging purpose
     */
    mword *ptr = reinterpret_cast<mword*>(Hpt::remap_cow(Pd::kern.quota, 
            Ec::current->getPd()->Space_mem::loc[Cpu::id], r->REG(ip), 3, sizeof(mword)));
    assert(ptr);
    char inst_buff[STR_MAX_LENGTH];
    instruction_in_hex(*ptr, inst_buff);
    String *buffer = new String(2*STR_MAX_LENGTH);
    String::print(buffer->get_string(), "GP in %s: Ec: %s  Pd: %s EIP %#lx:%#lx:%#lx:%#lx(%s), rdi %#lx",
    r->user() ? "USER" : "KERNEL", ec->get_name(), ec->getPd()->get_name(), regs_0.REG(ip), 
    regs_1.REG(ip), regs_2.REG(ip), r->REG(ip), inst_buff, r->REG(di));
    Logstore::add_entry_in_buffer(buffer->get_string());
    trace(0, "%s", buffer->get_string());
    delete buffer;
    Logstore::dump("handle_exc_gp", true);
    Counter::dump();
    ec->start_debugging(Debug_type::STORE_RUN_STATE);
    return false;
}

/**
 * 
 * @param r
 */
void Ec::handle_exc_db(Exc_regs *r) {
    if (r->user()) {
        assert(step_reason);
        single_stepped = true;
        switch (step_reason) {
            case SR_MMIO:
            case SR_PIO:
            case SR_RDTSC:
                // trace(0, "EXC_DB step_reason: %d", step_reason);
                if (not_nul_cowlist && step_reason != SR_PIO) {
                    trace(0, "cow_list not null was noticed Pd: %s", 
                            current->getPd()->get_name());
                    not_nul_cowlist = false;
                }
                if (!Cow_elt::is_empty()) {
                    if (step_reason != SR_PIO)
                        trace(0, "cow_list not null, noticed! Pd: %s", 
                                current->getPd()->get_name());
                    else {
                        not_nul_cowlist = true;
                    }
                }
                current->disable_step_debug();
                launch_state = UNLAUNCHED;
                return;
            case SR_PMI:
            {
                char buff[STR_MAX_LENGTH];
                ++Counter::pmi_ss;
                nb_inst_single_step++;
                if(nb_inst_single_step > nbInstr_to_execute + 5) {
                    Console::panic("SR_PMI Run %d Lost in Single stepping nb_inst_single_step %llu "
                    "nbInstr_to_execute %llu first_run_instr_number %llu second_run_instr_number %llu Pd %s Ec %s", Pe::run_number, nb_inst_single_step, 
                    nbInstr_to_execute, first_run_instr_number, second_run_instr_number, Pd::current->get_name(), Ec::current->get_name());
                }
//                if (nbInstr_to_execute > 0)
//                    nbInstr_to_execute--;
                if (prev_rip == current->regs.REG(ip)) { // Rep Prefix
                    nb_inst_single_step--;
//                    nbInstr_to_execute++; // Re-adjust the number of instruction                  
                    
                    // It may happen that this is the final instruction
                    Register cmp = current->compare_regs();
                    if (cmp) {
                        String::print(buff, "SR_PMI Run %d REP_PREF %s is different %lx:%lx:%lx:%lx nbSS %llu nbInstToExec %llu Pd %s Ec %s", Pe::run_number, 
                        reg_names[cmp], current->get_reg(cmp, 0), current->get_reg(cmp, 1), current->get_reg(cmp, 2), current->get_reg(cmp), 
                        nb_inst_single_step, nbInstr_to_execute, Pd::current->get_name(), Ec::current->get_name());
                        Logstore::add_entry_in_buffer(buff);
                    } else {
                        // check_instr_number_equals(1);
                        current->disable_step_debug();
                        if(Pe::inState1) {
                            current->restore_state2();
                        }
                        check_memory(PES_SINGLE_STEP);
                        return;
                    }
                }
                prev_rip = current->regs.REG(ip);
                // No need to compare if nbInstr_to_execute > 3 
                if (nb_inst_single_step < nbInstr_to_execute - 2) {
                    current->regs.REG(fl) |= Cpu::EFL_TF;
                    return;
                } else {
                    Register cmp = current->compare_regs();
                    if (cmp) {
                        String::print(buff, "SR_PMI Run %d : %s is different %lx:%lx:%lx:%lx nbSS %llu nbInstToExec %llu Pd %s Ec %s", Pe::run_number, 
                        reg_names[cmp], current->get_reg(cmp, 0), current->get_reg(cmp, 1), current->get_reg(cmp, 2), current->get_reg(cmp), 
                        nb_inst_single_step, nbInstr_to_execute, Pd::current->get_name(), Ec::current->get_name());
                        Logstore::add_entry_in_buffer(buff);
                        current->regs.REG(fl) |= Cpu::EFL_TF;
    //                    nbInstr_to_execute = 1;
                        return;
                    } else {
    //                    check_instr_number_equals(2);
                        current->disable_step_debug();
                        if(Pe::inState1) {
                            current->restore_state2();
                        }
                        check_memory(PES_SINGLE_STEP);
                        return;
                    }
                }
                break;
            }
            case SR_GP:
                return;
                break;
            case SR_DBG:
                if (nb_inst_single_step > nbInstr_to_execute) {
                    Console::panic("SR_DBG Finish");
                } else {
                    current->regs.REG(fl) |= Cpu::EFL_TF;
                    char buff[STR_MAX_LENGTH];
                    String::print(buff, "%llu IP %lx", nb_inst_single_step, current->regs.REG(ip)); 
                    Logstore::add_entry_in_buffer(buff);
                    nb_inst_single_step++;
                    return;
                }
                break;
            case SR_EQU:
            {
                char buff[STR_MAX_LENGTH];
                ++Counter::pmi_ss;
                if(nb_inst_single_step > nbInstr_to_execute){
                    Console::panic("SR_EQU Run %d Lost in Single stepping nb_inst_single_step %llu nbInstr_to_execute %llu "
                    "first_run_instr_number %llu second_run_instr_number %llu Pd %s Ec %s", Pe::run_number, nb_inst_single_step, nbInstr_to_execute, 
                    first_run_instr_number, second_run_instr_number, Pd::current->get_name(), Ec::current->get_name());
                }
                nb_inst_single_step++;
//                if (nbInstr_to_execute > 0)
//                    nbInstr_to_execute--;
                if (prev_rip == current->regs.REG(ip)) { // Rep Prefix
                    nb_inst_single_step--;
//                    nbInstr_to_execute++; // Re-adjust the number of instruction                  
                    
                    // It may happen that this is the final instruction
                    Register cmp = current->compare_regs();
                    if (cmp) {
                        String::print(buff, "SR_EQU && REP_PREF Run %d %s is different %lx:%lx:%lx:%lx nbSS %llu nbInstToExec %llu Pd %s Ec %s", 
                        Pe::run_number, reg_names[cmp], current->get_reg(cmp, 0), current->get_reg(cmp, 1), current->get_reg(cmp, 2), 
                        current->get_reg(cmp), nb_inst_single_step, nbInstr_to_execute, Pd::current->get_name(), Ec::current->get_name());
                        Logstore::add_entry_in_buffer(buff);
                    } else {
                        // check_instr_number_equals(3);
                        current->disable_step_debug();
                        if(Pe::inState1) {
                            current->restore_state2();
                        }
                        check_memory(PES_SINGLE_STEP);
                        return;
                    }
                }
                //here, single stepping 2nd run should be ok
                Register cmp = current->compare_regs();
                if (cmp) {
                    String::print(buff, "SR_EQU Run %d %s is different %lx:%lx:%lx:%lx nbSS %llu nbInstToExec %llu Pd %s Ec %s", 
                    Pe::run_number, reg_names[cmp], current->get_reg(cmp, 0), current->get_reg(cmp, 1), current->get_reg(cmp, 2), 
                    current->get_reg(cmp), nb_inst_single_step, nbInstr_to_execute, Pd::current->get_name(), Ec::current->get_name());
                    Logstore::add_entry_in_buffer(buff);
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
                            current->regs.REG(fl) |= Cpu::EFL_TF;
                        } else {
                            Console::panic("SR_EQU Run %d run_switched but %s is different %lx:%lx:%lx:%lx nb_inst_single_step %llu "
                                "nbInstr_to_execute %llu first_run_instr_number %llu second_run_instr_number %llu Pd %s Ec %s", 
                                Pe::run_number, reg_names[cmp], current->get_reg(cmp, 0), current->get_reg(cmp, 1), current->get_reg(cmp, 1),
                                current->get_reg(cmp), nb_inst_single_step, nbInstr_to_execute, first_run_instr_number, second_run_instr_number, 
                                Pd::current->get_name(), Ec::current->get_name());                            
                        }
                        return;
                    } else { // relaunch the first run without restoring the second execution state
                        current->regs.REG(fl) |= Cpu::EFL_TF;
                        return;
                    }
                } else {
                    // check_instr_number_equals(4);
                    current->disable_step_debug();
                    if(Pe::inState1) {
                        current->restore_state2();
                    }
                    check_memory(PES_SINGLE_STEP);
                    return;
                }
                break;
            }
            default:
                Console::panic("No step Reason");
        }
    } else {
        die("Debug in kernel");
    }
}

/**
 * 
 * @param vec
 * @return check_reason : PE_stopby, the deterministic cause of the this exception, 0, if not 
 * deterministic
 */
bool Ec::handle_deterministic_exception(mword vec, PE_stopby &stop_reason) {
    keep_cow = false;
    switch (vec) {
        case Cpu::EXC_INV:
            return (stop_reason = PES_DEV_NOT_AVAIL);
        case Cpu::EXC_NM:
            return (stop_reason = PES_DEV_NOT_AVAIL);
        case Cpu::EXC_TS:
            return (stop_reason = PES_INVALID_TSS);
        case Cpu::EXC_GP:
            keep_cow = true;
            return (stop_reason = PES_GP_FAULT);
        case Cpu::EXC_AC:
            return (stop_reason = PES_ALIGNEMENT_CHECK);
        case Cpu::EXC_MC:
            return (stop_reason = PES_MACHINE_CHECK);
        default :
            return (stop_reason = PES_DEFAULT);
    }
}

/**
 * Handle page fault exections
 * @param r
 * @return 
 */
bool Ec::handle_exc_pf(Exc_regs *r) {
    mword addr = r->cr2;

    // Is this page fault due to our hardenning code?
    if ((r->err & Hpt::ERR_U) && 
            Pd::current->Space_mem::is_cow_fault(Pd::current->quota, addr, r->err))
        return true;
    // From here, this is a native page fault. Nova got to resolve this.
    if (r->cs & 3){ // if page fault is user space one
        // So we stop the PE here only if the page fault comes from user space.
        check_memory(PES_PAGE_FAULT);
    }
    if (r->err & Hpt::ERR_U)
        return addr < USER_ADDR && Pd::current->Space_mem::loc[Cpu::id].sync_user (Pd::current->quota, Pd::current->Space_mem::hpt, addr);

    if (addr < USER_ADDR) {

        if (Pd::current->Space_mem::loc[Cpu::id].sync_from(Pd::current->quota, 
                Pd::current->Space_mem::hpt, addr, USER_ADDR))
            return true;

        if (fixup(r->REG(ip))) {
            r->REG(ax) = addr;
            return true;
        }
    }

    if (addr >= LINK_ADDR && addr < CPU_LOCAL && 
            Pd::current->Space_mem::loc[Cpu::id].sync_from(Pd::current->quota, 
            Hptp(reinterpret_cast<mword> (&PDBR)), addr, CPU_LOCAL))
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
/**
 * 
 * @param r : pointer to the faulty process registers and error code
 */
void Ec::handle_exc(Exc_regs *r) {
    Counter::exc[r->vec][Pe::run_number]++;
    if(Pe::run_number == 1 && step_reason == SR_NIL && run1_reason == PES_PMI) {
// What are your doing here? Actually, it means 2nd run exceeds 1st run and trigger exception
// In this case, PMI must be pending and should be served just after IRET
        return;
    }

    // Deterministic? May this exception be replayed or not
    PE_stopby check_reason = PES_DEFAULT;
    if(r->user() && handle_deterministic_exception(r->vec, check_reason)){
        check_memory(check_reason);        
    }
    switch (r->vec) {
        // Debug exception
        case Cpu::EXC_DB:
            handle_exc_db(r);
            return;
        
        // Non Maskable Interrupt
        case Cpu::EXC_NMI:
            Console::panic("NMI not handled yet");
            return;

        // Non Maskable Interrupt
        case Cpu::EXC_INV:
            Console::panic("Invalid Opcode");
            return;

            // Device not available
        case Cpu::EXC_NM:
            handle_exc_nm();
            return;
        
        // Invalid Task Segment Selector
        case Cpu::EXC_TS:
            if (handle_exc_ts(r))
                return;
            break;
           
        // If General Protection fault
        case Cpu::EXC_GP:
            if (handle_exc_gp(r))
                return;
            break;

        // if page fault
        case Cpu::EXC_PF:
            if (handle_exc_pf(r))
                return;
            break;

        case Cpu::EXC_AC:
            Console::print("Alignement check exception");
            break;
        // Machine check exception
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
 * This function is called at the end of every processing element to save the first and second run
 * states and also to make the states comparison and commitment if everythins went fine
 * @param from : where it is called from. Must be different from 0
 */
void Ec::check_memory(PE_stopby from) {
    assert(from);
    char buff[STR_MAX_LENGTH];
    String::print(buff, "run %u from %s", Pe::run_number, pe_stop[from]);
    Logstore::append_log_in_buffer(buff);    
    // Is cow_elts empty? If yes, and if we are not in recovering from stack fault or debuging our 
    // code, no memory to check
    if (Cow_elt::is_empty() && !Pe::in_debug_mode) {
        launch_state = UNLAUNCHED;
        reset_all();
        return;
    }
    Ec *ec = current;
    switch (Pe::run_number) {
        case 0:// First run
            String::print(buff, "rip1 %lx", ec->utcb ? from == PES_SYS_ENTER ? ec->regs.ARG_IP : 
                ec->regs.REG(ip) : Vmcs::read(Vmcs::GUEST_RIP));
            Logstore::append_log_in_buffer(buff);    
            run1_reason = from;
            ec->restore_state0();
            counter1 = Lapic::read_instCounter();
            second_max_instructions = MAX_INSTRUCTION;
            if (from == PES_PMI) {
                exc_counter1 = exc_counter;
                counter1 = Lapic::read_instCounter();
                /*
                 * Here we assume that Lapic::start_counter = (Lapic::perf_max_count - 
                 * MAX_INSTRUCTION) ie 0xFFFFFFF00000. So when counter overflows, counter1 will 
                 * NEVER be > Lapic::start_counter.
                 */
                first_run_instr_number = counter1 < Lapic::start_counter ? 
                    MAX_INSTRUCTION + counter1 - exc_counter1 : counter1 - (Lapic::perf_max_count - 
                        MAX_INSTRUCTION);
                assert(first_run_instr_number < Lapic::perf_max_count);
                if (current->utcb) {
                    uint8 *ptr = reinterpret_cast<uint8 *> (Hpt::remap_cow(Pd::kern.quota, 
                        Pd::current->Space_mem::loc[Cpu::id], ec->regs_1.REG(ip), 3));
                    if (ptr && (*ptr == 0xf3 || *ptr == 0xf2)) { // rep prefix
                        // We only deal with when the two runs are stopped in rep prefix, 
                        // There is also when one run is stopped before/after the rep prefix 
                        // instruction and the other is stopped right in the rep prefix instruction
                        char instr_buff[STR_MIN_LENGTH];
                        instruction_in_hex(*(reinterpret_cast<mword *> (ptr)), instr_buff);
                        String::print(buff, "Rep prefix in Run0 %lx: %s rcx %lx", ec->regs_1.REG(ip), 
                            instr_buff, ec->regs_1.REG(cx));
                        trace(0, "%s", buff);
                        Logstore::add_entry_in_buffer(buff);
                        in_rep_instruction = true;
                        Cpu::disable_fast_string();
                    }
                }/*else{ // Does VMX REP PREFIX exist?
                    
                }*/
                
                /* Currently, this only happens on vmx execution on qemu.
                 * must be dug deeper
                 */
                if((first_run_instr_number > MAX_INSTRUCTION + 300) || 
                        (first_run_instr_number < MAX_INSTRUCTION - 300)){
                    String::print(buff, "PMI served too early or too late first_run_instr_number %llu "
                    "counter1 %llx \nMust be dug deeper", first_run_instr_number, counter1);
                    Logstore::add_entry_in_buffer(buff);
                    Console::panic("%s", buff);          
                }
            } 
            Pe::run_number++;
            exc_counter = 0;
            if(step_reason == SR_DBG){
                nb_inst_single_step = 0;
            }
            Lapic::program_pmi(ec->utcb ? 0 : Lapic::perf_max_count);
            check_exit();
            break;
        case 1: // Second run
            /* If from is not PES_PMI nor PES_SINGLE_STEP and prev_reason == PES_PMI, 
             * surely the second run exceeds the first in a way the second run 
             * encounter an exception not found during the first run. So we have to 
             * single step the first run to catch up the second.
             * 
             */
            if (from == PES_PMI || (run1_reason == PES_PMI && from != PES_SINGLE_STEP)) {
                if (run1_reason != PES_PMI) {
                    /* This means that the second run lasts more than the first. It may also result 
                     * from a simultaneous PMI with another exception which was prioritized
                     * In this case, current pmi does not matter. Just go on with the second run.*/
                    
                    // If simulatneous PMI and exception, Lapic::read_instCounter() must be 
                    // 0xFFFFFFF00001
                    if(Lapic::read_instCounter() == Lapic::perf_max_count - second_max_instructions + 1)
                        check_exit();
                    
                    Logstore::dump("check_memory 1", true);
                    trace(0, "Attention : from >< prevreason %s%s counter1 %llx "
                    "counter2 %llx", pe_stop[run1_reason], pe_stop[from], counter1, Lapic::read_instCounter());
                }
                exc_counter2 = exc_counter;
                counter2 = Lapic::read_instCounter();
                Lapic::program_pmi();
                /*
                 * Here we assume that Lapic::start_counter = (Lapic::perf_max_count - 
                 * MAX_INSTRUCTION) ie 0xFFFFFFF00000. So when counter overflows, counter2 will 
                 * NEVER be > Lapic::start_counter.
                 */
                second_run_instr_number = counter2 < Lapic::start_counter ? 
                    second_max_instructions + counter2 - exc_counter2 : 
                    counter2 - (Lapic::perf_max_count - second_max_instructions);
                assert(second_run_instr_number < Lapic::perf_max_count);
                if ((second_run_instr_number > second_max_instructions + 300) || 
                        (second_run_instr_number < second_max_instructions - 300)){
                    trace(0, "PMI served too early or too late counter2 %llx \nMust be dug deeper", 
                            counter2);
                } 
                distance_instruction = distance(first_run_instr_number, second_run_instr_number);
//                if(!ec->utcb)
//                    trace(0, "restoring %d count1 %llx count2 %llx counter %llx", 
//                      distance_instruction <= 2 ? 0 : first_run_instr_number > 
//                      second_run_instr_number ? 2 : 1, first_run_instr_number, 
//                      second_run_instr_number, Lapic::read_instCounter());
                if (distance_instruction <= 2) {
                    Register cmp = ec->compare_regs();
                    if (cmp) {
                        String::print(buff, "distance_instruction %llu %s is different %lx:%lx:%lx:%lx 1stRunInstr %llu 2ndRunInstr %llu", 
                            distance_instruction, reg_names[cmp], current->get_reg(cmp, 0), current->get_reg(cmp, 1), current->get_reg(cmp, 2), 
                            current->get_reg(cmp), first_run_instr_number, second_run_instr_number);
                        Logstore::add_entry_in_buffer(buff);                    
                        nbInstr_to_execute = distance_instruction + 1;
                        if (first_run_instr_number > second_run_instr_number) {
                            if(ec->utcb) {
                                prev_rip = current->regs.REG(ip);
                                ec->enable_step_debug(SR_EQU);
                                ret_user_iret();
                            } else {
                                prev_rip = Vmcs::read(Vmcs::GUEST_RIP);
                                vmx_enable_single_step(SR_EQU);
                            }
                        } else if (first_run_instr_number < second_run_instr_number) {
                            ec->restore_state1();
                            if(ec->utcb) {
                                prev_rip = current->regs.REG(ip);
                                ec->enable_step_debug(SR_EQU);
                                ret_user_iret();
                            } else {
                                prev_rip = Vmcs::read(Vmcs::GUEST_RIP);
                                vmx_enable_single_step(SR_EQU);
                            }
                        } else {
                            if(single_stepped) {
                                assert(ec->utcb);
                                prev_rip = current->regs.REG(ip);
                                nbInstr_to_execute = 1;
                                ec->enable_step_debug(SR_EQU);
                                ret_user_iret();
                            } else if(in_rep_instruction) {
                                assert(ec->utcb);
                                prev_rip = current->regs.REG(ip);
                                mword rcx1 = current->get_reg(RCX, 1), rcx2 = current->get_reg(RCX);
                                String::print(buff, "rcx %lx:%lx ", rcx1, rcx2);
                                Logstore::add_entry_in_buffer(buff);                    
                                nbInstr_to_execute = rcx1 > rcx2 ? rcx1 - rcx2 : rcx2 - rcx1;
                                if(rcx1 > rcx2)
                                    ec->restore_state1();
                                ec->enable_step_debug(SR_EQU);
                                ret_user_iret();
                            }
                            Console::panic("1stInstnb = 2Instnb but %s is different %lx:%lx:%lx "
                            "first_run_instr_number %llu second_run_instr_number %llu", 
                            reg_names[cmp], current->get_reg(cmp, 0), current->get_reg(cmp, 1), 
                            current->get_reg(cmp), first_run_instr_number, second_run_instr_number);
                        }
                    } else {
                        //                        check_instr_number_equals(5);                        
                    }
                } else if (first_run_instr_number > second_run_instr_number) {
                    String::print(buff, "Single stepping required 1stRunInstr %llu 2ndRunInstr %llu", 
                        first_run_instr_number, second_run_instr_number);
                    Logstore::add_entry_in_buffer(buff);                    
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
                    String::print(buff, "Single stepping required 1stRunInstr %llu 2ndRunInstr %llu", 
                        first_run_instr_number, second_run_instr_number);
                    Logstore::add_entry_in_buffer(buff);                    
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
            int reg_diff = ec->compare_regs(from);
            String::print(buff, "rip2 %lx", ec->utcb ? from == PES_SYS_ENTER ? 
                ec->regs.ARG_IP : ec->regs_2.REG(ip) : Vmcs::read(Vmcs::GUEST_RIP));
            Logstore::append_log_in_buffer(buff);    
            if (Cow_elt::compare() || reg_diff) {
                if(IN_PRODUCTION){
                    Logstore::commit_buffer();
                    ec->rollback();
                    ec->reset_all();
                    ec->restore_state0_data();
                    check_exit();
                } else {
                    Pd *pd = ec->getPd();
                    String *s = new String(2*STR_MAX_LENGTH);
                    String::print(s->get_string(), "Checking failed by %s : Ec %s  Pd: %s From: %s:%s launch_state: %s "
                        "nb_cow_fault %u counter1 %llx counter2 %llx Nb_pe %llu is_saved %d", reg_diff ? 
                        reg_names[reg_diff] : "memory", ec->get_name(), pd->get_name(), pe_stop[run1_reason], 
                        pe_stop[from], launches[launch_state], Counter::cow_fault, counter1, counter2 ? counter2 : 
                        Lapic::read_instCounter(),  Counter::nb_pe, Fpu::is_saved());
                    Logstore::add_entry_in_buffer(s->get_string());
                    trace(0, "%s", s->get_string());
                    delete s;
                    Logstore::dump("check_memory 2", true);
                    counter2 = nbInstr_to_execute ? counter2 + nbInstr_to_execute : 
                    Lapic::read_instCounter();
                    /**
                     * Following instructions must come in this order.
                     * At this point, may be the failing check comes from guest stack change
                     * First, we save PE system values
                     */
                    uint64 nbInstr_to_execute_value = counter1 < Lapic::start_counter ? 
                        MAX_INSTRUCTION + counter1 - exc_counter1 : counter1 - (Lapic::perf_max_count - 
                            MAX_INSTRUCTION);
                    assert(nbInstr_to_execute < Lapic::perf_max_count);
    //                Console::debug_started = true;
    //                int from_value = from;
    //                int prev_reason_value = prev_reason;
                    Logstore::commit_buffer();
                    ec->debug_rollback();
                    ec->reset_all();
                    ec->save_state0();
    //                Console::print_on = true;
                    /* Try recovering from stack change check failing.
                     * Re-inforce this by !utcb, when we will be sure that stack Fail check is only 
                     * related to guest OS
                     */ 
    //                if((from_value == prev_reason_value) && (!reg_diff)){
    //                    debug_started_trace(0, "Rollback started %s", launches[launch_state]);  
    //                    check_exit();
    //                }
                    /*
                     * If we get here, it means that we have a bug or when in production, we have an SEU
                     * This is for debugging the rollback part of the hardening program.
                     * Before send in production, uncomment the previous check_exit();
                     */ 
                    // In production, we meust check_exit() to start the second redundancy round
    //                check_exit(); 
                    nbInstr_to_execute = nbInstr_to_execute_value;
                    Pe::in_debug_mode = true;
                    Console::print_on = true;
                    if(ec->utcb){
                        ec->enable_step_debug(SR_DBG);
                        check_exit();
                    } else {
                        mword guest_rip = Vmcs::read(Vmcs::GUEST_RIP);
                        Paddr hpa_miss_match_addr;
                        mword attr;
                        current->vtlb_lookup(Pe::missmatch_addr, hpa_miss_match_addr, attr);
                        mword offset = hpa_miss_match_addr & PAGE_MASK, mod = offset % sizeof(mword);
                        offset = (mod == 0) ? offset : offset - mod;
                        mword *mm_ptr = reinterpret_cast<mword*>(Hpt::remap_cow(Pd::kern.quota, 
                                hpa_miss_match_addr, 3, sizeof(mword)));
                        
                        trace(0, "SR DBG launch in VMX nbInstr_to_execute %llu guest_rip %lx "
                        "mm %lx:%lx:%p:%lx", nbInstr_to_execute, guest_rip, Pe::missmatch_addr, 
                                hpa_miss_match_addr, mm_ptr, *mm_ptr);             
                        vmx_enable_single_step(SR_DBG);
                    }
                }                
            } else {
                Cow_elt::commit();
//                trace(0, "check_memory run %d from %d name %s qce %lu:%u:%u count %llx", 
//                run_number, from, current->get_name(), cow_elt_number, Counter::cow_fault, 
//                Counter::used_cows_in_old_cow_elts, Lapic::read_instCounter());   
                if(in_rep_instruction){
                    in_rep_instruction = false;
                    Cpu::enable_fast_string();                    
                }
                launch_state = UNLAUNCHED;
                Logstore::commit_buffer();
                reset_all();
                return;
            }
        }
        [[fallthrough]];            
        default:
            Console::panic("run_number must be 0 or 1. Current run_number is %d", Pe::run_number);
    }
}

/**
 * To return to userspace by the right exit chosen among Iret, Sysret and VMResume
 */
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
            Console::panic("Bad Run launch_state %s", launches[launch_state]);
    }
}

/**
 * Reset all counters used during the processing Element execution
 */ 
void Ec::reset_counter() {
    exc_counter = counter1 = counter2 = exc_counter1 = exc_counter2 = nb_inst_single_step = 0;
    distance_instruction = first_run_instr_number = second_run_instr_number = second_max_instructions = 0;
    single_stepped = false;
    Counter::cow_fault = 0;
    Counter::used_cows_in_old_cow_elts = 0;
//    Lapic::program_pmi();
    Counter::nb_pe++;    
}
/**
 * Reset state data and counters
 */
void Ec::reset_all() {
    Pe::run_number = 0;
    reset_counter();
    run1_reason = 0;
    no_further_check = false;
    run_switched = false;
    Pending_int::exec_pending_interrupt();
}

/**
 * For debugging purpose
 * @param dt
 */
void Ec::start_debugging(Debug_type dt) {
    debug_type = dt;
    debug_rollback();
    reset_all();
    Pe::run_number = 0;
    Pe::inState1 = false;
    nbInstr_to_execute = first_run_instr_number;
    restore_state0_data();
    launch_state = Ec::IRET;
    enable_step_debug(SR_DBG);
    check_exit();
}

/**
 * For debugging purpose
 */
void Ec::debug_record_info() {
    switch (debug_type) {
        case CMP_TWO_RUN:

            break;
        case STORE_RUN_STATE:
            break;
        default:
            Console::panic("Undefined debug type %u", debug_type);
    }
}

void Ec::trace_interrupt(Exc_regs *r) {
    exc_counter++;
    count_interrupt(r);
    char counter_buff[STR_MIN_LENGTH], buff[STR_MAX_LENGTH];
    uint64 counter_value = Lapic::read_instCounter();
    if(counter_value > Lapic::perf_max_count - MAX_INSTRUCTION)
        String::print(counter_buff, "%#llx", counter_value);
    else
        String::print(counter_buff, "%llu", counter_value);
    if(r->vec == Cpu::EXC_PF) {
        String::print(buff, "PAGE FAULT Rip %lx utcb_rip %lx run_num %u addr %lx Counter %s", 
        current->regs.REG(ip), current->utcb->get_rip(), Pe::run_number, r->cr2, counter_buff);
    } else {
        String::print(buff, "INTERRUPT Rip %lx utcb_rip %lx run_num %u vec %lu Counter %s", current->regs.REG(ip), 
        current->utcb->get_rip(), Pe::run_number, r->vec, counter_buff);
    }
//    trace(0, "%s", buff);
    Logstore::add_entry_in_buffer(buff);
//    Console::print("%s", buff);    
    return;
}

void Ec::trace_sysenter(){
    char buff[STR_MAX_LENGTH];
    String::print(buff, "SysEnter ARG_IP/RIP %lx:%lx utcb_rip %lx Rdi %lx:%lx run_num %u Counter %llx", 
    current->regs.ARG_IP, current->regs.REG(ip), current->utcb->get_rip(), current->regs.ARG_1, 
    current->regs.REG(di),Pe::run_number, Lapic::read_instCounter());
    Logstore::add_entry_in_buffer(buff);
    return;
}

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
#include "lapic.hpp"
#include "pe.hpp"
#include "log_store.hpp"

void Ec::load_fpu()
{
    if (!Cmdline::fpu_eager && !utcb)
        regs.fpu_ctrl (true);

    if (EXPECT_FALSE (!fpu)) {
        if (Cmdline::fpu_eager && !utcb)
            regs.fpu_ctrl (true);

        Fpu::init();
    }
    else
        fpu->load();
}

void Ec::save_fpu()
{
    if (!Cmdline::fpu_eager && !utcb)
        regs.fpu_ctrl (false);

    if (EXPECT_FALSE (!fpu))
        fpu = new (*pd) Fpu;

    fpu->save();
}

void Ec::transfer_fpu (Ec *ec)
{
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
        Rcu::call (last);
    }

    fpowner = ec;
    bool ok = fpowner->add_ref();
    assert (ok);
}

void Ec::handle_exc_nm()
{
    if (Cmdline::fpu_eager)
        die ("FPU fault");

    Fpu::enable();

    if (current == fpowner) {
        if (!current->utcb && !current->regs.fpu_on)
           current->regs.fpu_ctrl (true);
        return;
    }

    if (fpowner)
        fpowner->save_fpu();

    current->load_fpu();

    if (fpowner && fpowner->del_rcu()) {
        Ec * last = fpowner;
        fpowner = nullptr;
        Rcu::call (last);
    }

    fpowner = current;
    bool ok = fpowner->add_ref();
    assert (ok);
}

bool Ec::handle_exc_ts (Exc_regs *r)
{
    if (r->user())
        return false;

    // SYSENTER with EFLAGS.NT=1 and IRET faulted
    r->REG(fl) &= ~Cpu::EFL_NT;

    return true;
}

bool Ec::handle_exc_gp (Exc_regs *)
{
    if (Cpu::hazard & HZD_TR) {
        Cpu::hazard &= ~HZD_TR;
        Gdt::unbusy_tss();
        asm volatile ("ltr %w0" : : "r" (SEL_TSS_RUN));
        return true;
    }

    return false;
}

bool Ec::handle_exc_pf (Exc_regs *r)
{
    mword addr = r->cr2;

    if (r->err & Hpt::ERR_U)
        return addr < USER_ADDR && Pd::current->Space_mem::loc[Cpu::id].sync_from (Pd::current->quota, Pd::current->Space_mem::hpt, addr, USER_ADDR);

    if (addr < USER_ADDR) {

        if (Pd::current->Space_mem::loc[Cpu::id].sync_from (Pd::current->quota, Pd::current->Space_mem::hpt, addr, USER_ADDR))
            return true;

        if (fixup (r->REG(ip))) {
            r->REG(ax) = addr;
            return true;
        }
    }

    if (addr >= LINK_ADDR && addr < CPU_LOCAL && Pd::current->Space_mem::loc[Cpu::id].sync_from (Pd::current->quota, Hptp (reinterpret_cast<mword>(&PDBR)), addr, CPU_LOCAL))
        return true;

    // Kernel fault in I/O space
    if (addr >= SPC_LOCAL_IOP && addr <= SPC_LOCAL_IOP_E) {
        Space_pio::page_fault (addr, r->err);
        return true;
    }

    // Kernel fault in OBJ space
    if (addr >= SPC_LOCAL_OBJ) {
        Space_obj::page_fault (addr, r->err);
        return true;
    }

    die ("#PF (kernel)", r);
}

void Ec::handle_exc (Exc_regs *r)
{
    Counter::exc[r->vec]++;

    switch (r->vec) {
        case Cpu::EXC_NMI:
            Console::print("NMI Counter %llx inVMX %s", Lapic::read_instCounter(), 
                    current->utcb ? "true" : "false");
            return;

        case Cpu::EXC_NM:
            handle_exc_nm();
            return;

        case Cpu::EXC_TS:
            if (handle_exc_ts (r))
                return;
            break;

        case Cpu::EXC_GP:
            if (handle_exc_gp (r))
                return;
            break;

        case Cpu::EXC_PF:
            if (handle_exc_pf (r))
                return;
            break;

        case Cpu::EXC_MC:
            Mca::vector();
            break;
    }

    if (r->user())
        send_msg<ret_user_iret>();

    if (Ec::current->idle_ec())
        return;

    die ("EXC", r);
}
/**
 * This function is called at the end of every processing element to save the first and second run
 * states and also to make the states comparison and commitment if everythins went fine
 * @param from : where it is called from. Must be different from 0
 */
void Ec::check_memory(PE_stopby from) {
   asm volatile ("" ::"m" (from)); // to avoid gdb "optimized out"            
}

void Ec::save_regs(Exc_regs *r) {
    char buff[STR_MAX_LENGTH];
    if(r->vec == Cpu::EXC_PF) {
        String::print(buff, "PAGE FAULT rip %lx run_num %u addr %lx Counter %llx", 
        current->regs.REG(ip), Pe::run_number, r->cr2, Lapic::read_instCounter());
    } else {
        String::print(buff, "INTERRUPT rip %lx run_num %u vec %lu Counter %llx", current->regs.REG(ip), 
        Pe::run_number, r->vec, Lapic::read_instCounter());
    }
//    trace(0, "%s", buff);
    Logstore::add_entry_in_buffer(buff);
    return;
}

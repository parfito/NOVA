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

ALIGNED(16) static Fpu empty;

void Fpu::init()
{
    empty.load();
    asm volatile ("fninit");
}

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
        return addr < USER_ADDR && Pd::current->Space_mem::loc[Cpu::id].sync_user (Pd::current->quota, Pd::current->Space_mem::hpt, addr);

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

void Ec::trace_interrupt(Exc_regs *r) {
    if(r->vec == Cpu::EXC_PF) 
        debug_started_trace(0, "PAGE FAULT rip %lx addr %lx", current->regs.REG(ip), r->cr2);
    else
        debug_started_trace(0, "INTERRUPT rip %lx vec %lu", current->regs.REG(ip), r->vec);
    return;
}

void Ec::trace_sysenter(){
    debug_started_trace(0, "SysEnter rip %lx", current->regs.ARG_IP);
    return;
}
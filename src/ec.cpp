/*
 * Execution Context
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012-2013 Udo Steinberg, Intel Corporation.
 * Copyright (C) 2014 Udo Steinberg, FireEye, Inc.
 * Copyright (C) 2013-2015 Alexander Boettcher, Genode Labs GmbH
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

#include "bits.hpp"
#include "ec.hpp"
#include "elf.hpp"
#include "hip.hpp"
#include "rcu.hpp"
#include "stdio.hpp"
#include "svm.hpp"
#include "vmx.hpp"
#include "vtlb.hpp"
#include "sm.hpp"
#include "pt.hpp"
#include "msr.hpp"

INIT_PRIORITY(PRIO_SLAB)
Slab_cache Ec::cache(sizeof (Ec), 32);
unsigned Ec::exc_counter = 0, Ec::gsi_counter1 = 0, Ec::exc_counter1 = 0, Ec::exc_counter2 = 0, 
        Ec::lvt_counter1 = 0, Ec::msi_counter1 = 0, Ec::ipi_counter1 = 0, Ec::gsi_counter2 = 0,
        Ec::lvt_counter2 = 0, Ec::msi_counter2 = 0, Ec::ipi_counter2 = 0;
unsigned Ec::step_nb = 100, Ec::compteur = 0;
bool Ec::ec_debug = false;
Ec *Ec::current, *Ec::fpowner;
// Constructors

Ec::Ec(Pd *own, void (*f)(), unsigned c) : Kobject(EC, static_cast<Space_obj *> (own)), cont(f), utcb(nullptr), pd(own), partner(nullptr), prev(nullptr), next(nullptr), fpu(nullptr), cpu(static_cast<uint16> (c)), glb(true), evt(0), timeout(this), user_utcb(0), xcpu_sm(nullptr), pt_oom(nullptr) {
    trace(TRACE_SYSCALL, "EC:%p created (PD:%p Kernel)", this, own);

    regs.vtlb = nullptr;
    regs.vmcs = nullptr;
    regs.vmcb = nullptr;
}

/**
 * create en execution context 
 * @param own
 * @param sel : selector for the execution context
 * @param p : protection domain which the execution context will be bound to
 * @param f : pointer to the routine to be executed
 * @param c : cpu
 * @param e : event selector for this execution context
 * @param u : user thread control block
 * @param s : stack pointer
 */
Ec::Ec(Pd *own, mword sel, Pd *p, void (*f)(), unsigned c, unsigned e, mword u, mword s, Pt *oom) : Kobject(EC, static_cast<Space_obj *> (own), sel, 0xd, free, pre_free), cont(f), pd(p), partner(nullptr), prev(nullptr), next(nullptr), fpu(nullptr), cpu(static_cast<uint16> (c)), glb(!!f), evt(e), timeout(this), user_utcb(u), xcpu_sm(nullptr), pt_oom(oom) {
    // Make sure we have a PTAB for this CPU in the PD
    pd->Space_mem::init(pd->quota, c);

    regs.vtlb = nullptr;
    regs.vmcs = nullptr;
    regs.vmcb = nullptr;

    if (pt_oom)
        pt_oom->add_ref();

    if (u) { // if a user thread
        //        Console::print("...user thread.");
        regs.cs = SEL_USER_CODE;
        regs.ds = SEL_USER_DATA;
        regs.es = SEL_USER_DATA;
        regs.ss = SEL_USER_DATA;
        regs.REG(fl) = Cpu::EFL_IF;
        if (glb) { // if global
            regs.REG(sp) = s;
        } else // local thread
            regs.set_sp(s);

        utcb = new (pd->quota) Utcb;

        pd->Space_mem::insert(pd->quota, u, 0, Hpt::HPT_U | Hpt::HPT_W | Hpt::HPT_P, Buddy::ptr_to_phys(utcb));

        regs.dst_portal = NUM_EXC - 2;

        trace(TRACE_SYSCALL, "EC:%p created (PD:%p CPU:%#x UTCB:%#lx ESP:%lx EVT:%#x)", this, p, c, u, s, e);

        if (pd == &Pd::root)
            pd->insert_utcb(pd->quota, u, Buddy::ptr_to_phys(utcb) >> 12);

    } else { //virtual CPU
        Console::print("...virtual CPU.");

        utcb = nullptr;

        regs.dst_portal = NUM_VMI - 2;
        regs.vtlb = new (pd->quota) Vtlb;

        if (Hip::feature() & Hip::FEAT_VMX) {

            regs.vmcs = new (pd->quota) Vmcs(reinterpret_cast<mword> (sys_regs() + 1),
                    pd->Space_pio::walk(pd->quota),
                    pd->loc[c].root(pd->quota),
                    pd->ept.root(pd->quota));

            regs.nst_ctrl<Vmcs>();

            /* allocate and register the host MSR area */
            mword host_msr_area_phys = Buddy::ptr_to_phys(new (pd->quota) Msr_area);
            Vmcs::write(Vmcs::EXI_MSR_LD_ADDR, host_msr_area_phys);
            Vmcs::write(Vmcs::EXI_MSR_LD_CNT, Msr_area::MSR_COUNT);

            /* allocate and register the guest MSR area */
            mword guest_msr_area_phys = Buddy::ptr_to_phys(new (pd->quota) Msr_area);
            Vmcs::write(Vmcs::ENT_MSR_LD_ADDR, guest_msr_area_phys);
            Vmcs::write(Vmcs::ENT_MSR_LD_CNT, Msr_area::MSR_COUNT);
            Vmcs::write(Vmcs::EXI_MSR_ST_ADDR, guest_msr_area_phys);
            Vmcs::write(Vmcs::EXI_MSR_ST_CNT, Msr_area::MSR_COUNT);

            /* allocate and register the virtual APIC page */
            mword virtual_apic_page_phys = Buddy::ptr_to_phys(new (pd->quota) Virtual_apic_page);
            Vmcs::write(Vmcs::APIC_VIRT_ADDR, virtual_apic_page_phys);
            vmcs_backup = regs.vmcs->clone();
            vmcs1 = regs.vmcs->clone();
            vmcs2 = regs.vmcs->clone();

            regs.vmcs->clear();
            cont = send_msg<ret_user_vmresume>;
            trace(TRACE_SYSCALL, "EC:%p created (PD:%p VMCS:%p VTLB:%p)", this, p, regs.vmcs, regs.vtlb);

        } else if (Hip::feature() & Hip::FEAT_SVM) {

            regs.REG(ax) = Buddy::ptr_to_phys(regs.vmcb = new (pd->quota) Vmcb(pd->quota, pd->Space_pio::walk(pd->quota), pd->npt.root(pd->quota)));

            regs.nst_ctrl<Vmcb>();
            vmcb_backup = regs.vmcb->clone();
            vmcb1 = regs.vmcb->clone();
            vmcb2 = regs.vmcb->clone();
            cont = send_msg<ret_user_vmrun>;
            trace(TRACE_SYSCALL, "EC:%p created (PD:%p VMCB:%p VTLB:%p)", this, p, regs.vmcb, regs.vtlb);
        }
    }
}

Ec::Ec(Pd *own, Pd *p, void (*f)(), unsigned c, Ec *clone) : Kobject(EC, static_cast<Space_obj *> (own), 0, 0xd, free, pre_free), cont(f), regs(clone->regs), rcap(clone), utcb(clone->utcb), pd(p), partner(nullptr), prev(nullptr), next(nullptr), fpu(clone->fpu), cpu(static_cast<uint16> (c)), glb(!!f), evt(clone->evt), timeout(this), user_utcb(0), xcpu_sm(clone->xcpu_sm), pt_oom(clone->pt_oom) {
    // Make sure we have a PTAB for this CPU in the PD
    pd->Space_mem::init(pd->quota, c);

    regs.vtlb = nullptr;
    regs.vmcs = nullptr;
    regs.vmcb = nullptr;

    if (pt_oom)
        pt_oom->add_ref();
}

//De-constructor

Ec::~Ec() {
    pre_free(this);

    if (pt_oom && pt_oom->del_ref())
        Pt::destroy(pt_oom, pd->quota);

    if (fpu)
        Fpu::destroy(fpu, pd->quota);

    if (utcb) {
        Utcb::destroy(utcb, pd->quota);
        return;
    }

    /* skip xCPU EC */
    if (!regs.vtlb)
        return;

    /* vCPU cleanup */
    Vtlb::destroy(regs.vtlb, pd->quota);

    if (Hip::feature() & Hip::FEAT_VMX) {

        regs.vmcs->make_current();

        mword host_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_LD_ADDR);
        Msr_area *host_msr_area = reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(host_msr_area_phys));
        Msr_area::destroy(host_msr_area, pd->quota);

        mword guest_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_ST_ADDR);
        Msr_area *guest_msr_area = reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(guest_msr_area_phys));
        Msr_area::destroy(guest_msr_area, pd->quota);

        mword virtual_apic_page_phys = Vmcs::read(Vmcs::APIC_VIRT_ADDR);
        Virtual_apic_page *virtual_apic_page =
                reinterpret_cast<Virtual_apic_page*> (Buddy::phys_to_ptr(virtual_apic_page_phys));
        Virtual_apic_page::destroy(virtual_apic_page, pd->quota);

        regs.vmcs->clear();

        Vmcs::destroy(regs.vmcs, pd->quota);
    } else if (Hip::feature() & Hip::FEAT_SVM)
        Vmcb::destroy(regs.vmcb, pd->quota);
}

void Ec::handle_hazard(mword hzd, void (*func)()) {
    if (hzd & HZD_RCU)
        Rcu::quiet();

    if (hzd & HZD_SCHED) {
        current->cont = func;
        Sc::schedule();
    }

    if (hzd & HZD_RECALL) {
        current->regs.clr_hazard(HZD_RECALL);

        if (func == ret_user_vmresume) {
            current->regs.dst_portal = NUM_VMI - 1;
            send_msg<ret_user_vmresume>();
        }

        if (func == ret_user_vmrun) {
            current->regs.dst_portal = NUM_VMI - 1;
            send_msg<ret_user_vmrun>();
        }

        if (func == ret_user_sysexit)
            current->redirect_to_iret();

        current->regs.dst_portal = NUM_EXC - 1;
        send_msg<ret_user_iret>();
    }

    if (hzd & HZD_STEP) {
        current->regs.clr_hazard(HZD_STEP);

        if (func == ret_user_sysexit)
            current->redirect_to_iret();

        current->regs.dst_portal = Cpu::EXC_DB;
        send_msg<ret_user_iret>();
    }

    if (hzd & HZD_TSC) {
        current->regs.clr_hazard(HZD_TSC);

        if (func == ret_user_vmresume) {
            //Console::print("TSC_OFFSET");
            current->regs.vmcs->make_current();
            Vmcs::write(Vmcs::TSC_OFFSET, static_cast<mword> (current->regs.tsc_offset));
            Vmcs::write(Vmcs::TSC_OFFSET_HI, static_cast<mword> (current->regs.tsc_offset >> 32));
        } else
            current->regs.vmcb->tsc_offset = current->regs.tsc_offset;
    }

    if (hzd & HZD_DS_ES) {
        Cpu::hazard &= ~HZD_DS_ES;
        asm volatile ("mov %0, %%ds; mov %0, %%es" : : "r" (SEL_USER_DATA));
    }

    if (hzd & HZD_FPU)
        if (current != fpowner)
            Fpu::disable();
}

void Ec::ret_user_sysexit() {
    if (current->is_idle()) {
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_STEP | HZD_RCU | HZD_FPU | HZD_DS_ES | HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_sysexit);

        current->save_state();
        current->launch_state = Ec::SYSEXIT;
    }
    if(ec_debug)
        Console::print("TF: %08lx SYSEXIT", current->regs.r11);
    asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR RET_USER_HYP) : : "m" (current->regs) : "memory");

    UNREACHED;
}

void Ec::ret_user_iret() {
    if (current->is_idle()) {
        // No need to check HZD_DS_ES because IRET will reload both anyway
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_STEP | HZD_RCU | HZD_FPU | HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_iret);

        current->save_state();
        current->launch_state = Ec::IRET;
    }
    if(ec_debug)
        Console::print("TF: %08lx IRET", current->regs.REG(fl));
    asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR LOAD_SEG RET_USER_EXC) : : "m" (current->regs) : "memory");

    UNREACHED;
}

void Ec::chk_kern_preempt() {
    if (!Cpu::preemption)
        return;

    if (Ec::current->is_idle() && Cpu::hazard & HZD_SCHED) { // this may leak from the kernel without terminating a double_running.
        Cpu::preempt_disable();
        Sc::schedule();
    }
}

void Ec::ret_user_vmresume() {
    if (current->is_idle()) {
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_TSC | HZD_RCU | HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_vmresume);

        current->regs.vmcs->make_current();

        current->vmx_save_state();
        current->launch_state = Ec::VMRESUME;
    }

    if (EXPECT_FALSE(Pd::current->gtlb.chk(Cpu::id))) {
        Pd::current->gtlb.clr(Cpu::id);
        if (current->regs.nst_on)
            Pd::current->ept.flush();
        else
            current->regs.vtlb->flush(true);
    }

    if (EXPECT_FALSE(get_cr2() != current->regs.cr2))
        set_cr2(current->regs.cr2);
    current->regs.disable_rdtsc<Vmcs>();
    asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR)
                "vmresume;"
                "vmlaunch;"
                "mov %1," EXPAND(PREG(sp);)
                : : "m" (current->regs), "i" (CPU_LOCAL_STCK + PAGE_SIZE) : "memory");

    trace(0, "VM entry failed with error %#lx", Vmcs::read(Vmcs::VMX_INST_ERROR));

    die("VMENTRY");
}

void Ec::ret_user_vmrun() {
    if (!Ec::current->hardening_started || current->is_idle()) {
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_TSC | HZD_RCU | HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_vmrun);

        current->svm_save_state();
        current->launch_state = Ec::VMRUN;
    }
    if (EXPECT_FALSE(Pd::current->gtlb.chk(Cpu::id))) {
        Pd::current->gtlb.clr(Cpu::id);
        if (current->regs.nst_on)
            current->regs.vmcb->tlb_control = 1;
        else
            current->regs.vtlb->flush(true);
    }
    current->regs.disable_rdtsc<Vmcb>();

    //    if (current->debug) {
    //        current->regs.enable_rdtsc<Vmcb>();
    //    }
    asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR)
                "clgi;"
                "sti;"
                "vmload;"
                "vmrun;"
                "vmsave;"
                EXPAND(SAVE_GPR)
                "mov %1," EXPAND(PREG(ax);)
                "mov %2," EXPAND(PREG(sp);)
                "vmload;"
                "cli;"
                "stgi;"
                "jmp svm_handler;"
                : : "m" (current->regs), "m" (Vmcb::root), "i" (CPU_LOCAL_STCK + PAGE_SIZE) : "memory");

    UNREACHED;
}

void Ec::idle() {
    for (;;) {

        mword hzd = Cpu::hazard & (HZD_RCU | HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, idle);

        uint64 t1 = rdtsc();
        asm volatile ("sti; hlt; cli" : : : "memory");
        uint64 t2 = rdtsc();

        Counter::cycles_idle += t2 - t1;
    }
}

void Ec::root_invoke() {
    Eh *e = static_cast<Eh *> (Hpt::remap(Pd::kern.quota, Hip::root_addr));
    if (!Hip::root_addr || e->ei_magic != 0x464c457f || e->ei_class != ELF_CLASS || e->ei_data != 1 || e->type != 2 || e->machine != ELF_MACHINE)
        die("No ELF");

    unsigned count = e->ph_count;
    current->regs.set_pt(Cpu::id);
    current->regs.set_ip(e->entry);
    current->regs.set_sp(USER_ADDR - PAGE_SIZE);

    ELF_PHDR *p = static_cast<ELF_PHDR *> (Hpt::remap(Pd::kern.quota, Hip::root_addr + e->ph_offset));

    for (unsigned i = 0; i < count; i++, p++) {

        if (p->type == 1) {

            unsigned attr = !!(p->flags & 0x4) << 0 | // R
                    !!(p->flags & 0x2) << 1 | // W
                    !!(p->flags & 0x1) << 2; // X

            if (p->f_size != p->m_size || p->v_addr % PAGE_SIZE != p->f_offs % PAGE_SIZE)
                die("Bad ELF");

            mword phys = align_dn(p->f_offs + Hip::root_addr, PAGE_SIZE);
            mword virt = align_dn(p->v_addr, PAGE_SIZE);
            mword size = align_up(p->f_size, PAGE_SIZE);

            for (unsigned long o; size; size -= 1UL << o, phys += 1UL << o, virt += 1UL << o)
                Pd::current->delegate<Space_mem>(&Pd::kern, phys >> PAGE_BITS, virt >> PAGE_BITS, (o = min(max_order(phys, size), max_order(virt, size))) - PAGE_BITS, attr);
        }
    }

    // Map hypervisor information page
    Pd::current->delegate<Space_mem>(&Pd::kern, reinterpret_cast<Paddr> (&FRAME_H) >> PAGE_BITS, (USER_ADDR - PAGE_SIZE) >> PAGE_BITS, 0, 1);

    Space_obj::insert_root(Pd::kern.quota, Pd::current);
    Space_obj::insert_root(Pd::kern.quota, Ec::current);
    Space_obj::insert_root(Pd::kern.quota, Sc::current);

    /* adjust root quota used by Pd::kern during bootstrap */
    Quota::boot(Pd::kern.quota, Pd::root.quota);

    /* preserve per CPU 4 pages quota */
    Quota cpus;
    bool s = Pd::root.quota.transfer_to(cpus, Cpu::online * 4);
    assert(s);

    /* preserve for the root task memory that is not transferable */
    bool res = Pd::root.quota.set_limit((1 * 1024 * 1024) >> 12, 0, Pd::root.quota);
    assert(res);

    /* setup PCID handling */
    Space_mem::boot_init();
    assert(Pd::kern.did == 0);
    assert(Pd::root.did == 1);

    /* quirk */
    if (Dpt::ord != ~0UL && Dpt::ord > 0x8) {
        trace(0, "disabling super pages for DMAR");
        Dpt::ord = 0x8;
    }

    ret_user_sysexit();
}

void Ec::handle_tss() {
    Console::panic("Task gate invoked");
}

bool Ec::fixup(mword &eip) {
    for (mword *ptr = &FIXUP_S; ptr < &FIXUP_E; ptr += 2)
        if (eip == *ptr) {
            eip = *++ptr;
            return true;
        }

    return false;
}

void Ec::die(char const *reason, Exc_regs *r) {
    if (current->utcb || current->pd == &Pd::kern) {
        if (strcmp(reason, "PT not found"))
            trace(0, "Killed EC:%p SC:%p V:%#lx CS:%#lx EIP:%#lx CR2:%#lx ERR:%#lx (%s)",
                current, Sc::current, r->vec, r->cs, r->REG(ip), r->cr2, r->err, reason);
    } else
        trace(0, "Killed EC:%p SC:%p V:%#lx CR0:%#lx CR3:%#lx CR4:%#lx (%s)",
            current, Sc::current, r->vec, r->cr0_shadow, r->cr3_shadow, r->cr4_shadow, reason);

    Ec *ec = current->rcap;

    if (ec)
        ec->cont = ec->cont == ret_user_sysexit ? static_cast<void (*)()> (sys_finish<Sys_regs::COM_ABT>) : dead;

    reply(dead);
}

void Ec::xcpu_return() {
    assert(current->xcpu_sm);
    assert(current->rcap);
    assert(current->utcb);
    assert(Sc::current->ec == current);

    current->rcap->regs = current->regs;

    current->xcpu_sm->up(ret_xcpu_reply);

    current->rcap = nullptr;
    current->utcb = nullptr;
    current->fpu = nullptr;

    Rcu::call(current);
    Rcu::call(Sc::current);

    Sc::schedule(true);
}

void Ec::idl_handler() {
    if (Ec::current->cont == Ec::idle)
        Rcu::update();
}

bool Ec::is_temporal_exc(mword v) {
    uint16 *ptr = reinterpret_cast<uint16 *> (v);
    if (*ptr == 0x310f) {// rdtsc 0f 31
        return true;
    } else
        return false;
}

bool Ec::is_io_exc(mword v) {
    /*TODO
     * Firstly we must ensure that the port the process is trying to access is 
     * within its I/O port space
     * We must also deal with the REP prefix
     */
    uint8 *ptr = reinterpret_cast<uint8 *> (v);
    switch (*ptr) {
        case 0xe4: // IN AL, imm8
        case 0xe5: // IN AX, imm8 || IN EAX, imm8
        case 0xe6: // OUT imm8, AL
        case 0xe7: // OUT imm8, AX || OUT imm8, EAX
        case 0xec: // IN AL,DX
            //            uint8 io_port = reinterpret_cast<uint8 *> (r->REG(dx));
        case 0xed: // IN AX, || IN EAX,DX
        case 0xee: // OUT DX, AL
        case 0xef: // OUT DX, AX || OUT DX, EAX
        case 0x6c: // INS m8, DX || INSB 
        case 0x6d: // INS m16, DX || INS m32, DX || INSW || INSD
        case 0x6e: // OUTS DX, m8 || OUTSB
        case 0x6f: // OUTS DX, m16 || OUTS DX, m32 || OUTSW || OUTSD
            return true;
        case 0x66:
        case 0x67:
            return is_io_exc(v + 1); // operand-size prefixe
        default:
            return false;
    }
}

void Ec::resolve_PIO_execption() {
    //    Console::print("Read PIO");
    Paddr phys;
    mword attr;
    Hpt hpt = Pd::current->Space_mem::loc[Cpu::id];
    Quota quota = Pd::current->quota;
    hpt.lookup(LOCAL_IOP_REMAP, phys, attr);
    hpt.update(quota, SPC_LOCAL_IOP, 1, phys, attr, Hpt::TYPE_DF, false);
    hpt.cow_flush(SPC_LOCAL_IOP);
    Ec::current->enable_step_debug(SPC_LOCAL_IOP, phys, attr, Step_reason::PIO);
}

void Ec::resolve_temp_exception() {
    //    Console::print("Read TSC Ec: %p, is_idle(): %d  IP: %p", current, current->is_idle(), current->regs.REG(ip));
    set_cr4(get_cr4() & ~Cpu::CR4_TSD);
    Ec::current->enable_step_debug(0, 0, 0, Step_reason::RDTSC);
}

void Ec::enable_step_debug(mword fault_addr, Paddr fault_phys, mword fault_attr, Step_reason reason) {
    regs.REG(fl) |= Cpu::EFL_TF;
    io_addr = fault_addr;
    io_phys = fault_phys;
    io_attr = fault_attr;
    step_reason = reason;
    current->launch_state = Launch_type::IRET; // to ensure that this will finished before any other thread is scheduled
    //            if (io_addr == 0x7fffd6a0) {
    //                Ec::count++;
    //            }
    //            if (Ec::count > 1) {
    //                Console::print("io_addr: %08lx  io_phys: %08lx  io_attr: %08lx", io_addr, io_phys, io_attr);
    //            }
}

void Ec::disable_step_debug() {
    regs.REG(fl) &= ~Cpu::EFL_TF;
    switch (step_reason) {
        case MMIO:
            //            Console::print("MMIO read");
            Pd::current->loc[Cpu::id].update(Pd::current->quota, io_addr, 0, io_phys, io_attr & ~Hpt::HPT_P, Hpt::TYPE_UP, true);
            Hpt::cow_flush(io_addr);
            break;
        case PIO:
            //            Console::print("PIO read");
            Paddr phys;
            mword attr;
            Pd::current->Space_mem::loc[Cpu::id].lookup(LOCAL_IOP_REMAP, phys, attr);
            //            Console::print("current: %p  io_frame: %p", Pd::current, current->io_frame);
            Pd::current->loc[Cpu::id].update(Pd::current->quota, SPC_LOCAL_IOP, 0, Pd::current->io_remap1, io_attr, Hpt::TYPE_DF, false);
            Pd::current->loc[Cpu::id].update(Pd::current->quota, SPC_LOCAL_IOP + PAGE_SIZE, 0, Pd::current->io_remap2, io_attr, Hpt::TYPE_DF, false);
            Hpt::cow_flush(SPC_LOCAL_IOP);
            Hpt::cow_flush(SPC_LOCAL_IOP + PAGE_SIZE);
            break;
        case RDTSC:
            //            Console::print("TSC read Ec: %p, is_idle(): %d  IP: %p", current, current->is_idle(), current->regs.REG(ip));
            set_cr4(get_cr4() | Cpu::CR4_TSD);
            break;
        default:
            Console::print("Unknown reason");
            break;
    }
    step_reason = NIL;
}

void Ec::clear_instCounter() {
    //Msr::write (Msr::IA32_PMC0, 0x0);
    //Msr::write (Msr::IA32_PMC1, 0x0);
    Msr::write(Msr::MSR_PERF_GLOBAL_CTRL, 0x700000003);
    Msr::write(Msr::MSR_PERF_FIXED_CTR0, 0x0);
    //Msr::write (Msr::IA32_PERFEVTSEL0, 0x004100c0);
    //Msr::write (Msr::IA32_PERFEVTSEL1, 0x004100c8);
    Msr::write(Msr::MSR_PERF_FIXED_CTRL, 0xa);
    Msr::write(Msr::IA32_PERF_GLOBAL_OVF_CTRL, 1ull<<32);
}

void Ec::incr_count(unsigned cs) {
    if (cs & 3)
        Ec::exc_counter++;
}

void Ec::restore_state() {
    pd->restore_state();
    regs = regs_0;
}

void Ec::rollback() {
    regs = regs_0;
    pd->rollback();
}

void Ec::getVec(unsigned cs, unsigned vec, mword rip) {
    if(ec_debug && (cs & 3 || vec == 1001))
        Console::print("vector: %u  cs: %u  rip: %lx", vec, cs, rip);
}
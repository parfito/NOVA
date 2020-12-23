/*
 * Execution Context
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012-2013 Udo Steinberg, Intel Corporation.
 * Copyright (C) 2014 Udo Steinberg, FireEye, Inc.
 * Copyright (C) 2012-2018 Alexander Boettcher, Genode Labs GmbH.
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
#include "lapic.hpp"
#include "string.hpp"
#include "vectors.hpp"
#include "log.hpp"
#include "cow_elt.hpp"
#include "pe_stack.hpp"
#include "pe.hpp"
#include "log_store.hpp"
#include "pending_int.hpp"

mword Ec::prev_rip = 0, Ec::tscp_rcx1 = 0, Ec::tscp_rcx2 = 0, Ec::vmlaunch, 
        Ec::guest_single_step_rsp, Ec::pe_guest_rsp, Ec::guest_start_rip, Ec::pe_start_rip;
bool Ec::hardening_started = false, Ec::in_rep_instruction = false, Ec::not_nul_cowlist = false, 
        Ec::no_further_check = false, Ec::run_switched = false, Ec::keep_cow = false, 
        Ec::single_stepped = false, Ec::ept_backup;
uint64 Ec::exc_counter = 0, Ec::exc_counter1 = 0, Ec::exc_counter2 = 0, Ec::counter1 = 0, 
        Ec::counter2 = 0, Ec::debug_compteur = 0, Ec::count_je = 0, Ec::nbInstr_to_execute = 0,
        Ec::nb_inst_single_step = 0, Ec::second_run_instr_number = 0, 
        Ec::first_run_instr_number = 0, Ec::distance_instruction = 0, Ec::prev_counter_val;
       
uint8 Ec::launch_state = 0, Ec::step_reason = 0, Ec::vmx_step_reason = 0, Ec::debug_nb = 0, 
        Ec::debug_type = 0, Ec::replaced_int3_instruction, Ec::replaced_int3_instruction2;
uint64 Ec::tsc1 = 0, Ec::tsc2 = 0;
Paddr Ec::guest_rsp_phys;

int Ec::run1_reason = 0, Ec::previous_ret = 0, Ec::nb_try = 0;
const char* Ec::reg_names[24] = {"N/A", "RAX", "RBX", "RCX", "RDX", "RBP", "RDI", "RSI", "R8", 
"R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP", "RSP", "RFLAG", "GUEST_RIP", "GUEST_RSP", 
"GUEST_RIP", "FPU_DATA", "FPU_STATE"};
const char* Ec::pe_stop[29] = {"NUL", "PMI", "PAGE_FAULT", "SYS_ENTER", "VMX_EXIT", 
"INVALID_TSS", "GP_FAULT", "DEV_NOT_AVAIL", "SEND_MSG", "MMIO", "SINGLE_STEP", 
"VMX_SEND_MSG", "VMX_EXT_INT", "GSI", "MSI", "LVT", "ALIGNEMENT_CHECK", 
"MACHINE_CHECK", "VMX_INVLPG", "VMX_PAGE_FAULT", "VMX_EPT_VIOL", "VMX_CR", "VMX_EXC",
"VMX_RDTSC", "VMX_RDTSCP", "VMX_IO", "COW_IN_STACK", "PES_SINGLE_STEP_FINISHED", "PES_VMX_MTF"};
const char* Ec::launches[6] = {"UNLAUNCHED", "SYSEXIT", "IRET", "VMRESUME", "VMRUN", "EXT_INT"};

Ec *Ec::current, *Ec::fpowner;
bool Ec::debug_started;

// Constructors

Cpu_regs Ec::regs_0, Ec::regs_1, Ec::regs_2;

Msr_area *Ec::host_msr_area0 = new (Pd::kern.quota) Msr_area, 
        *Ec::guest_msr_area0 = new (Pd::kern.quota) Msr_area,
        *Ec::host_msr_area1 = new (Pd::kern.quota) Msr_area, 
        *Ec::guest_msr_area1 = new (Pd::kern.quota) Msr_area,
        *Ec::host_msr_area2 = new (Pd::kern.quota) Msr_area, 
        *Ec::guest_msr_area2 = new (Pd::kern.quota) Msr_area;
Virtual_apic_page *Ec::virtual_apic_page0 = new (Pd::kern.quota) Virtual_apic_page,
        *Ec::virtual_apic_page1 = new (Pd::kern.quota) Virtual_apic_page,
        *Ec::virtual_apic_page2 = new (Pd::kern.quota) Virtual_apic_page;

Ec::Ec(Pd *own, void (*f)(), unsigned c, char const *nm) : 
Kobject(EC, static_cast<Space_obj *> (own)), cont(f), pd(own), partner(nullptr), prev(nullptr), 
        next(nullptr), fpu(nullptr), cpu(static_cast<uint16> (c)), glb(true), evt(0), timeout(this), 
        user_utcb(0), xcpu_sm(nullptr), pt_oom(nullptr) {
    trace(TRACE_SYSCALL, "EC:%p created (PD:%p Kernel)", this, own);
    copy_string(name, nm);
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
Ec::Ec(Pd *own, mword sel, Pd *p, void (*f)(), unsigned c, unsigned e, mword u, mword s, Pt *oom, 
        char const *nm) : Kobject(EC, static_cast<Space_obj *> (own), sel, 0xd, free, pre_free), 
        cont(f), pd(p), partner(nullptr), prev(nullptr), next(nullptr), fpu(nullptr), 
        cpu(static_cast<uint16> (c)), glb(!!f), evt(e), timeout(this), user_utcb(u), 
        xcpu_sm(nullptr), pt_oom(oom) {
    // Make sure we have a PTAB for this CPU in the PD
    pd->Space_mem::init(pd->quota, c);
    copy_string(name, nm);

    regs.vtlb = nullptr;
    regs.vmcs = nullptr;
    regs.vmcb = nullptr;

    if (pt_oom && !pt_oom->add_ref())
        pt_oom = nullptr;

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

        pd->Space_mem::insert(pd->quota, u, 0, Hpt::HPT_U | Hpt::HPT_W | Hpt::HPT_P, 
                Buddy::ptr_to_phys(utcb), pd->get_to_be_cowed() ? true : false);

        regs.dst_portal = NUM_EXC - 2;

        trace(TRACE_SYSCALL, "EC:%p created (PD:%p CPU:%#x UTCB:%#lx ESP:%lx EVT:%#x)", this, p, c, 
                u, s, e);

        if (pd == &Pd::root)
            pd->insert_utcb (pd->quota, pd->mdb_cache, u, Buddy::ptr_to_phys(utcb) >> 12);

    } else { //virtual CPU
        Console::print("...virtual CPU.");

        utcb = nullptr;

        regs.dst_portal = NUM_VMI - 2;
        regs.vtlb = new (pd->quota) Vtlb;
        regs.fpu_on = Cmdline::fpu_eager;

        if (Hip::feature() & Hip::FEAT_VMX) {
            mword host_cr3 = pd->loc[c].root(pd->quota) | (Cpu::feature (Cpu::FEAT_PCID) ? pd->did : 0);

            regs.vmcs = new (pd->quota) Vmcs (reinterpret_cast<mword>(sys_regs() + 1),
                                              pd->Space_pio::walk(pd->quota),
                                              host_cr3,
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
            regs.vmcs->clear();
            cont = send_msg<ret_user_vmresume>;
            trace(TRACE_SYSCALL, "EC:%p created (PD:%p VMCS:%p VTLB:%p)", this, p, regs.vmcs, 
                    regs.vtlb);

        } else if (Hip::feature() & Hip::FEAT_SVM) {

            regs.REG(ax) = Buddy::ptr_to_phys(regs.vmcb = new (pd->quota) Vmcb(pd->quota, 
                    pd->Space_pio::walk(pd->quota), pd->npt.root(pd->quota)));

            regs.nst_ctrl<Vmcb>();
            cont = send_msg<ret_user_vmrun>;
            trace(TRACE_SYSCALL, "EC:%p created (PD:%p VMCB:%p VTLB:%p)", this, p, regs.vmcb, 
                    regs.vtlb);
        }
    }
}

Ec::Ec(Pd *own, Pd *p, void (*f)(), unsigned c, Ec *clone, char const *nm) : 
    Kobject(EC, static_cast<Space_obj *> (own), 0, 0xd, free, pre_free), cont(f), regs(clone->regs), 
        rcap(clone), utcb(clone->utcb), pd(p), partner(nullptr), prev(nullptr), next(nullptr), 
        fpu(clone->fpu), cpu(static_cast<uint16> (c)), glb(!!f), evt(clone->evt), timeout(this), 
        user_utcb(0), xcpu_sm(clone->xcpu_sm), pt_oom(clone->pt_oom) {
    // Make sure we have a PTAB for this CPU in the PD
    pd->Space_mem::init(pd->quota, c);
    copy_string(name, nm);

    regs.vtlb = nullptr;
    regs.vmcs = nullptr;
    regs.vmcb = nullptr;

    if (pt_oom && !pt_oom->add_ref())
        pt_oom = nullptr;
}

//De-constructor

Ec::~Ec() {
    if (xcpu_sm) {
        Sm::destroy(xcpu_sm, *pd);
        xcpu_sm = nullptr;
    }

    pre_free(this);

    if (pt_oom && pt_oom->del_ref())
        Pt::destroy(pt_oom);

    if (fpu)
        Fpu::destroy(fpu, *pd);

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
        Msr_area *host_msr_area = reinterpret_cast<Msr_area*> (
                Buddy::phys_to_ptr(host_msr_area_phys));
        Msr_area::destroy(host_msr_area, pd->quota);

        mword guest_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_ST_ADDR);
        Msr_area *guest_msr_area = reinterpret_cast<Msr_area*> 
                (Buddy::phys_to_ptr(guest_msr_area_phys));
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

    if (hzd & HZD_SCHED && is_idle()) {
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

    if (hzd & HZD_FPU) {
        if (Cmdline::fpu_eager)
            die("FPU HZD detected");

        if (current != fpowner)
            Fpu::disable();
    }
}

void Ec::ret_user_sysexit() {
    if (is_idle()) {
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_STEP | HZD_RCU | 
                HZD_FPU | HZD_DS_ES | HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_sysexit);

        if (current->regs.ARG_IP >= USER_ADDR) {
            current->regs.dst_portal = 13;
            send_msg<Ec::ret_user_sysexit>();
        }

        current->save_state0();
        launch_state = Ec::SYSEXIT;
    }
    char counter_buff[STR_MIN_LENGTH];
    uint64 counter_value = Lapic::read_instCounter();
    if(counter_value < Lapic::perf_max_count - MAX_INSTRUCTION)
        String::print(counter_buff, "%llu", counter_value);
    else
        String::print(counter_buff, "%llu", counter_value - Lapic::start_counter);
    call_log_funct(Logstore::add_entry_in_buffer, 0, "Sysreting Run %d Pd %s Ec %s Rip %lx utcb_rip %lx Counter %s", Pe::run_number, 
    current->pd->get_name(), current->get_name(), current->regs.ARG_IP, current->utcb->get_rip(), counter_buff);
    if (step_reason == SR_NIL) {
        asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR RET_USER_HYP) : : "m" (current->regs) : 
                    "memory");
    } else {
        asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR RET_USER_HYP_SS) : : "m" (current->regs) :
                    "memory");
    }
    UNREACHED;
}

void Ec::ret_user_iret() {
    if (is_idle()) {
        // No need to check HZD_DS_ES because IRET will reload both anyway
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_STEP | HZD_RCU | 
                HZD_FPU | HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_iret);

        current->save_state0();
        launch_state = Ec::IRET;
    }
    char counter_buff[STR_MIN_LENGTH];
    uint64 counter_value = Lapic::read_instCounter();
    if(counter_value < Lapic::perf_max_count - MAX_INSTRUCTION)
        String::print(counter_buff, "%llu", counter_value);
    else
        String::print(counter_buff, "%llu", counter_value - Lapic::start_counter);
    call_log_funct(Logstore::add_entry_in_buffer, 0, "Ireting Run %d Pd %s Ec %s Rip %lx EFLAGS %lx utcb_rip %lx Counter %s", Pe::run_number, 
    current->pd->get_name(), current->get_name(), current->get_reg(RIP), current->get_reg(RFLAG), current->utcb->get_rip(), counter_buff);
    asm volatile ("lea %0," EXPAND(PREG(sp); LOAD_GPR LOAD_SEG RET_USER_EXC) : : "m" (current->regs)
    : "memory");

    UNREACHED;
}

void Ec::chk_kern_preempt() {
    if (!Cpu::preemption)
        return;
    // this may leak from the kernel without terminating a double_running.
    if (is_idle() && Cpu::hazard & HZD_SCHED) { 
        Cpu::preempt_disable();
        Sc::schedule();
    }
}

void Ec::ret_user_vmresume() {
    //    Console::print("VMRun is_idle %d", is_idle());
    if (is_idle()) {
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_TSC | HZD_RCU | 
                HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_vmresume);

        current->regs.vmcs->make_current();

        current->save_state0();
        launch_state = Ec::VMRESUME;
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
    guest_start_rip = Vmcs::read(Vmcs::GUEST_RIP);
    call_log_funct(Logstore::add_entry_in_buffer, nb_try ? 1 : 0, "VMResume : Run %d Ec %s "
        "RIP %lx RSP %lx RFLAGS %lx Counter %llx", Pe::run_number, current->get_name(), 
        guest_start_rip, Vmcs::read(Vmcs::GUEST_RSP), 
        Vmcs::read(Vmcs::GUEST_RFLAGS), Lapic::read_instCounter());
    if(step_reason == SR_DBG)
        enable_mtf();
    asm volatile (EXPAND(LOAD_GPR_COUNT)
                "vmresume;" // VMRESUME is not counted as instruction; we don't know why
                EXPAND(RESET_COUNTER)
                "vmlaunch;"
                "mov %2," EXPAND(PREG(sp);)
                : "=m" (vmlaunch) : "m" (current->regs), "i" (CPU_LOCAL_STCK + PAGE_SIZE), 
                "i" (CPU_LOCAL_STCK + PAGE_SIZE - 0x80),
                "m" (Cpu::nb_instruction_before_vmresume),
                "m" (Cpu::nb_instruction_after_vmresume) : EXPAND(REG(ax)), 
                EXPAND(REG(bx)), EXPAND(REG(cx)), EXPAND(REG(dx)), "memory");

    trace(0, "VM entry failed with error %#lx", Vmcs::read(Vmcs::VMX_INST_ERROR));

    die("VMENTRY");
}

void Ec::ret_user_vmrun() {
    if (is_idle()) {
        mword hzd = (Cpu::hazard | current->regs.hazard()) & (HZD_RECALL | HZD_TSC | HZD_RCU | 
                HZD_SCHED);
        if (EXPECT_FALSE(hzd))
            handle_hazard(hzd, ret_user_vmrun);

        //        current->svm_save_state();
        launch_state = Ec::VMRUN;
    }
    if (EXPECT_FALSE(Pd::current->gtlb.chk(Cpu::id))) {
        Pd::current->gtlb.clr(Cpu::id);
        if (current->regs.nst_on)
            current->regs.vmcb->tlb_control = 1;
        else
            current->regs.vtlb->flush(true);
    }
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
                : : "m" (current->regs), "m" (Vmcb::root), "i" (CPU_LOCAL_STCK + PAGE_SIZE) : 
                    "memory");

    UNREACHED;
}

void Ec::idle() {
    for (;;) {

        mword hzd = Cpu::hazard & (HZD_RCU | HZD_SCHED);
        if (is_idle() && EXPECT_FALSE(hzd))
            handle_hazard(hzd, idle);

        uint64 t1 = rdtsc();
        asm volatile ("sti; hlt; cli" : : : "memory");
        uint64 t2 = rdtsc();

//        Counter::dump();
        Counter::cycles_idle += t2 - t1;
    }
}

void Ec::root_invoke()
{
    /* transfer memory from second allocator */
    Quota tmp;
    bool ok = Quota::init.transfer_to(tmp, Quota::init.limit());
    assert(ok);
    ok = tmp.transfer_to(Pd::root.quota, tmp.limit());
    assert(ok);

    Eh *e = static_cast<Eh *>(Hpt::remap (Pd::kern.quota, Hip::root_addr));
    if (!Hip::root_addr || e->ei_magic != 0x464c457f || e->ei_class != ELF_CLASS || e->ei_data != 1 
            || e->type != 2 || e->machine != ELF_MACHINE)
        die("No ELF");

    unsigned count = e->ph_count;
    current->regs.set_pt(Cpu::id);
    current->regs.set_ip(e->entry);
    current->regs.set_sp(USER_ADDR - PAGE_SIZE);

    ELF_PHDR *p = static_cast<ELF_PHDR *> (Hpt::remap(Pd::kern.quota, 
            Hip::root_addr + e->ph_offset));

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
                Pd::current->delegate<Space_mem>(&Pd::kern, phys >> PAGE_BITS, virt >> PAGE_BITS, 
                        (o = min(max_order(phys, size), max_order(virt, size))) - PAGE_BITS, attr);
        }
    }

    // Map hypervisor information page
    Pd::current->delegate<Space_mem>(&Pd::kern, reinterpret_cast<Paddr> (&FRAME_H) >> PAGE_BITS, 
            (USER_ADDR - PAGE_SIZE) >> PAGE_BITS, 0, 1);

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

    /* LazyFP vulnerability - a never ending story Intel ? */
    if (Cpu::vendor == Cpu::Vendor::INTEL)
        Cmdline::fpu_eager = true;

    if (Cmdline::fpu_eager) {
        Ec::current->transfer_fpu(Ec::current);
        Cpu::hazard &= ~HZD_FPU;
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
    bool const show = current->pd == &Pd::kern || current->pd == &Pd::root;
    bool const pf_in_kernel = str_equal(reason, "#PF (kernel)");
    if (current->utcb || show || pf_in_kernel) {
//        if (show || !strmatch(reason, "PT not found", 12))
            trace(0, "Killed EC:%s SC:%p V:%#lx CS:%#lx IP:%#lx(%#lx) CR2:%#lx ERR:%#lx (%s) %s",
                current->name, Sc::current, r->vec, r->cs, r->REG(ip), r->ARG_IP, r->cr2, r->err, 
                    reason, current->pd == &Pd::root ? "Pd::root" : current->pd == &Pd::kern ? 
                        "Pd::kern" : "");
    } else
        trace(0, "Killed EC:%s SC:%p V:%#lx CR0:%#lx CR3:%#lx CR4:%#lx (%s) Pd: %s Ec: %s",
            current->name, Sc::current, r->vec, r->cr0_shadow, r->cr3_shadow, r->cr4_shadow, reason, 
                Pd::current->get_name(), Ec::current->get_name());
    Logstore::dump("die", false, 0);
    Ec *ec = current->rcap;

    if (ec)
        ec->cont = ec->cont == ret_user_sysexit ? 
            static_cast<void (*)()> (sys_finish<Sys_regs::COM_ABT>) : dead;

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
    current->xcpu_sm = nullptr;

    Rcu::call(current);
    Rcu::call(Sc::current);

    Sc::schedule(true);
}

void Ec::idl_handler() {
    if (Ec::current->cont == Ec::idle)
        Rcu::update();
}

bool Ec::is_temporal_exc() {
    uint16 *ptr = reinterpret_cast<uint16*>(Hpt::remap_cow(Pd::kern.quota, 
            Ec::current->getPd()->Space_mem::loc[Cpu::id], regs.REG(ip), 3, 2));
    if(!ptr)
        return false;
    if (*ptr == 0x310f) // rdtsc 0f 31
        return true;
    else if (*ptr == 0xf901) // rdtscp 0F 01 F9
        return true;
    else
        return false;
}

bool Ec::is_io_exc(mword eip) {
    /*TODO
     * Firstly we must ensure that the port the process is trying to access is 
     * within its I/O port space
     * We must also deal with the REP prefix: solved because rep prefix makes instr code = 6cf3, 
     * 6df3 e4f3 ...
     */
    mword v = eip ? eip : regs.REG(ip);
    uint8 *ptr = reinterpret_cast<uint8*>(Hpt::remap_cow(Pd::kern.quota,
            Ec::current->getPd()->Space_mem::loc[Cpu::id], v, 3));
    if(!ptr)
        return false;
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
    reinterpret_cast<Space_pio*> (pd->subspace(Crd::PIO))->enable_pio(pd->quota);
    Ec::current->enable_step_debug(SR_PIO, SPC_LOCAL_IOP, 0, 0);
}

void Ec::enable_step_debug(Step_reason reason, mword fault_addr, Paddr fault_phys, mword fault_attr) 
{
    regs.REG(fl) |= Cpu::EFL_TF;
    step_reason = reason;
    switch (reason) {
        case SR_PIO:
        case SR_MMIO:
            ++Counter::simple_io;
            io_addr = fault_addr;
            io_phys = fault_phys;
            io_attr = fault_attr;
            // Ensure that this will finished before any other thread is scheduled
            launch_state = Launch_type::IRET; 
            break;
        case SR_RDTSC:
            set_cr4(get_cr4() & ~Cpu::CR4_TSD);
            launch_state = Launch_type::IRET;
            break;
        case SR_PMI:
        case SR_EQU:
        {
            uint8 *ptr = reinterpret_cast<uint8 *> (Hpt::remap_cow(Pd::kern.quota, 
                    Ec::current->getPd()->Space_mem::loc[Cpu::id], regs.REG(ip), 3));
            if (ptr && (*ptr == 0xf3 || *ptr == 0xf2)) {
                Console::print("Rep prefix detected: Step reason %d addr %lx rcx %lx", reason, 
                        fault_addr, current->regs.REG(cx));
                in_rep_instruction = true;
                Cpu::disable_fast_string();
            }
            break;
        }
        case SR_DBG:
            break;
        case SR_NIL:
        default:
            die("Unknown debug reason -- Enable");
            break;
    }
}

void Ec::disable_step_debug() {
    regs.REG(fl) &= ~Cpu::EFL_TF;
    switch (step_reason) {
        case SR_MMIO:
            //            Console::print("MMIO read");
            Pd::current->Space_mem::loc[Cpu::id].replace_cow(Pd::current->quota, io_addr, io_phys, 
                    io_attr & ~Hpt::HPT_P);
//            Hpt::cow_flush(io_addr);
            break;
        case SR_PIO:
            //            Console::print("PIO read");
            reinterpret_cast<Space_pio*> (pd->subspace(Crd::PIO))->disable_pio(pd->quota);
            break;
        case SR_RDTSC:
// Console::print("TSC read Ec: %p, is_idle(): %d  IP: %p", current, is_idle(), 
//            current->regs.REG(ip));
            set_cr4(get_cr4() | Cpu::CR4_TSD);
            break;
        case SR_PMI:
        case SR_EQU:            
            if (in_rep_instruction) {
                Cpu::enable_fast_string();
                in_rep_instruction = false;
            }
            nbInstr_to_execute = 0;
            break;
        case SR_DBG:
            break;
        default:
            die("Unknown debug reason -- Disable");
            break;
    }
    step_reason = SR_NIL;
}

void Ec::restore_state0() {
    regs_1 = regs;
    regs = regs_0;
    Cow_elt::restore_state0();
    Fpu::dwc_restore();
    if (fpu)
        fpu->restore_data();
    if(!utcb){
        vmx_restore_state0();
    }
    Pe::c_regs[1] = regs_1;
    Pe::c_regs[2] = regs_0;
}

void Ec::restore_state1() {
    Pe::inState1 = true;
    regs_2 = regs;
    regs = regs_1;
    Cow_elt::restore_state1();
    Fpu::dwc_restore1();
    if (fpu)
        fpu->restore_data1();
    if(!utcb){
        vmx_restore_state1();
    }
    Pe::run_number = 0;
}

void Ec::restore_state2() {
    Pe::inState1 = false;
    regs_1 = regs;
    regs = regs_2;
    Cow_elt::restore_state2();
    Fpu::dwc_restore2();
    if (fpu)
        fpu->restore_data2();
    if(!utcb){
        vmx_restore_state2();
    }
    Pe::run_number = 1;
}

/**
 * cancel the double execution effects
 */
void Ec::rollback() {
    regs = regs_0;
    Fpu::dwc_rollback();
    if (fpu)
        fpu->roll_back();
    Cow_elt::rollback();
    if (!utcb) {
        vmx_rollback();
    }
    Lapic::program_pmi();    
    Pe::c_regs[0] = regs_0;
    Pe::inState1 = false;
    Pe::run_number = 0;
}

/**
 * cancel the double execution effects
 */
void Ec::debug_rollback() {
    regs = regs_0;
    Fpu::dwc_rollback();
    if (fpu)
        fpu->roll_back();
    Cow_elt::debug_rollback();
    if (!utcb) {
        vmx_rollback();
    }
}

/**
 * save state before starting the PE double execution
 */
void Ec::save_state0() {
    assert(!Pending_int::get_number());
    regs_0 = regs;
    call_log_funct(Logstore::add_log_in_buffer, 0, "PE %llu Pd %s Ec %s Rip0 %lx:%lx", Counter::nb_pe, 
    getPd()->get_name(), get_name(), regs.ARG_IP, get_reg(RIP));
    Cow_elt::free_current_pd_cowelts();
    Fpu::dwc_save(); // If FPU activated, save fpu state
    if (fpu)         // If fpu defined, save it 
        fpu->save_data();
    if(utcb){
// Ce n'est pas optimal car avec ceci on ne peut plus profiter des PE dont le cow_elts est vide
//        Pd::current->Space_mem::loc[Cpu::id].reserve_stack(Pd::current->quota, regs.REG(sp));
        Lapic::program_pmi();
    } else {
//        mword cr0_shadow = current->regs.cr0_shadow, cr3_shadow = current->regs.cr3_shadow, 
//              cr4_shadow = current->regs.cr4_shadow; 
//        regs.vtlb->reserve_stack(cr0_shadow, cr3_shadow, cr4_shadow);
        vmx_save_state0();        
        Lapic::program_pmi();
    }
    Pe::c_regs[0] = regs_0;
    Pe::inState1 = false;
    Pe::run_number = 0;
}

/**
 * called after rollback to relauch the double execution
 */
void Ec::restore_state0_data() {
    regs_0 = regs;
    Fpu::dwc_save(); // If FPU activated, save fpu state
    if (fpu)         // If fpu defined, save it 
        fpu->save_data();
    if(utcb){
// Ce n'est pas optimal car avec ceci on ne peut plus profiter des PE dont le cow_elts est vide
//        Pd::current->Space_mem::loc[Cpu::id].reserve_stack(Pd::current->quota, regs.REG(sp));
    } else {
//        mword cr0_shadow = current->regs.cr0_shadow, cr3_shadow = current->regs.cr3_shadow, 
//          cr4_shadow = current->regs.cr4_shadow; 
//        regs.vtlb->reserve_stack(cr0_shadow, cr3_shadow, cr4_shadow);
        vmx_save_state0();        
    }
    Pe::c_regs[0] = regs_0;
    Pe::inState1 = false;
    Pe::run_number = 0;
}

void Ec::vmx_save_state0() {
    if(!current->regs.nst_on)
        save_vm_stack();
    pe_start_rip = Vmcs::read(Vmcs::GUEST_RIP);   
    mword host_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_LD_ADDR);
    Msr_area *cur_host_msr_area = reinterpret_cast<Msr_area*> 
            (Buddy::phys_to_ptr(host_msr_area_phys));
    memcpy(host_msr_area0, cur_host_msr_area, PAGE_SIZE);

    mword guest_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_ST_ADDR);
    Msr_area *cur_guest_msr_area = reinterpret_cast<Msr_area*> 
            (Buddy::phys_to_ptr(guest_msr_area_phys));
    memcpy(guest_msr_area0, cur_guest_msr_area, PAGE_SIZE);

    mword virtual_apic_page_phys = Vmcs::read(Vmcs::APIC_VIRT_ADDR);
    Virtual_apic_page *cur_virtual_apic_page =
            reinterpret_cast<Virtual_apic_page*> (Buddy::phys_to_ptr(virtual_apic_page_phys));
    memcpy(virtual_apic_page0, cur_virtual_apic_page, PAGE_SIZE);

    regs.vmcs->clear();
    memcpy(Vmcs::vmcs0, regs.vmcs, Vmcs::basic.size);
    regs.vmcs->make_current();
    Pe::guest_rip[0] = Vmcs::read(Vmcs::GUEST_RIP);   
    Pe::guest_rsp[0] = Vmcs::read(Vmcs::GUEST_RSP); 
//    if(Pe_stack::rsp_tlb)
//        current->regs.vtlb->flush(Pe_stack::guest_rsp);
}

void Ec::vmx_restore_state0() {
    Pe::guest_rip[1] = Vmcs::read(Vmcs::GUEST_RIP);        
    Pe::guest_rsp[1] = Vmcs::read(Vmcs::GUEST_RSP);  
    regs.vmcs->clear();
    memcpy(Vmcs::vmcs1, regs.vmcs, Vmcs::basic.size);
    memcpy(regs.vmcs, Vmcs::vmcs0, Vmcs::basic.size);
    regs.vmcs->make_current();
    
    mword host_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_LD_ADDR);
    Msr_area *cur_host_msr_area = reinterpret_cast<Msr_area*> 
            (Buddy::phys_to_ptr(host_msr_area_phys));
    memcpy(host_msr_area1, cur_host_msr_area, PAGE_SIZE);
    memcpy(cur_host_msr_area, host_msr_area0, PAGE_SIZE);

    mword guest_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_ST_ADDR);
    Msr_area *cur_guest_msr_area = reinterpret_cast<Msr_area*> 
            (Buddy::phys_to_ptr(guest_msr_area_phys));
    memcpy(guest_msr_area1, cur_guest_msr_area, PAGE_SIZE);
    memcpy(cur_guest_msr_area, guest_msr_area0, PAGE_SIZE);

    mword virtual_apic_page_phys = Vmcs::read(Vmcs::APIC_VIRT_ADDR);
    Virtual_apic_page *cur_virtual_apic_page =
            reinterpret_cast<Virtual_apic_page*> (Buddy::phys_to_ptr(virtual_apic_page_phys));
    memcpy(virtual_apic_page1, cur_virtual_apic_page, PAGE_SIZE);
    memcpy(cur_virtual_apic_page, virtual_apic_page0, PAGE_SIZE);
}

void Ec::vmx_restore_state1() {
    assert(Pe::run_number == 1);
    Pe::guest_rip[2] = Vmcs::read(Vmcs::GUEST_RIP);        
    Pe::guest_rsp[2] = Vmcs::read(Vmcs::GUEST_RSP);        
    regs.vmcs->clear();
    memcpy(Vmcs::vmcs2, regs.vmcs, Vmcs::basic.size);
    memcpy(regs.vmcs, Vmcs::vmcs1, Vmcs::basic.size);
    regs.vmcs->make_current();

    mword host_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_LD_ADDR);
    Msr_area *cur_host_msr_area = 
            reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(host_msr_area_phys));
    memcpy(host_msr_area2, cur_host_msr_area, PAGE_SIZE);
    memcpy(cur_host_msr_area, host_msr_area1, PAGE_SIZE);

    mword guest_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_ST_ADDR);
    Msr_area *cur_guest_msr_area = 
            reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(guest_msr_area_phys));
    memcpy(guest_msr_area2, cur_guest_msr_area, PAGE_SIZE);
    memcpy(cur_guest_msr_area, guest_msr_area1, PAGE_SIZE);

    mword virtual_apic_page_phys = Vmcs::read(Vmcs::APIC_VIRT_ADDR);
    Virtual_apic_page *cur_virtual_apic_page =
            reinterpret_cast<Virtual_apic_page*> (Buddy::phys_to_ptr(virtual_apic_page_phys));
    memcpy(virtual_apic_page2, cur_virtual_apic_page, PAGE_SIZE);
    memcpy(cur_virtual_apic_page, virtual_apic_page1, PAGE_SIZE);
}

void Ec::vmx_restore_state2() {
    assert(Pe::run_number == 0);
    Pe::guest_rip[1] = Vmcs::read(Vmcs::GUEST_RIP);        
    Pe::guest_rsp[1] = Vmcs::read(Vmcs::GUEST_RSP);        
    regs.vmcs->clear();
    memcpy(Vmcs::vmcs1, regs.vmcs, Vmcs::basic.size);
    memcpy(regs.vmcs, Vmcs::vmcs2, Vmcs::basic.size);
    regs.vmcs->make_current();

    mword host_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_LD_ADDR);
    Msr_area *cur_host_msr_area = 
            reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(host_msr_area_phys));
    memcpy(host_msr_area1, cur_host_msr_area, PAGE_SIZE);
    memcpy(cur_host_msr_area, host_msr_area2, PAGE_SIZE);

    mword guest_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_ST_ADDR);
    Msr_area *cur_guest_msr_area = 
            reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(guest_msr_area_phys));
    memcpy(guest_msr_area1, cur_guest_msr_area, PAGE_SIZE);
    memcpy(cur_guest_msr_area, guest_msr_area2, PAGE_SIZE);

    mword virtual_apic_page_phys = Vmcs::read(Vmcs::APIC_VIRT_ADDR);
    Virtual_apic_page *cur_virtual_apic_page =
            reinterpret_cast<Virtual_apic_page*> (Buddy::phys_to_ptr(virtual_apic_page_phys));
    memcpy(virtual_apic_page1, cur_virtual_apic_page, PAGE_SIZE);
    memcpy(cur_virtual_apic_page, virtual_apic_page2, PAGE_SIZE);
}

void Ec::vmx_rollback() {
    regs.vmcs->clear();
    memcpy(regs.vmcs, Vmcs::vmcs0, Vmcs::basic.size);
    regs.vmcs->make_current();

    mword host_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_LD_ADDR);
    Msr_area *cur_host_msr_area = 
            reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(host_msr_area_phys));
    memcpy(cur_host_msr_area, host_msr_area0, PAGE_SIZE);

    mword guest_msr_area_phys = Vmcs::read(Vmcs::EXI_MSR_ST_ADDR);
    Msr_area *cur_guest_msr_area = 
            reinterpret_cast<Msr_area*> (Buddy::phys_to_ptr(guest_msr_area_phys));
    memcpy(cur_guest_msr_area, guest_msr_area0, PAGE_SIZE);

    mword virtual_apic_page_phys = Vmcs::read(Vmcs::APIC_VIRT_ADDR);
    Virtual_apic_page *cur_virtual_apic_page =
            reinterpret_cast<Virtual_apic_page*> (Buddy::phys_to_ptr(virtual_apic_page_phys));
    memcpy(cur_virtual_apic_page, virtual_apic_page0, PAGE_SIZE);
}

void Ec::save_vm_stack() {
    current->regs.vtlb->reserve_stack(&current->cow_fields);
}

mword Ec::get_regsRIP() {
    return utcb ? regs.REG(ip) : Vmcs::read(Vmcs::GUEST_RIP);
}

mword Ec::get_regsRCX() {
    return regs.REG(cx);
}

mword Ec::get_regsES() {
    if(utcb) {
        return regs.es;
    } else {
        return Vmcs::read(Vmcs::GUEST_SEL_ES);
    }
}

mword Ec::get_regsSS() {
    if(utcb) {
        return regs.ss;
    } else {
        return Vmcs::read(Vmcs::GUEST_SEL_SS);
    }
}

void Ec::Setx86DebugReg(mword addr, int dr) {
    mword dr7 = 0; // or 0x4aa or 0x7aa or 0x6aa 
    switch (dr) {
        default:
        case 0:
            asm volatile ("mov %0, %%dr0"::"r"(addr));
            dr7 = 0x000D07aa;
            break;
        case 1:
            asm volatile ("mov %0, %%dr1" : : "r"(addr));
            dr7 = 0x00D00004;
            break;
        case 2:
            asm volatile ("mov %0, %%dr2"::"r"(addr));
            dr7 = 0x0D000010;
            break;
        case 3:
            dr7 = 0xD0000040;
            asm volatile ("mov %0, %%dr3"::"r"(addr));
    }
    asm volatile ("mov %0, %%dr7"::"r"(dr7));
    return;
}

void Ec::debug_func(const char* source) {
    mword rip;
    if (strcmp(source, "Ireting"))
        rip = current->regs.REG(cx);
    else
        rip = current->regs.REG(ip);
    Console::print("%s PD: %s EC %s EIP %lx rcx %lx counter %llx exc %lld", source, 
            Pd::current->get_name(), current->get_name(), rip, current->regs.REG(cx), 
            Lapic::read_instCounter(), exc_counter);
}

void Ec::debug_print(const char* source) {
    if (current->pd->is_debug() || current->debug)
        debug_func(source);
    return;

}

ALWAYS_INLINE
static inline mword read_ebp() {
    mword ebp;
    asm volatile("mov " EXPAND(PREG(bp)) ",%0" : "=r" (ebp));
    return ebp;
}

/**
 * Only valable on 32 bits
 */
void Ec::backtrace(int depth) {
    mword ebp = read_ebp(), eip = 0;
    mword* ebpp;
    Console::print("Stack backtrace:");
    int tour = 0;
    while (ebp && (tour < depth)) {//if ebp is 0, we are back at the first caller
        ebpp = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, 
                Ec::current->getPd()->Space_mem::loc[Cpu::id], ebp, 3, sizeof(mword)));
        assert(ebpp);
        eip = *(ebpp + 1);
        char args[60];
        int argno = 0;
        for (; argno < 5; argno++) {
            String::print(args, "%lx ", *(ebpp + 2 + argno));
        }

        Console::print("ebp %lx eip %lx args %s (ebp) %lx", ebp, eip, args, *ebpp);
        ebp = *ebpp;
        tour++;
    }
    return;
}
/**
 * 
 * @param reg_number
 * @param state
 * @return 
 */
mword Ec::get_reg(Register reg, int state) {
    //TODO :: Handle state0, state1 and state2 cases for VCPU
    Cpu_regs r;
    switch (state) {
        case 0:
            r = regs_0;
            break;
        case 1:
            r = regs_1;
            break;
        case 2:
            r = regs_2;
            break;
        case 3:
            r = regs;
            break;
        default:
            Console::panic("INVALID STATE");
    }
    switch (reg) {
        case NOREG:
            Console::panic("INVALID REGISTRY %d", reg);
        case RAX:
            return r.REG(ax);
        case RBX:
            return r.REG(bx);
        case RCX:
            return r.REG(cx);
        case RDX:
            return r.REG(dx);
        case RBP:
            return r.REG(bp);
        case RDI:
            return r.REG(di);
        case RSI:
            return r.REG(si);
        case R8:
            return r.r8;
        case R9:
            return r.r9;
        case R10:
            return r.r10;
        case R11:
            return r.r11;
        case R12:
            return r.r12;
        case R13:
            return r.r13;
        case R14:
            return r.r14;
        case R15:
            return r.r15;
        case RIP:
            return utcb ? r.REG(ip) : state ? (state == 1 ? Pe::guest_rip[1] : (state == 2 ? Pe::guest_rip[2] : Vmcs::read(Vmcs::GUEST_RIP))) : Pe::guest_rip[0];
        case RSP:
            return utcb ? r.REG(sp) : state ? (state == 1 ? Pe::guest_rsp[1] : (state == 2 ? Pe::guest_rsp[2] : Vmcs::read(Vmcs::GUEST_RSP))) : Pe::guest_rsp[0];
        case RFLAG:
            return utcb ? r.REG(fl) : state ? (state == 1 ? Pe::guest_rflags[1] : (state == 2 ? Pe::guest_rflags[2] : Vmcs::read(Vmcs::GUEST_RFLAGS))) : Pe::guest_rflags[0];
        case GUEST_RIP:
            return utcb ? 0 : state ? (state == 1 ? Pe::guest_rip[1] : (state == 2 ? Pe::guest_rip[2] : Vmcs::read(Vmcs::GUEST_RIP))) : Pe::guest_rip[0];
        case GUEST_RSP:
            return utcb ? 0 : state ? (state == 1 ? Pe::guest_rsp[1] : (state == 2 ? Pe::guest_rsp[2] : Vmcs::read(Vmcs::GUEST_RSP))) : Pe::guest_rsp[0];
        case GUEST_RFLAG:
            return utcb ? 0 : state ? (state == 1 ? Pe::guest_rflags[1] : (state == 2 ? Pe::guest_rflags[2] : Vmcs::read(Vmcs::GUEST_RFLAGS))) : Pe::guest_rflags[0];
        case FPU_DATA:
            return FPU_DATA;
        case FPU_STATE:
            return FPU_STATE;
        default:
            Console::panic("INVALID REGISTRY %d", reg);
    }
}

Ec::Register Ec::compare_regs(PE_stopby reason) {
    if (regs.r15 != (Pe::inState1 ? regs_2.r15 : regs_1.r15)) {
        return R15;
    }
    if (regs.r14 != (Pe::inState1 ? regs_2.r14 : regs_1.r14)) {
        return R14;
    }
    if (regs.r13 != (Pe::inState1 ? regs_2.r13 : regs_1.r13)) {
        return R13;
    }
    if (regs.r12 != (Pe::inState1 ? regs_2.r12 : regs_1.r12)) {
        return R12;
    }
    if (regs.r11 != (Pe::inState1 ? regs_2.r11 : regs_1.r11)) {
        // resume flag  or trap flag may be set if reason is step-mode
        // but it is unclear why. Must be fixed later
        if (((regs.r11 | 1u << 16) == (Pe::inState1 ? regs_2.r11 : regs_1.r11)) || 
                (regs.r11 == ((Pe::inState1 ? regs_2.r11 : regs_1.r11) | 1u << 8))) {
            // it's ok, just continue;
        } else {
            return R11;
        }
    }
    if (regs.r10 != (Pe::inState1 ? regs_2.r10 : regs_1.r10)) {
        return R10;
    }
    if (regs.r9 != (Pe::inState1 ? regs_2.r9 : regs_1.r9)) {
        return R9;
    }
    if (regs.r8 != (Pe::inState1 ? regs_2.r8 : regs_1.r8)) {
        return R8;
    }
    if (regs.REG(si) != (Pe::inState1 ? regs_2.REG(si) : regs_1.REG(si))) {
        return RSI;
    }
    if (regs.REG(di) != (Pe::inState1 ? regs_2.REG(di) : regs_1.REG(di))) {
        return RDI;
    }
    if (regs.REG(bp) != (Pe::inState1 ? regs_2.REG(bp) : regs_1.REG(bp))) {
        return RBP;
    }
    if (regs.REG(dx) != (Pe::inState1 ? regs_2.REG(dx) : regs_1.REG(dx))) {
        return RDX;
    }
    if (regs.REG(cx) != (Pe::inState1 ? regs_2.REG(cx) : regs_1.REG(cx))) {
        return RCX;
    }
    if (regs.REG(bx) != (Pe::inState1 ? regs_2.REG(bx) : regs_1.REG(bx))) {
        return RBX;
    }
    if (regs.REG(ax) != (Pe::inState1 ? regs_2.REG(ax) : regs_1.REG(ax))) {
        return RAX;
    }
    if(reason) {
        if (fpu && fpu->data_check())
            return FPU_DATA;
        if (Fpu::dwc_check())
            return FPU_STATE;
    }
    // following checks are not valid if reason is Sysenter
    if (reason == PES_SYS_ENTER) 
        return NOREG;        
    if(utcb){
        if (regs.REG(ip) != (Pe::inState1 ? regs_2.REG(ip) : regs_1.REG(ip))) {
            return RIP;
        }
        if (regs.REG(sp) != (Pe::inState1 ? regs_2.REG(sp) : regs_1.REG(sp))) {
            return RSP;
        }
//        if ((regs_2.REG(fl) != regs_1.REG(fl)) && ((regs_2.REG(fl) | (1u << 16)) != regs_1.REG(fl))) {
//            resume flag may be set if reason is step-mode but it is curious why this flag is set in
//            regs_1 and not in regs_2. The contrary would be understandable. Must be fixed later
//            return 18;
//        }        
    } else {
//        if(memcmp(regs.vmcs, Pe::inState1 ? Vmcs::vmcs2 : Vmcs::vmcs1, Vmcs::basic.size))
        if(Vmcs::read(Vmcs::GUEST_RIP) != (Pe::inState1 ? Pe::guest_rip[2] : Pe::guest_rip[1]))
            return GUEST_RIP;
        if(Vmcs::read(Vmcs::GUEST_RSP) != (Pe::inState1 ? Pe::guest_rsp[2] : Pe::guest_rsp[1]))
            return GUEST_RSP;
//        if(Vmcs::read(Vmcs::GUEST_RFLAGS) != (Pe::inState1 ? Pe::vmcsRFLAG_2 : Pe::vmcsRFLG_1))
//            return GUEST_RFLAG;
    }
    return NOREG;
}

void Ec::count_interrupt(Exc_regs *r){
    mword vector = r->vec;
    switch (vector) {
        case 0 ... VEC_GSI - 1:
            Counter::exc[vector][Pe::run_number]++;
            break;
        case VEC_GSI ... VEC_LVT - 1:
            Counter::gsi[vector - VEC_GSI][Pe::run_number]++;
            break;
        case VEC_LVT ... VEC_MSI - 1:
            Counter::lvt[vector - VEC_LVT][Pe::run_number]++;
            break;
        case VEC_MSI ... VEC_IPI - 1:
            Counter::msi[vector - VEC_MSI][Pe::run_number]++;
            break;
        case VEC_IPI ... VEC_MAX - 1:
            Counter::ipi[vector - VEC_IPI][Pe::run_number]++;
            break;
    }
    uint8 *ptr = reinterpret_cast<uint8 *> (Hpt::remap_cow(Pd::kern.quota, 
        Pd::current->Space_mem::loc[Cpu::id], r->REG(ip)-1, 3, 2));
    if(!ptr)
        return;
    ptr += 1;
// last_rip-1 : + 1 
    if (*ptr == 0xf3 || *ptr == 0xf2) { // rep prefix instruction
        Counter::rep_prefix[Pe::run_number]++;
//            exc_counter--;
    }
    if(*ptr == 0xf4) { // halt instruction
        Counter::hlt_instr[Pe::run_number]++;
//            exc_counter--;
    } else if(*(ptr - 1) == 0xf4) {
        Counter::hlt_instr[Pe::run_number]++;
//                exc_counter--;
    }
}
/**
 * 
 * @param from
 */
void Ec::check_instr_number_equals(int from){
    uint64 nb_run1, nb_run2;
    size_t buff_length = 8;
    char instr_number_comp[buff_length+1] = "Inf";
    if(distance_instruction <= 2) {
        if(run_switched){
            nb_run1 = first_run_instr_number + nb_inst_single_step; 
            nb_run2 = second_run_instr_number;
            run_switched = false;
            copy_string(instr_number_comp, "Equ sup", buff_length);
        } else{
            nb_run1 = first_run_instr_number; 
            nb_run2 = second_run_instr_number + nb_inst_single_step;
            copy_string(instr_number_comp, "Equ inf", buff_length);            
        }
    } else if(first_run_instr_number > second_run_instr_number){
        nb_run1 = first_run_instr_number; nb_run2 = second_run_instr_number + nb_inst_single_step;
    } else {
        nb_run1 = first_run_instr_number + nb_inst_single_step; nb_run2 = second_run_instr_number;        
        copy_string(instr_number_comp, "Sup", buff_length);
    }
    char to_print[200];
//    Log::counter(to_print);
    long nb_run_diff = nb_run1 < nb_run2 ? nb_run2 - nb_run1 : -(nb_run1 - nb_run2);
    if(nb_run_diff != 0){
        Console::print("%s %d: ec %s pd %s nb_run1 %llu nb_run2 %llu nb_run_diff %ld counter1 %llu "
        "counter2 %llu %s ss %llu ",
        instr_number_comp, from, current->get_name(), current->getPd()->get_name(), nb_run1, 
                nb_run2,  nb_run_diff, counter1, counter2, to_print, nb_inst_single_step);
    }else{
        Console::print("%s %d: ec %s pd %s counter1 %llu counter2 %llu %s ss %llu ",
        instr_number_comp, from, current->get_name(), current->getPd()->get_name(), counter1,
                counter2, to_print, nb_inst_single_step);
    }
}

void Ec::step_debug(){
    step_reason = SR_GP;
    current->regs.REG(fl) |= Cpu::EFL_TF;
}

size_t Ec::lookup(uint64 v, Paddr &p, mword &a){
    if(utcb) {
        return Pd::current->Space_mem::loc[Cpu::id].lookup(v, p, a);
    } else {
        if(regs.nst_on) {
//            Paddr h_cr3;
//            mword a_cr3;
//            mword guest_cr3 = Vmcs::read(Vmcs::GUEST_CR3);
//            Pd::current->ept.lookup(guest_cr3 +, p, a);
//            Hptp hpt(h_cr3);
//            hpt.lookup(p+v, p, a);
            Ept* ept;
            /* We use cow_walk instead of Pte lookup because pte lookup behaves 
             weirdly due to it s = --- + order() */
            return Pd::current->ept.cow_walk(v, p, a, ept);
        } else {
            return vtlb_lookup(v, p, a); 
        }
    }
}

size_t Ec::vtlb_lookup(uint64 v, Paddr &p, mword &a){
    Vtlb* tlb = nullptr;
    return regs.vtlb->lookup(v, p, a, tlb);    
}

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

#pragma once

#include "counter.hpp"
#include "fpu.hpp"
#include "mtd.hpp"
#include "pd.hpp"
#include "queue.hpp"
#include "regs.hpp"
#include "sc.hpp"
#include "timeout_hypercall.hpp"
#include "tss.hpp"
#include "si.hpp"

#include "stdio.hpp"

class Utcb;
class Sm;
class Pt;

class Ec : public Kobject, public Refcount, public Queue<Sc> {
    friend class Queue<Ec>;
    friend class Sc;

private:
    void (*cont)() ALIGNED(16);
    Cpu_regs regs;
    static Cpu_regs regs_0, regs_1;
    Ec * rcap;
    Utcb * utcb;
    Refptr<Pd> pd;
    Ec * partner;
    Ec * prev;
    Ec * next;
    Fpu * fpu;
    Vmcb *vmcb_backup, *vmcb1, *vmcb2;
    Vmcs *vmcs_backup, *vmcs1, *vmcs2;
    char name[str_max_length];
    
    union {

        struct {
            uint16 cpu;
            uint16 glb;
        };
        uint32 xcpu;
    };
    unsigned const evt;
    Timeout_hypercall timeout;
    mword user_utcb;

    Sm * xcpu_sm;
    Pt * pt_oom;

    static Slab_cache cache;

    REGPARM(1)
    static void handle_exc(Exc_regs *) asm ("exc_handler");

    NORETURN
    static void handle_vmx() asm ("vmx_handler");

    NORETURN
    static void handle_svm() asm ("svm_handler");

    NORETURN
    static void handle_tss() asm ("tss_handler");

    static void handle_exc_nm();
    static bool handle_exc_ts(Exc_regs *);
    static bool handle_exc_gp(Exc_regs *);
    static bool handle_exc_pf(Exc_regs *);

    static inline uint8 ifetch(mword);

    NORETURN
    static inline void svm_exception(mword);

    NORETURN
    static inline void svm_cr();

    NORETURN
    static inline void svm_invlpg();

    NORETURN
    static inline void vmx_exception();

    NORETURN
    static inline void vmx_extint();

    NORETURN
    static inline void vmx_invlpg();

    NORETURN
    static inline void vmx_cr();

    static bool fixup(mword &);

    NOINLINE
    static void handle_hazard(mword, void (*)());

    static void pre_free(Rcu_elem * a) {
        Ec * e = static_cast<Ec *> (a);

        assert(e);

        // remove mapping in page table
        if (e->user_utcb) {
            e->pd->remove_utcb(e->user_utcb);
            e->pd->Space_mem::insert(e->pd->quota, e->user_utcb, 0, 0, 0);
            e->user_utcb = 0;
        }

        // XXX If e is on another CPU and there the fpowner - this check will fail.
        // XXX For now the destruction is delayed until somebody else grabs the FPU.
        if (fpowner == e) {
            assert(Sc::current->cpu == e->cpu);

            bool zero = fpowner->del_ref();
            assert(!zero);

            fpowner = nullptr;
            Cpu::hazard |= HZD_FPU;
        }
    }

    static void free(Rcu_elem * a) {
        Ec * e = static_cast<Ec *> (a);

        if (!e->utcb && !e->xcpu_sm) {
            trace(0, "leaking memory - vCPU EC memory re-usage not supported");
            return;
        }

        if (e->del_ref()) {
            assert(e != Ec::current);
            delete e;
        }
    }

    ALWAYS_INLINE
    inline Sys_regs *sys_regs() {
        return &regs;
    }

    ALWAYS_INLINE
    inline Exc_regs *exc_regs() {
        return &regs;
    }

    ALWAYS_INLINE
    inline void set_partner(Ec *p) {
        partner = p;
        partner->add_ref();
        partner->rcap = this;
        partner->rcap->add_ref();
        Sc::ctr_link++;
    }

    ALWAYS_INLINE
    inline unsigned clr_partner() {
        assert(partner == current);
        if (partner->rcap) {
            partner->rcap->del_ref();
            partner->rcap = nullptr;
        }
        partner->del_ref();
        partner = nullptr;
        return Sc::ctr_link--;
    }

    ALWAYS_INLINE
    inline void redirect_to_iret() {
        regs.REG(sp) = regs.ARG_SP;
        regs.REG(ip) = regs.ARG_IP;
    }

    void load_fpu();
    void save_fpu();

    void transfer_fpu(Ec *);

public:
    static Ec *current CPULOCAL_HOT;
    static Ec *fpowner CPULOCAL;
    
    static Fpu *fpu_0, *fpu_1, *fpu_2;
    int previous_reason = 0, nb_extint = 0;
    uint64 tour = 0;
    mword io_addr, io_attr;
    Paddr io_phys;
    enum Launch_type {
        UNLAUNCHED = 0,
        SYSEXIT = 1,
        IRET = 2,
        VMRESUME = 3,
        VMRUN = 4,
    };

    enum Step_reason {
        NIL = 0,
        MMIO = 1,
        PIO = 2,
        RDTSC = 3,
        TIMER = 4,
        PMI = 5,
    };
    
    static unsigned step_nb, affich_num, affich_mod;
    static mword prev_rip, last_rip, last_rcx, end_rip, end_rcx;
    static uint64 begin_time, end_time, runtime1, runtime2, total_runtime, step_debug_time, static_tour, counter1, counter2, nbInstr_to_execute, exc_counter, exc_counter1, exc_counter2, gsi_counter1, lvt_counter1, msi_counter1, ipi_counter1,
            gsi_counter2, lvt_counter2, msi_counter2, ipi_counter2, debug_compteur;
    static uint8 run_number, launch_state, step_reason;
    static bool ec_debug, debug, hardening_started, in_rep_instruction, not_nul_cowlist;
    
    Ec(Pd *, void (*)(), unsigned, char* const nm = const_cast<char* const> ("Unknown"));
    Ec(Pd *, mword, Pd *, void (*)(), unsigned, unsigned, mword, mword, Pt *, char* const nm = const_cast<char* const> ("Unknown"));
    Ec(Pd *, Pd *, void (*f)(), unsigned, Ec *, char* const nm = const_cast<char* const> ("Unknown"));

    ~Ec();

    ALWAYS_INLINE
    inline void add_tsc_offset(uint64 tsc) {
        regs.add_tsc_offset(tsc);
    }
    
    ALWAYS_INLINE
    inline bool blocked() const {
        return next || !cont;
    }

    ALWAYS_INLINE
    inline void set_timeout(uint64 t, Sm *s) {
        if (EXPECT_FALSE(t))
            timeout.enqueue(t, s);
    }

    ALWAYS_INLINE
    inline void clr_timeout() {
        if (EXPECT_FALSE(timeout.active()))
            timeout.dequeue();
    }

    ALWAYS_INLINE
    inline void set_si_regs(mword sig, mword cnt) {
        regs.ARG_2 = sig;
        regs.ARG_3 = cnt;
    }

    ALWAYS_INLINE NORETURN
    inline void make_current() {
        if (EXPECT_FALSE(current->del_ref())) {
            delete current;
        }

        current = this;

        current->add_ref();

        Tss::run.sp0 = reinterpret_cast<mword> (exc_regs() + 1);

        pd->make_current();

        asm volatile ("mov %0," EXPAND(PREG(sp);) "jmp *%1" : : "g" (CPU_LOCAL_STCK + PAGE_SIZE), "q" (cont) : "memory");
        UNREACHED;
    }

    ALWAYS_INLINE
    static inline Ec *remote(unsigned c) {
        return *reinterpret_cast<volatile typeof current *> (reinterpret_cast<mword> (&current) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    }

    NOINLINE
    void help(void (*c)()) {
        if (EXPECT_TRUE(cont != dead)) {

            Counter::print<1, 16> (++Counter::helping, Console_vga::COLOR_LIGHT_WHITE, SPN_HLP);
            current->cont = c;

            if (EXPECT_TRUE(++Sc::ctr_loop < 100))
                activate();

            die("Livelock");
        }
    }

    NOINLINE
    void block_sc() {
        {
            Lock_guard <Spinlock> guard(lock);

            if (!blocked())
                return;

            Sc::current->add_ref();
            enqueue(Sc::current);
        }

        if (is_idle())
            Sc::schedule(true);
    }

    ALWAYS_INLINE
    inline void release(void (*c)()) {
        if (c)
            cont = c;

        Lock_guard <Spinlock> guard(lock);

        for (Sc *s; dequeue(s = head());) {
            if (EXPECT_FALSE(s->del_ref()) && (this == s->ec)) {
                delete s;
                continue;
            }
            s->remote_enqueue();
        }
    }

    HOT NORETURN
    static void ret_user_sysexit();

    HOT NORETURN
    static void ret_user_iret() asm ("ret_user_iret");

    HOT
    static void chk_kern_preempt() asm ("chk_kern_preempt");

    NORETURN
    static void ret_user_vmresume();

    NORETURN
    static void ret_user_vmrun();

    NORETURN
    static void ret_xcpu_reply();

    template <void (*)() >
    NORETURN
    static void ret_xcpu_reply_oom();

    template <Sys_regs::Status S, bool T = false >

    NOINLINE NORETURN
    static void sys_finish();

    NORETURN
    void activate();

    template <void (*)() >
    NORETURN
    static void send_msg();

    HOT NORETURN
    static void recv_kern();

    HOT NORETURN
    static void recv_user();

    HOT NORETURN
    static void reply(void (*)() = nullptr, Sm * = nullptr);

    HOT NORETURN
    static void sys_call();

    HOT NORETURN
    static void sys_reply();

    NORETURN
    static void sys_create_pd();

    NORETURN
    static void sys_create_ec();

    NORETURN
    static void sys_create_sc();

    NORETURN
    static void sys_create_pt();

    NORETURN
    static void sys_create_sm();

    NORETURN
    static void sys_revoke();

    NORETURN
    static void sys_lookup();

    NORETURN
    static void sys_ec_ctrl();

    NORETURN
    static void sys_sc_ctrl();

    NORETURN
    static void sys_pt_ctrl();

    NORETURN
    static void sys_sm_ctrl();

    NORETURN
    static void sys_pd_ctrl();

    NORETURN
    static void sys_assign_pci();

    NORETURN
    static void sys_assign_gsi();

    NORETURN
    static void sys_xcpu_call();

    template <void (*)() >
    NORETURN
    static void sys_xcpu_call_oom();

    NORETURN
    static void idle();

    NORETURN
    static void xcpu_return();

    template <void (*)() >
    NORETURN
    static void oom_xcpu_return();

    NORETURN
    static void root_invoke();

    template <bool>
    static void delegate();

    NORETURN
    static void dead() {
        die("IPC Abort");
    }

    NORETURN
    static void die(char const *, Exc_regs * = &current->regs);

    static void idl_handler();

    ALWAYS_INLINE
    static inline void *operator new (size_t, Quota &quota) {
        return cache.alloc(quota);
    }

    ALWAYS_INLINE
    static inline void operator delete (void *ptr) {
        cache.free(ptr, static_cast<Ec *> (ptr)->pd->quota);
    }

    template <void (*)() >
    NORETURN
    void oom_xcpu(Pt *, mword, mword);

    NORETURN
    void oom_delegate(Ec *, Ec *, Ec *, bool, bool);

    NORETURN
    void oom_call(Pt *, mword, mword, void (*)(), void (*)());

    NORETURN
    void oom_call_cpu(Pt *, mword, void (*)(), void (*)());

    template <void(*C)()>
    static void check(mword, bool = true);

    REGPARM(1)
    static void check_memory(int pmi = 0) asm ("memory_checker");
    REGPARM(1)
    static void incr_count(unsigned) asm ("incr_count");
    REGPARM(1)
    static void saveRegs(Exc_regs *) asm ("saveRegs");
    
    bool is_temporal_exc();
    bool is_io_exc(mword = 0);

    void resolve_PIO_execption();
    
    void enable_step_debug(Step_reason raison = NIL, mword fault_addr = 0, Paddr fault_phys = 0, mword fault_attr = 0); 
    void disable_step_debug();
       
    void save_state() {
        regs_0 = regs;
        if(fpu)
            fpu->dwc_save();
    }

    void svm_save_state() {
        save_state();
        memcpy(vmcb_backup, regs.vmcb, PAGE_SIZE);
    }

    void vmx_save_state() {
        save_state();
        memcpy(vmcs_backup, regs.vmcs, PAGE_SIZE);
    }

    bool two_run_ok() {
        return run_number == 2;
    }

    static bool one_run_ok() {
        return run_number == 1;
    }

    static bool is_idle() {
        return launch_state == UNLAUNCHED && step_reason == NIL;
    }

    void set_env(uint64 t) {
        // set EAX and EDX to the correct value
        // update EIP
        regs.REG(ax) = static_cast<mword> (t);
        regs.REG(dx) = static_cast<mword> (t >> 32);
        //        Console::print("eax %08lx  edx %08lx  t %llx", regs.eax, regs.edx, t);
        regs.REG(ip) += 0x2; // because rdtsc is a 2 bytes long instruction
    }

    Pd* getPd() {
        return pd;
    }
    
    char *get_name() {
        return name;
    }

    void restore_state();
    void rollback();
    mword get_regsRIP();
    mword get_regsRCX();
    int compare_regs(int);
    
    static bool activate_timer();
    static void clear_instCounter();
    static void reset_counter();
    static void check_exit();
    static void print_stat(bool);
    static void reset_time();
    static void reset_all();
};

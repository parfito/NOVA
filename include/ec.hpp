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
#include "cmdline.hpp"

#include "stdio.hpp"
#include "vmx.hpp"
#include "pe_state.hpp"
#include "utcb.hpp"

class Utcb;
class Sm;
class Pt;

class Ec : public Kobject, public Refcount, public Queue<Sc> {
    friend class Queue<Ec>;
    friend class Sc;
    friend class Pt;
private:
    void (*cont)() ALIGNED(16);
    Cpu_regs regs{};
    Ec * rcap{ nullptr};
    Utcb * utcb{ nullptr};
    Refptr<Pd> pd;
    Ec * partner;
    Ec * prev;
    Ec * next;
    Fpu * fpu;

    union {

        struct {
            uint16 cpu;
            uint16 glb;
        };
        uint32 xcpu;
    };

    static Cpu_regs regs_0, regs_1, regs_2;
    static Msr_area *host_msr_area0, *guest_msr_area0, *host_msr_area1, *guest_msr_area1,
    *host_msr_area2, *guest_msr_area2;
    static Virtual_apic_page *virtual_apic_page0, *virtual_apic_page1, *virtual_apic_page2;

    char name[MAX_STR_LENGTH];

    unsigned const evt;
    Timeout_hypercall timeout;
    mword user_utcb;

    Sm * xcpu_sm;
    Pt * pt_oom;

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
    static void handle_exc_db(Exc_regs *);

    static inline uint8 ifetch(mword);

    NORETURN
    static inline void svm_exception(mword);

    NORETURN
    static inline void svm_cr(mword);

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
            if (!Cmdline::fpu_eager) {
                assert(!(Cpu::hazard & HZD_FPU));
                Fpu::disable();
                assert(!(Cpu::hazard & HZD_FPU));
            }
        }
    }

    ALWAYS_INLINE
    static inline void destroy(Ec *obj, Pd &pd) {
        obj->~Ec();
        pd.ec_cache.free(obj, pd.quota);
    }

    ALWAYS_INLINE
    inline bool idle_ec() {
        return !utcb && !regs.vmcb && !regs.vmcs && !regs.vtlb;
    }

    static void free(Rcu_elem * a) {
        Ec * e = static_cast<Ec *> (a);

        if (e->regs.vtlb) {
            trace(0, "leaking memory - vCPU EC memory re-usage not supported");
            return;
        }

        if (e->del_ref()) {
            assert(e != Ec::current);
            Ec::destroy(e, *e->pd);
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
        bool ok = partner->add_ref();
        assert(ok);
        partner->rcap = this;
        ok = partner->rcap->add_ref();
        assert(ok);
        Sc::ctr_link++;
    }

    ALWAYS_INLINE
    inline unsigned clr_partner() {
        assert(partner == current);
        if (partner->rcap) {
            bool last = partner->rcap->del_ref();
            assert(!last);
            partner->rcap = nullptr;
        }
        bool last = partner->del_ref();
        assert(!last);
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

    Ec(const Ec&);
    Ec &operator=(Ec const &);

public:
    static Ec *current CPULOCAL_HOT;
    static Ec *fpowner CPULOCAL;

    static Fpu *fpu_0, *fpu_1, *fpu_2;
    int previous_reason = 0, nb_extint = 0;
    mword io_addr = {}, io_attr = {};
    Paddr io_phys = {};

    bool debug = false;

    enum Launch_type {
        UNLAUNCHED = 0,
        SYSEXIT = 1,
        IRET = 2,
        VMRESUME = 3,
        VMRUN = 4,
        EXT_INT = 5,
    };

    enum Step_reason {
        SR_NIL = 0,
        SR_MMIO = 1,
        SR_PIO = 2,
        SR_RDTSC = 3,
        SR_PMI = 4,
        SR_GP = 5,
        SR_DBG = 6,
        SR_EQU = 7,
        SR_VMIO = 8,
    };

    enum PE_stopby {
        PES_DEFAULT = 0,
        PES_PMI = 1,
        PES_PAGE_FAULT = 2,
        PES_SYS_ENTER = 3,
        PES_VMX_EXIT = 4,
        PES_INVALID_TSS = 5,
        PES_GP_FAULT = 6,
        PES_DEV_NOT_AVAIL = 7,
        PES_SEND_MSG = 8,
        PES_MMIO = 9,
        PES_SINGLE_STEP = 10,
        PES_VMX_SEND_MSG = 11,
        PES_VMX_EXT_INT = 12,
        PES_GSI = 13,
        PES_MSI = 14,
        PES_LVT = 15,
        PES_ALIGNEMENT_CHECK = 16,
        PES_MACHINE_CHECK = 17,
        PES_VMX_INVLPG = 18,
        PES_VMX_PAGE_FAULT = 19,
        PES_VMX_EPT_VIOL = 20,
        PES_VMX_CR = 21,
        PES_VMX_EXC = 22,
        PES_VMX_RDTSC = 23,
        PES_VMX_RDTSCP = 24,
        PES_VMX_IO = 25,
        PES_COW_IN_STACK = 26,
    };

    enum Debug_type {
        DT_NULL = 0,
        CMP_TWO_RUN = 1,
        STORE_RUN_STATE = 2,
    };
    static mword prev_rip, last_rip, last_rcx, last_rsp, end_rip, end_rcx, instruction_value, 
    tscp_rcx1, tscp_rcx2;
    static uint64 counter1, counter2, exc_counter, exc_counter1, exc_counter2, debug_compteur, 
    count_je, nbInstr_to_execute, tsc1, tsc2, nb_inst_single_step, second_run_instr_number, 
    first_run_instr_number, distance_instruction;
    static uint8 run_number, launch_state, step_reason, debug_nb, debug_type, 
    replaced_int3_instruction, replaced_int3_instruction2;
    static bool hardening_started, in_rep_instruction, not_nul_cowlist, 
    no_further_check, first_run_advanced, keep_cow;
    static int prev_reason, previous_ret, nb_try, reg_diff;
    static const char* regs_name_table[];

    Ec(Pd *, void (*)(), unsigned, char const *nm = "Unknown");
    Ec(Pd *, mword, Pd *, void (*)(), unsigned, unsigned, mword, mword, Pt *, 
    char const *nm = "Unknown");
    Ec(Pd *, Pd *, void (*f)(), unsigned, Ec *, char const *nm = "Unknown");

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
        if (EXPECT_FALSE(current->del_rcu()))
            Rcu::call(current);

        if (Cmdline::fpu_eager) {
            if (!idle_ec()) {
                if (!current->utcb && !this->utcb)
                    assert(!(Cpu::hazard & HZD_FPU));

                transfer_fpu(this);
                assert(fpowner == this);
            }

            Cpu::hazard &= ~HZD_FPU;
        }

        current = this;

        bool ok = current->add_ref();
        assert(ok);

        Tss::run.sp0 = reinterpret_cast<mword> (exc_regs() + 1);

        pd->make_current();

        asm volatile ("mov %0," EXPAND(PREG(sp);) "jmp *%1" : : "g" (CPU_LOCAL_STCK + PAGE_SIZE), 
        "q" (cont) : "memory");
        UNREACHED;
    }

    ALWAYS_INLINE
    static inline Ec *remote(unsigned c) {
        return *reinterpret_cast<volatile typeof current *> (reinterpret_cast<mword> (&current) - 
                CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
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

            bool ok = Sc::current->add_ref();
            assert(ok);

            Queue<Sc>::enqueue(Sc::current);
        }

        Sc::schedule(true);
    }

    ALWAYS_INLINE
    inline void release(void (*c)()) {
        if (c)
            cont = c;

        Lock_guard <Spinlock> guard(lock);

        for (Sc *s; Queue<Sc>::dequeue(s = Queue<Sc>::head());) {
            if (EXPECT_TRUE(!s->last_ref()) || s->ec->partner) {
                s->remote_enqueue(false);
                continue;
            }

            Rcu::call(s);
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
    static inline void *operator new (size_t, Pd &pd){return pd.ec_cache.alloc(pd.quota);}

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
    static void check_memory(PE_stopby = PES_DEFAULT) asm ("memory_checker");
    REGPARM(1)
    static void vm_check_memory(int = 0);
    REGPARM(1)
    static void save_regs(Exc_regs *) asm ("save_regs");

    bool is_temporal_exc();
    bool is_io_exc(mword = 0);

    void resolve_PIO_execption();

    void enable_step_debug(Step_reason raison = SR_NIL, mword fault_addr = 0, Paddr fault_phys = 0, 
    mword fault_attr = 0);
    void disable_step_debug();

    void save_state0();
    void restore_state0_data();

    void vmx_save_state();
    void vmx_restore_state();
    void vmx_restore_state1();
    void vmx_rollback();

    void run2_pmi_check(int);
    void run1_ext_int_check();

    bool two_run_ok() {
        return run_number == 2;
    }

    static bool one_run_ok() {
        return run_number == 1;
    }

    static bool is_idle() {
        return launch_state == UNLAUNCHED && step_reason == SR_NIL;
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

    void restore_state0();
    void restore_state1();
    void rollback();
    mword get_regsRIP();
    mword get_regsRCX();
    int compare_regs(int);
    void save_stack();
    void save_vm_stack();

    static void reset_counter();
    static void check_exit();
    static void print_stat(bool);
    static void reset_all();
    static void Setx86DebugReg(mword, int);
    static void debug_func(const char*);
    static void debug_print(const char*);
    static void debug_call(mword);
    static void backtrace(int depth = 6);

    static void enable_rdtsc();
    static void disable_rdtsc();
    static void enable_mtf();
    static void disable_mtf();
    NORETURN
    static void vmx_enable_single_step(Step_reason);
    static void vmx_emulate_rdtsc(bool);
    static void emulate_rdtsc2();
    NORETURN
    static void vmx_disable_single_step();
    NORETURN
    static void vmx_resolve_rdtsc(bool = false);
    NORETURN
    static void vmx_resolve_io();
    NORETURN
    static void vmx_emulate_io();

    bool is_virutalcpu() {
        return !utcb;
    }
    mword get_reg(int);
    int compare_regs_mute();
    bool single_step_finished();
    static void count_interrupt(mword);
    static void check_instr_number_equals(int);
    void start_debugging(Debug_type);
    static void debug_record_info();
    static void step_debug();
    static void prepare_checking();
    size_t vtlb_lookup(mword, Paddr &, mword&);
    //        size_t get_cow_number() { return cow_elts.size(); }
    //        bool is_cow_elts_empty() { return !cow_elts.head(); }
    //        void dump_regs();
    static bool is_debug_requested_from_user_space() { return Console::log_on || 
            current->pd->is_debug() || current->debug; }
private:
    static bool handle_deterministic_exception(mword, PE_stopby&);
};

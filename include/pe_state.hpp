/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pe_state.hpp
 * Author: parfait
 *
 * Created on 3 octobre 2018, 14:34
 */

#pragma once
#include "types.hpp"
#include "slab.hpp"
#include "compiler.hpp"
#include "queue.hpp"
#include "console.hpp"
#include "regs.hpp"
#include "stdio.hpp"

class Pe_state {
    
public:
    enum Type {
        PE_STATE_DEFAULT              = 0,
        PE_STATE_RESOLVE_COWFAULT     = 1,
        PE_STATE_PLACE_PHYS0          = 2,
        PE_STATE_INTERRUPT            = 3,
        PE_STATE_VM_EXIT              = 4,
    };
    
private:
    friend class Queue<Pe_state>;
    friend class Pe;
    static Slab_cache cache;    
    static Queue<Pe_state> pe_states, log_pe_states;
    
    static size_t number;
    mword rax = 0, rbx = 0, rcx = 0, rdx = 0, rbp = 0, rdi = 0, rsi = 0, rsp = 0, rip = 0, r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    mword m_rip = 0, m_rsp = 0, m_eflag = 0;
    uint64 retirement_counter = 0;
    uint8 run_number = 123; 
    mword interrupt_number = 0;
    bool is_vcpu = false;
    size_t numero = 0;
    mword instruction = 0;
    mword attr = 0; 
    mword sub_reason = 0;
    mword diff_reason = 0;
    Type type = PE_STATE_DEFAULT;
    size_t count = 0, page_twin_index = 0;
    int missmatch_addr = 0;
    mword page_addr = 0, page_twin_addr = 0, page_addr_placed = 0, page_twin_addr_placed = 0;
    Paddr phys0 = 0, phys1 = 0, phys2 = 0, phys0_placed = 0, phys1_placed = 0, phys2_placed = 0;
    
    Pe_state* prev;
    Pe_state* next;
    
public:
    
    /**
     * 
     * @param ec
     * @param pd
     * @param rip_value
     * @param counter
     */
    Pe_state(Exc_regs*, uint64, uint8, mword, bool = false); 
    Pe_state(Cpu_regs*, uint64, uint8, mword, bool = false); 
    Pe_state &operator = (Pe_state const &);
    Pe_state(size_t, int, mword, Paddr, Paddr, Paddr, mword, mword);
    Pe_state(mword, Paddr, Paddr, Paddr, mword);
    Pe_state(mword, uint8, mword, uint64);
    Pe_state(mword, mword, mword, mword, uint8, uint64);   
    
    ALWAYS_INLINE
    static inline void *operator new (size_t, Quota &quota) { return cache.alloc(quota); }

    ALWAYS_INLINE
    static inline void destroy (Pe_state *obj, Quota &quota) { obj->~Pe_state(); cache.free (obj, quota); }
    
    Pe_state(const Pe_state& orig);    
    ~Pe_state();
    
    ALWAYS_INLINE
    static inline void operator delete (void *ptr, Quota &quota) {
        Pe_state* pe_state = static_cast<Pe_state*> (ptr);
        pe_state->~Pe_state();
        cache.free (ptr, quota);
    }
    
    void print();
    
    static size_t get_number(){
        return number;
    }
    
    static void add_pe_state(Pe_state*);
    
    static void set_current_pe_sub_reason(mword);
    
    static void set_current_pe_diff_reason(mword);
    
    static void free_recorded_pe_state();
    static void free_recorded_log_pe_state();
    
    static void dump();
    static void dump_log();
};

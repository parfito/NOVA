/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pe_stack.hpp
 * Author: parfait
 *
 * Created on 6 mai 2019, 2018, 13:26
 */

#pragma once

#include "slab.hpp"
#include "queue.hpp"
#include "vtlb.hpp"
#include "hpt.hpp"
#include "stdio.hpp"

class Pe_stack {
    friend class Queue<Pe_stack>;
    static Slab_cache cache; 
    static  Queue<Pe_stack> detected_stacks;
        
public:
    static mword stack;
    Pe_stack(mword, Paddr, mword, Vtlb*, Hpt*);
    Pe_stack(const Pe_stack& orig);
    ~Pe_stack();
    ALWAYS_INLINE
    static inline void *operator new (size_t, Quota &quota) { return cache.alloc(quota); }
    ALWAYS_INLINE
    static inline void destroy (Pe_stack *obj, Quota &quota) { obj->~Pe_stack(); cache.free (obj, quota);}
    ALWAYS_INLINE
    static inline void operator delete (void *ptr, Quota &quota) {
        Pe_stack* pi = static_cast<Pe_stack*> (ptr);
        pi->~Pe_stack();
        cache.free (ptr, quota);
    }

    Pe_stack &operator = (Pe_stack const &);
    
    static void add_detected_stack(mword, Paddr, mword, Vtlb*, Hpt*);
    
    static void free_detected_stacks();
    
    static bool is_empty() {
        return !detected_stacks.head();
    }
    
    static void remove_cow_for_detected_stacks(Vtlb*, Hpt*); 
    
    static void print(){
        Pe_stack *c = detected_stacks.head(), *head = detected_stacks.head(), *n = nullptr;

        while (c) {
            trace(0, "rsp %lx phys %lx attr %lx", c->rsp, c->phys, c->attr);
            n = c->next;
            c = (c == n || n == head) ? nullptr : n;
        }        
    }
    
private:
    mword rsp;
    Paddr phys;
    mword attr;
    Hpt *hpt;
    Vtlb *tlb;
    Pe_stack* prev;
    Pe_stack* next;     
};
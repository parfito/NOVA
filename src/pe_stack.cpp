/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/* 
 * File:   Pe_stack.cpp
 * Author: parfait
 *
 * Created on 6 mai 2019, 13:26
 */

#include "pe_stack.hpp"
#include "pd.hpp"
#include "cow_elt.hpp"
#include "stdio.hpp"

Slab_cache Pe_stack::cache(sizeof (Pe_stack), 32);
Queue<Pe_stack> Pe_stack::detected_stacks;
mword Pe_stack::stack;

Pe_stack::Pe_stack(mword v, Paddr p, mword a, Vtlb *t, Hpt *h): rsp(v), phys(p), attr(a), hpt(h), tlb(t), prev(nullptr), next(nullptr) { }

Pe_stack::~Pe_stack() {
}

void Pe_stack::add_detected_stack(mword rsp, Paddr phys, mword attr, Vtlb *tlb, Hpt *hpt ){
    detected_stacks.enqueue(new (Pd::kern.quota) Pe_stack(rsp, phys, attr, tlb, hpt));
}

void Pe_stack::free_detected_stacks() {
    Pe_stack *ps = nullptr;
    while (detected_stacks.dequeue(ps = detected_stacks.head())) {
        Pe_stack::destroy(ps, Pd::kern.quota);
    }
    stack = 0;
}

void Pe_stack::remove_cow_for_detected_stacks(Vtlb* tlb, Hpt* hpt){
    Pe_stack *ps = nullptr;
    Paddr phys;
    mword v, a;
    debug_started_trace(0, "remove_cow_for_detected_stacks");
    while (detected_stacks.dequeue(ps = detected_stacks.head())) {
        v = ps->rsp;
        a = ps->attr;
        phys = ps->phys;
        debug_started_trace(0, "remove_cow_for_detected_stacks rsp: %lx phys %lx attr %lx", 
                v, phys, a);
        if(hpt){
            assert(!tlb);
            Hpt *e = ps->hpt;
            Cow_elt::resolve_cow_fault(nullptr, e, v, phys, a);       
        }
        if(tlb){
            assert(!hpt);
            Vtlb *t = ps->tlb;
            Cow_elt::resolve_cow_fault(t, nullptr, v, phys, a);                   
        }
        Pe_stack::destroy(ps, Pd::kern.quota);
    }
}
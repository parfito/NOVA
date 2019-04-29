/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Cow_elt.cpp
 * Author: parfait
 * 
 * Created on 7 octobre 2018, 21:29
 */

#include "cow_elt.hpp"
#include "pd.hpp"
#include "stdio.hpp"
#include "hpt.hpp"
#include "string.hpp"

Slab_cache Cow_elt::cache(sizeof (Cow_elt), 32);
Queue<Cow_elt> Cow_elt::cow_elts;
size_t Cow_elt::number = 0;

Cow_elt::Cow_elt(mword v, Paddr phys, mword a, Page_type t) : type(t), page_addr(v), old_phys(phys), attr(a), prev(nullptr), next(nullptr) {
    unsigned short ord = (t == NORMAL) ? 1 : 11;
    linear_add = Buddy::allocator.alloc(ord, Pd::kern.quota, Buddy::NOFILL);
    new_phys[0] = Buddy::ptr_to_phys(linear_add);
    new_phys[1] = new_phys[0] + (1UL << ((ord - 1) + PAGE_BITS));
    number++;
}

Cow_elt::~Cow_elt() {
    Buddy::allocator.free(reinterpret_cast<mword> (linear_add), Pd::kern.quota);
    number--;
}

void Cow_elt::resolve_cow_fault(Vtlb* tlb, mword virt, Paddr phys, mword attr) {
    phys &= ~PAGE_MASK; 
    virt &= ~PAGE_MASK; 
    Cow_elt *ce = new (Pd::kern.quota) Cow_elt(virt, phys, attr, Cow_elt::NORMAL);
    if(tlb){
        ce->vtlb = tlb;
    }
    if (!is_mapped_elsewhere(phys, ce)) {
        copy_frame(ce, virt);
    }
    cow_elts.enqueue(ce);
    mword a = ce->attr | Vtlb::TLB_W;
    a &= ~Vtlb::TLB_COW;
    tlb->cow_update(ce->new_phys[0], a);
}
    
bool Cow_elt::is_mapped_elsewhere(Paddr phys, Cow_elt* ce){
    Cow_elt *c = cow_elts.head(), *head = cow_elts.head(), *n = nullptr;
    while (c) {
        if (c->old_phys == phys) {//frame already mapped elsewhere
            ce->old_phys = phys;
            ce->new_phys[0] = c->new_phys[0];
            ce->new_phys[1] = c->new_phys[1];
            trace(COW_FAULT, "Is mapped elsewhere c->old_phys == phys : Phys:%lx new_phys[0]:%lx new_phys[1]:%lx",
                    c->old_phys, c->new_phys[0], c->new_phys[1]);
            return true;
        }
        n = c->next;
        c = (c == n || n == head) ? nullptr : n;
    }
    return false;
}

void Cow_elt::copy_frame(Cow_elt *ce, mword virt){
    void *ptr = Hpt::remap_cow(Pd::kern.quota, ce->new_phys[0]);
    memcpy(ptr, reinterpret_cast<const void*> (virt), PAGE_SIZE);
    ptr = Hpt::remap_cow(Pd::kern.quota, ce->new_phys[1]);
    memcpy(ptr, reinterpret_cast<const void*> (virt), PAGE_SIZE);
}

void Cow_elt::restore_state(){
    Cow_elt *c = cow_elts.head(), *head = cow_elts.head(), *n = nullptr;
    while (c) {
        mword a = c->attr|Vtlb::TLB_W;
        a &= ~Vtlb::TLB_COW;
        c->vtlb->cow_update(c->new_phys[1], a);
        n = c->next;
        c = (c == n || n == head) ? nullptr : n;
    }
}

bool Cow_elt::compare_and_commit(){
    Cow_elt *c = nullptr;
    while (cow_elts.dequeue(c = cow_elts.head())) {
        //        Console::print("Compare v: %p  phys: %p  ce: %p  phys1: %p  phys2: %p", cow->page_addr_or_gpa, cow->old_phys, cow, cow->new_phys[0]->phys_addr, cow->new_phys[1]->phys_addr);
        mword *ptr1 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->new_phys[0])),
                *ptr2 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->new_phys[1], PAGE_SIZE));
        int missmatch_addr = memcmp(ptr1, ptr2, PAGE_SIZE); 
        if (missmatch_addr) {
            mword index = (PAGE_SIZE / 4 - missmatch_addr - 1) * 4 /sizeof(mword); // because memcmp compare by grasp of 4 bytes
            mword val1 = *(ptr1 + index);
            mword val2 = *(ptr2 + index);
            Console::print("VMX Pd: %s phys0:%lx phys1 %lx phys2 %lx ptr1: %p  ptr2: %p  val1: 0x%lx  val2: 0x%lx  missmatch_addr: %p",
                    Pd::current->get_name(), c->old_phys, c->new_phys[0], c->new_phys[1], ptr1, ptr2, val1, val2, ptr2 + index);
            return true;
        }
        Paddr old_phys = c->old_phys;
        void *ptr = Hpt::remap_cow(Pd::kern.quota, old_phys);
        memcpy(ptr, ptr2, PAGE_SIZE);
        if(c->vtlb){
            c->vtlb->cow_update(old_phys, c->attr);
        }else{
            c->hpt->cow_update(old_phys, c->attr);
        }
        destroy(c, Pd::kern.quota);
    }
    return false;
}
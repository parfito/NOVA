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

Paddr Cow_elt::resolve_cow_fault(mword virt, Paddr phys, mword attr) {
    phys &= ~PAGE_MASK; 
    virt &= ~PAGE_MASK; 
    Cow_elt *ce = new (Pd::kern.quota) Cow_elt(virt, phys, attr, Cow_elt::NORMAL);

    if (is_mapped_elsewhere(phys, ce) || subtitute(ce, virt)) {
        cow_elts.enqueue(ce);
        return ce->new_phys[0];
    } else 
        Console::panic("Cow frame exhausted");
}
    
bool Cow_elt::is_mapped_elsewhere(Paddr phys, Cow_elt* ce){
    Cow_elt *c = nullptr;
    while (cow_elts.dequeue(c = cow_elts.head())) {
        if (c->old_phys == phys) {//frame already mapped elsewhere
            ce->old_phys = phys;
            ce->new_phys[0] = c->new_phys[0];
            ce->new_phys[1] = c->new_phys[1];
            trace(COW_FAULT, "Is mapped elsewhere c->old_phys == phys : Phys:%lx new_phys[0]:%lx new_phys[1]:%lx",
                    c->old_phys, c->new_phys[0], c->new_phys[1]);
            return true;
        }
    }
    return false;
}

bool Cow_elt::subtitute(Cow_elt *ce, mword virt){
    void *ptr = Hpt::remap_cow(Pd::kern.quota, ce->new_phys[0]);
    memcpy(ptr, reinterpret_cast<const void*> (virt), PAGE_SIZE);
    ptr = Hpt::remap_cow(Pd::kern.quota, ce->new_phys[1]);
    memcpy(ptr, reinterpret_cast<const void*> (virt), PAGE_SIZE);
    return true;
}
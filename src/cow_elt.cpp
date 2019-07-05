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
#include "pe.hpp"
#include "vmx.hpp"
#include "pe_stack.hpp"
#include "ec.hpp"

Slab_cache Cow_elt::cache(sizeof (Cow_elt), 32);
Queue<Cow_elt> Cow_elt::cow_elts;
size_t Cow_elt::number = 0;

Cow_elt::Cow_elt(mword v, Paddr phys, mword a, Page_type t) : type(t), page_addr(v), old_phys(phys), attr(a), prev(nullptr), next(nullptr) {
    // TODO: Implement handling of cow fault in big pages
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

void Cow_elt::resolve_cow_fault(Vtlb* tlb, Hpt *hpt, mword virt, Paddr phys, mword attr) {
    phys &= ~PAGE_MASK; 
    virt &= ~PAGE_MASK; 
    /* Do not try again to optimize by avoiding a new Cow_elt creation when phys is mapped elsewhere
     * if you don't have a good reason to. When phys is already mapped elsewhere, 
     * a new Cow_elt is necessary to save data relative to the current cow fault.
     */
    Cow_elt *ce = new (Pd::kern.quota) Cow_elt(virt, phys, attr, Cow_elt::NORMAL),
            *c = is_mapped_elsewhere(phys);
    mword a;
    if(tlb){
        assert(!hpt);
        ce->vtlb = tlb;
        a = ce->attr | Vtlb::TLB_W;
        a &= ~Vtlb::TLB_COW;
    } else if(hpt){
        assert(!tlb);
        ce->hpt = hpt;
        a = ce->attr | Hpt::HPT_W;
        a &= ~Hpt::HPT_COW;
    } else {
        Console::panic("Neither tlb, nor htp is specified");
    }
    
    if (c) {
        ce->new_phys[0] = c->new_phys[0];
        ce->new_phys[1] = c->new_phys[1];
    } else {
        if(hpt){
            copy_frames(ce, reinterpret_cast<void*> (virt));
        } 
        if(tlb){
            void *phys_to_ptr = Hpt::remap_cow(Pd::kern.quota, phys, 2*PAGE_SIZE);
            copy_frames(ce, phys_to_ptr);
        }
    }
    if(tlb) {
        tlb->cow_update(ce->new_phys[0], a);
    } 
    if(hpt) {
        hpt->cow_update(ce->new_phys[0], a, ce->page_addr); 
    }
    cow_elts.enqueue(ce);
//    Console::print("Cow error  v: %lx  phys: %lx attr %lx phys1: %lx  phys2: %lx", virt, phys, ce->attr, ce->new_phys[0], ce->new_phys[1]);            
    Pe::add_pe_state(0, 0, ce->page_addr, ce->old_phys, ce->new_phys[0], ce->new_phys[1], reinterpret_cast<mword>(
                c ? c->page_addr : 0), 0);
}

Cow_elt* Cow_elt::is_mapped_elsewhere(Paddr phys){
    Cow_elt *c = cow_elts.head(), *n = nullptr;
    while (c) {
        if (c->old_phys == phys) {//frame already mapped elsewhere
            trace(COW_FAULT, "Is mapped elsewhere c->old_phys == phys : Phys:%lx new_phys[0]:%lx new_phys[1]:%lx",
                    c->old_phys, c->new_phys[0], c->new_phys[1]);
            return c;
        }
        n = c->next;
        c = (c == n || n == cow_elts.head()) ? nullptr : n;
    }
    return nullptr;
}

void Cow_elt::copy_frames(Cow_elt *ce, void* virt){
    void *ptr = Hpt::remap_cow(Pd::kern.quota, ce->new_phys[0]);
    memcpy(ptr, virt, PAGE_SIZE);
    ptr = Hpt::remap_cow(Pd::kern.quota, ce->new_phys[1]);
    memcpy(ptr, virt, PAGE_SIZE);
}

void Cow_elt::restore_state(){
    Cow_elt *c = cow_elts.head(), *n = nullptr;
    
    mword a;
    while (c) {
        if(c->vtlb) {
            a= c->attr|Vtlb::TLB_W;
            a &= ~Vtlb::TLB_COW;
            c->vtlb->cow_update(c->new_phys[1], a);
            debug_started_trace(0, "Cow Restore  ce: %p  virt: %lx  phys2: %lx attr %lx", 
                    c, c->page_addr, c->new_phys[1], a);        
        }
        if(c->hpt){
            a= c->attr|Hpt::HPT_W;
            a &= ~Hpt::HPT_COW;
            c->hpt->cow_update(c->new_phys[1], a, c->page_addr); 
        }

        n = c->next;
        c = (c == n || n == cow_elts.head()) ? nullptr : n;
    }
}

bool Cow_elt::compare(){
    Cow_elt *c = cow_elts.head(), *n = nullptr;
    while (c) {
        //        Console::print("Compare v: %p  phys: %p  ce: %p  phys1: %p  phys2: %p", cow->page_addr_or_gpa, cow->old_phys, cow, cow->new_phys[0]->phys_addr, cow->new_phys[1]->phys_addr);
        mword *ptr1 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->new_phys[0])),
                *ptr2 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->new_phys[1], PAGE_SIZE));
        int missmatch_addr = memcmp(ptr1, ptr2, PAGE_SIZE); 
        if (missmatch_addr) {
            if(Pe::in_recover_from_stack_fault_mode){
                asm volatile ("" :: "m" (missmatch_addr)); // to avoid gdb "optimized out"            
                asm volatile ("" :: "m" (c)); // to avoid gdb "optimized out"                        
                mword index = (PAGE_SIZE - 4 * (missmatch_addr + 1)) / sizeof(mword); // because memcmp compare by grasp of 4 bytes
                mword val1 = *(ptr1 + index);
                mword val2 = *(ptr2 + index);
                mword *ptr3 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->old_phys, 2*PAGE_SIZE));
                mword val0 = *(ptr3 + index);
                Pe::missmatch_addr = c->page_addr + index * sizeof(mword);
                Console::print("MISSMATCH Pd: %s virt %lx phys0:%lx phys1 %lx phys2 %lx ptr1: %p  ptr2: %p  val0: 0x%lx  val1: 0x%lx val2 0x%lx missmatch_addr: %p",
                        Pd::current->get_name(), c->page_addr, c->old_phys, c->new_phys[0], c->new_phys[1], ptr1, ptr2, val0, val1, val2, ptr2 + index);
                Console::print_page(reinterpret_cast<void*>(ptr1));
                Console::print_page(reinterpret_cast<void*>(ptr2));
            }
            return true;
        }
        n = c->next;
        c = (c == n || n == cow_elts.head()) ? nullptr : n;
    }
    
    return false;
}

void Cow_elt::commit(){
    Cow_elt *c = nullptr;
    // If everything went fine during comparison, we can copy memories and destroy cow_elts
    while (cow_elts.dequeue(c = cow_elts.head())) {
        Paddr old_phys = c->old_phys;
        void *ptr = Hpt::remap_cow(Pd::kern.quota, old_phys);
        mword *ptr1 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->new_phys[0], PAGE_SIZE));
        
        memcpy(ptr, ptr1, PAGE_SIZE);
        if(c->vtlb){
            c->vtlb->cow_update(old_phys, c->attr);
        }
        if(c->hpt){
            c->hpt->cow_update(old_phys, c->attr, c->page_addr);
        }
//        trace(0, "cow_elt %lx ", c->page_addr);    
        destroy(c, Pd::kern.quota);
    }
//    trace(0, "============================================ Ec %s", Ec::current->get_name());
    if(Pe::in_recover_from_stack_fault_mode){
        Pe::in_recover_from_stack_fault_mode = false;
        debug_started_trace(0,"Rollback finished");
    }
}

void Cow_elt::restore_state1(){
    Cow_elt *c = cow_elts.head(), *n = nullptr;
    mword a;
    while (c) {
        if(c->vtlb) {
            a = c->attr|Vtlb::TLB_W;
            a &= ~Vtlb::TLB_COW;
            c->vtlb->cow_update(c->new_phys[0], a);
        }
        if(c->hpt){
            a= c->attr|Hpt::HPT_W;
            a &= ~Hpt::HPT_COW;
            c->hpt->cow_update(c->new_phys[0], a, c->page_addr); 
        }
        n = c->next;
        c = (c == n || n == cow_elts.head()) ? nullptr : n;
    }
}

/*
 * upadate hpt or vtlb with old_phys value and attr
 */
void Cow_elt::rollback(){
    Cow_elt *c = cow_elts.head(), *n = nullptr;
    mword a;
    while (c) {
        void *phys_to_ptr = Hpt::remap_cow(Pd::kern.quota, c->old_phys, 2*PAGE_SIZE);
        copy_frames(c, phys_to_ptr);
        if(c->vtlb){
            a = c->attr|Vtlb::TLB_W;
            a &= ~Vtlb::TLB_COW;
            c->vtlb->cow_update(c->new_phys[0], a);
//            trace(0, "rollback v: %lx  phys: %lx attr %lx ce: %p  phys1: %lx  phys2: %lx", c->page_addr, c->old_phys, ca, ce, ce->new_phys[0], ce->new_phys[1]);        
        }
        if(c->hpt){
            a= c->attr|Hpt::HPT_W;
            a &= ~Hpt::HPT_COW;
            c->hpt->cow_update(c->new_phys[0], a, c->page_addr);
        }
        n = c->next;
        c = (c == n || n == cow_elts.head()) ? nullptr : n;
    }
}

void Cow_elt::place_phys0(bool is_vcpu){
    Cow_elt *c = Ec::current->cow_elts.head(), *n = nullptr;
     
    while (c) {
        if(is_vcpu) {
            mword a = c->attr | Vtlb::TLB_W;
            a &= ~Vtlb::TLB_COW;
            c->vtlb->cow_update(c->new_phys[0], a);
    //        debug_started_trace(0, "Cow error  v: %lx  phys: %lx attr %lx ce: %p  phys1: %lx  phys2: %lx", virt, phys, a, ce, ce->new_phys[0], ce->new_phys[1]);        
        } else {
            mword a = c->attr | Hpt::HPT_W;
            a &= ~Hpt::HPT_COW;
            c->hpt->cow_update(c->new_phys[0], a, c->page_addr); 
        }
        n = c->next;
        c = (c == n || n == Ec::current->cow_elts.head()) ? nullptr : n;
    }        
}

bool Cow_elt::is_cowed(mword v){
    Cow_elt *c = Ec::current->cow_elts.head(), *head = Ec::current->cow_elts.head(), *n = nullptr;
    while (c) {
        if(v == c->page_addr)
            return true;
        n = c->next;
        c = (c == n || n == head) ? nullptr : n;
    }  
    return false;
}
/*
 * Host Page Table (HPT)
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012-2013 Udo Steinberg, Intel Corporation.
 * Copyright (C) 2015 Alexander Boettcher, Genode Labs GmbH
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

#include "assert.hpp"
#include "bits.hpp"
#include "hpt.hpp"
#include "pd.hpp"
#include "string.hpp"
#include "ec.hpp"
#include "hip.hpp"
#include "cow_elt.hpp"
#include "pe_stack.hpp"
#include "log.hpp"
#include "pe.hpp"

//void Hpt::print_table(Quota &quota, mword o) {
//    for (mword v = 0; v <= o; v = v + PAGE_SIZE) {
//        mword l = (bit_scan_reverse(v ^ o) - PAGE_BITS) / bpl();
//        print_walk(quota, v, l);
//    }
//}
bool Hpt::sync_from(Quota &quota, Hpt src, mword v, mword o) {
    mword l = (bit_scan_reverse(v ^ o) - PAGE_BITS) / bpl();

    Hpt *s = static_cast<Hpt *> (src.walk(quota, v, l, false));
    if (!s)
        return false;

    Hpt *d = static_cast<Hpt *> (walk(quota, v, l));
    assert(d);

    if (d->val == s->val)
        return false;

    d->val = s->val;
//    is_cow_fault(quota, v, err);
    return true;
}

void Hpt::sync_master_range (Quota & quota, mword s, mword e)
{
    for (mword l = (bit_scan_reverse (LINK_ADDR ^ CPU_LOCAL) - PAGE_BITS) / bpl(); s < e; s += 1UL << (l * bpl() + PAGE_BITS))
        sync_from (quota, Hptp (reinterpret_cast<mword>(&PDBR)), s, CPU_LOCAL);
}

/**
 * ---Parfait---
 * replace the frame mapped to the address v page by an other frame starting at
 * physical address p if it is not writable
 * @param quota
 * @param v
 * @param p
 * @return the new page table entry value
 */
Paddr Hpt::replace(Quota &quota, mword v, mword p) {
    Hpt o, *e = walk(quota, v, 0);
    assert(e);

    do o = *e; while (o.val != p && !(o.attr() & HPT_W) && !e->set (o.val, p));

    flush(v);
    return e->addr();
}

/**
 * ---Parfait---
 * retourne un pointeur sur l'adresse virtuelle correspondant à l'addresse 
 * physique phys dans notre espace d'adressage en y mappant au passage la frame contenant
 * cette adresse physique
// */
//void *Hpt::remap(Quota &quota, Paddr phys) {
//    Hptp hpt(current());
//
//    size_t size = 1UL << (bpl() + PAGE_BITS);
//
//    mword offset = phys & (size - 1);
//
//    phys &= ~offset;
//
//    Paddr old; mword attr;
//    if (hpt.lookup (SPC_LOCAL_REMAP, old, attr)) {
//        hpt.update (quota, SPC_LOCAL_REMAP,        bpl(), 0, 0, Hpt::TYPE_DN); flush (SPC_LOCAL_REMAP);
//        hpt.update (quota, SPC_LOCAL_REMAP + size, bpl(), 0, 0, Hpt::TYPE_DN); flush (SPC_LOCAL_REMAP + size);
//    }
//
//    hpt.update (quota, SPC_LOCAL_REMAP,        bpl(), phys,        HPT_W | HPT_P);
//    hpt.update (quota, SPC_LOCAL_REMAP + size, bpl(), phys + size, HPT_W | HPT_P);
//
//    return reinterpret_cast<void *>(SPC_LOCAL_REMAP + offset);
//}

void *Hpt::remap (Quota &quota, Paddr phys, bool is_cow)
{
    Hptp hpt (current());
    mword page = is_cow ? COW_ADDR : SPC_LOCAL_REMAP;
    size_t size = 1UL << (bpl() + PAGE_BITS);

    mword offset = phys & (size - 1);

    phys &= ~offset;

    Paddr old; mword attr;
    if (hpt.lookup (page, old, attr)) {
        hpt.update (quota, page,        bpl(), 0, 0, Hpt::TYPE_DN); flush (page);
        hpt.update (quota, page + size, bpl(), 0, 0, Hpt::TYPE_DN); flush (page + size);
    }

    hpt.update (quota, page,        bpl(), phys,        HPT_W | HPT_P);
    hpt.update (quota, page + size, bpl(), phys + size, HPT_W | HPT_P);

    return reinterpret_cast<void *>(page + offset);
}

void *Hpt::remap_cow(Quota &quota, Hpt proc_hpt, mword addr, uint8 offset, uint8 span) {
    Paddr phys;
    mword a;
    if(!proc_hpt.lookup(addr, phys, a))
        return nullptr;
    return remap_cow(quota, phys, offset, span);
}

void *Hpt::remap_cow(Quota &quota, Paddr phys, uint8 offset, uint8 span) {
    assert(span < PAGE_SIZE);
    mword new_addr = COW_ADDR + PAGE_SIZE * offset, addr_offset = phys & PAGE_MASK;
    Hptp hpt(current());
    hpt.replace_cow(quota, new_addr, phys, Hpt::HPT_W | Hpt::HPT_P);
    if(addr_offset > static_cast<mword>(PAGE_SIZE - span))
        hpt.replace_cow(quota, new_addr + PAGE_SIZE, phys + PAGE_SIZE, 
                Hpt::HPT_W | Hpt::HPT_P);
    return reinterpret_cast<void *> (new_addr + addr_offset);
}

bool Hpt::is_cow_fault(Quota &quota, mword v, mword err) {
    Paddr phys;
    mword a;
    size_t s = lookup(v, phys, a);
    if (s && (a & Hpt::HPT_COW) && (a & Hpt::HPT_U)) {
        //        Ec::cow_count++;
        Ec *ec = Ec::current;
        Pd *pd = ec->getPd();
        if (!(a & Hpt::HPT_P) && (a & Hpt::PTE_COW_IO)) { //Memory mapped IO
            ec->check_memory(Ec::PES_MMIO);
            replace_cow(quota, v, phys, a | Hpt::HPT_P); 
            ec->enable_step_debug(Ec::SR_MMIO, v, phys, a);
            return true;
        } else if ((err & Hpt::ERR_W) && !(a & Hpt::HPT_W)) {
            if (v >= USER_ADDR) {
                Console::panic("Normally, this must not happen since this is not a user space here but..");               
                replace_cow(quota, v, phys, a | Hpt::HPT_W);
                //              Console::print("Cow Error above USER_ADDR");
            } else {
                if (Ec::step_reason && (Ec::step_reason != Ec::SR_DBG) && (Ec::step_reason != Ec::SR_GP)) {//Cow error in single stepping : why this? we don't know; qemu oddities
                    if (Ec::step_reason != Ec::SR_PIO)
                        Console::print("Cow error in single stepping v: %lx  phys: %lx  Pd: %s step_reason %d",
                                v, phys, pd->get_name(), Ec::step_reason);
                    Logstore::dump("Hpt::is_cow_fault");
                    if (ec->is_io_exc()) {
                        replace_cow(quota, v, phys, a | Hpt::HPT_W);
                        return true;
                    } else {// IO instruction already executed but still in single stepping
                        ec->disable_step_debug();
                        if (Ec::launch_state)
                            Ec::launch_state = Ec::UNLAUNCHED;
                    }
                }
                
                Hpt *e = walk(quota, v, 0); // mword l = (bit_scan_reverse(v ^ USSER_ADDR) - PAGE_BITS) / bpl() = 3; but 3 doesnot work

                assert(e);
                assert(v != Pe_stack::stack);
                Cow_elt::resolve_cow_fault(nullptr, e, v, phys, a);
            }
            return true;
        } else
            return false;
    } else
        return false;
}

Paddr Hpt::replace_cow(Quota &quota, mword v, Paddr p, mword a) {
    v &= ~PAGE_MASK; 
    p &= ~PAGE_MASK; 
    a &= ~HPT_NX;
    assert((a & ~PAGE_MASK) == 0);
    Hpt o, *e = walk(quota, v, 0);
    assert(e);
    p |= a;
    do o = *e; while (o.val != p && !e->set(o.val, p));

    flush(v);
    return e->addr();
}

void Hpt::replace_cow_n(Quota &quota, mword v, int n, Paddr p, mword a) {
    for (int i = 0; i< n; i++)
        replace_cow(quota, v+i*PAGE_SIZE, p+i*PAGE_SIZE, a);
}

void Hpt::print(char const *s, mword v){
    Console::print("%s %lx", s, v);
}

void Hpt::set_cow_page(mword virt, mword &entry) {
    if ((virt < USER_ADDR) && (entry & HPT_P) && (entry & HPT_U)) {
        if (Hip::is_mmio(entry & ~(PAGE_MASK|HPT_NX))) {
            entry |= HPT_COW | HPT_COW_IO;
            entry &= ~HPT_P;
        } else if (entry & HPT_W) {
            entry |= HPT_COW;
            entry &= ~HPT_COW_IO;
            entry &= ~HPT_W;
        }
    }
}

/**
 * This update is very specific to our copy on write because it is relative to the entry 
 * directely. So, no page walking is needed.
 * @param phys
 * @param attr
 */
void Hpt::cow_update(Paddr phys, mword attr, mword v){
    /**TODO
     Use tremplate to merge Hpt::cow_update and Vtlb::cow_update in one function*/
    Hpt o, *e = this;
    mword new_val = phys | attr;
    do o = *e; while (o.val != new_val && !e->set (o.val, new_val));
    flush(v);    
}

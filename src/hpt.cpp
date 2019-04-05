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
#include "cow.hpp"
#include "hip.hpp"

//void Hpt::print_table(Quota &quota, mword o) {
//    for (mword v = 0; v <= o; v = v + PAGE_SIZE) {
//        mword l = (bit_scan_reverse(v ^ o) - PAGE_BITS) / bpl();
//        print_walk(quota, v, l);
//    }
//}
bool Hpt::sync_from(Quota &quota, Hpt src, mword v, mword o, mword err) {
    mword l = (bit_scan_reverse(v ^ o) - PAGE_BITS) / bpl();

    Hpt *s = static_cast<Hpt *> (src.walk(quota, v, l, false));
    if (!s)
        return false;

    Hpt *d = static_cast<Hpt *> (walk(quota, v, l));
    assert(d);

    if (d->val == s->val)
        return false;

    d->val = s->val;
    is_cow_fault(quota, v, err);
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
 */
void *Hpt::remap(Quota &quota, Paddr phys) {
    Hptp hpt(current());

    size_t size = 1UL << (bpl() + PAGE_BITS);

    mword offset = phys & (size - 1);

    phys &= ~offset;

    Paddr old; mword attr;
    if (hpt.lookup (SPC_LOCAL_REMAP, old, attr)) {
        hpt.update (quota, SPC_LOCAL_REMAP,        bpl(), 0, 0, Hpt::TYPE_DN); flush (SPC_LOCAL_REMAP);
        hpt.update (quota, SPC_LOCAL_REMAP + size, bpl(), 0, 0, Hpt::TYPE_DN); flush (SPC_LOCAL_REMAP + size);
    }

    hpt.update (quota, SPC_LOCAL_REMAP,        bpl(), phys,        HPT_W | HPT_P);
    hpt.update (quota, SPC_LOCAL_REMAP + size, bpl(), phys + size, HPT_W | HPT_P);

    return reinterpret_cast<void *>(SPC_LOCAL_REMAP + offset);
}

void *Hpt::remap_cow(Quota &quota, Paddr phys, mword addr) {
    Hptp hpt(current());
    addr += COW_ADDR;
    hpt.replace_cow(quota, addr, phys | Hpt::HPT_W | Hpt::HPT_P);
//    Hpt::cow_flush(addr);
    return reinterpret_cast<void *> (addr);
}

bool Hpt::is_cow_fault(Quota &quota, mword v, mword err) {
    Paddr phys;
    mword a;
    if (lookup(v, phys, a) && (a & Hpt::HPT_COW) && (a & Hpt::HPT_U)) {
        //        Ec::cow_count++;
        Ec *ec = Ec::current;
        Pd *pd = ec->getPd();
        if (!(a & Hpt::HPT_P) && (a & Hpt::PTE_COW_IO)) { //Memory mapped IO
//      if (Ec::current->ec_debug) {
//          Console::print("Cow error in IO: v: %lx  phys: %lx, attr: %lx",
//                                        v, phys, a);
//          Ec::current->ec_debug = false;
//      }
            ec->check_memory(Ec::PES_MMIO);
            ++Counter::mmio;
            ++Counter::io;
            replace_cow(quota, v, phys | a | Hpt::HPT_P); // the old frame may have been released; so we have to retain it
//            cow_flush(v);
            //            Console::print("Read MMIO");
                ec->enable_step_debug(Ec::SR_MMIO, v, phys, a);
            return true;
        } else if ((err & Hpt::ERR_W) && !(a & Hpt::HPT_W)) {
            //            if (Ec::current->ec_debug) {
            //                Console::print("Cow error in Memory: v: %p  phys: %08p, attr: %08p",
            //                        v, phys, a);
            //                Ec::current->ec_debug = false;
            //            }
            if (v >= USER_ADDR) {
                //Normally, this must not happen since this is not a user space here but...                
                replace_cow(quota, v, phys | a | Hpt::HPT_W);
                //              Console::print("Cow Error above USER_ADDR");
            } else {
                if (Ec::step_reason && (Ec::step_reason != Ec::SR_DBG) && (Ec::step_reason != Ec::SR_GP)) {//Cow error in single stepping : why this? we don't know; qemu oddities
                    if (Ec::step_reason != Ec::SR_PIO)
                        Console::print("Cow error in single stepping v: %lx  phys: %lx  Pd: %s", v, phys, pd->get_name());
                    if (ec->is_io_exc()) {
                        replace_cow(quota, v, phys | a | Hpt::HPT_W);
//                        cow_flush(v);
                        return true;
                    } else {// IO instruction already executed but still in single stepping
                        ec->disable_step_debug();
                        if (Ec::launch_state)
                            Ec::launch_state = Ec::UNLAUNCHED;
                    }
                }
                Cow::cow_elt *ce = nullptr;
                if (!Cow::get_cow_list_elt(&ce)) //get new cow_elt
                    ec->die("Cow elt exhausted");

                if (pd->is_mapped_elsewhere(phys & ~PAGE_MASK, ce) || Cow::subtitute(phys & ~PAGE_MASK, ce, v & ~PAGE_MASK)) {
                    ce->page_addr_or_gpa = v & ~PAGE_MASK;
                    ce->attr = a;
                } else // Cow::subtitute will fill cow's fields old_phys, new_phys and frame_index 
                    ec->die("Cow frame exhausted");
                pd->add_cow(ce);
                replace_cow(quota, v, ce->new_phys[0]->phys_addr | a | Hpt::HPT_W);
//                cow_flush(v);
//                                Console::print("Cow error Ec: %p  v: %lx  phys: %lx  ce: %p  phys1: %lx  phys2: %lx", ec, v, phys, ce, ce->new_phys[0]->phys_addr, ce->new_phys[1]->phys_addr);
                //                update(quota, v, 0, phys, a | Hpt::HPT_W, Type::TYPE_UP, false);
                //                cow_flush(v);
                //                Console::print("Cow error Ec: %p  v: %p  phys: %p", ec, v, phys);
            }
            return true;
        } else
            return false;
    } else
        return false;
}

Paddr Hpt::replace_cow(Quota &quota, mword v, mword p) {
    Hpt o, *e = walk(quota, v, 0);
    if(!e) return 0;
    
    do o = *e; while (o.val != p && !e->set(o.val, p));

    flush(v);
    return e->addr();
}

void Hpt::replace_cow_n(Quota &quota, mword v, int n, mword p) {
    for (int i = 0; i< n; i++)
        replace_cow(quota, v+i*PAGE_SIZE, p+i*PAGE_SIZE);
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
void Hpt::cow_update(Paddr phys, mword attr){
    /**TODO
     Use tremplate to merge Hpt::cow_update and Vtlb::cow_update in one function*/
    val = phys | attr| HPT_W;
    val &= ~HPT_COW;
}
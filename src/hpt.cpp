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

bool Hpt::sync_from(Quota &quota, Hpt src, mword v, mword o) {
    mword l = (bit_scan_reverse(v ^ o) - PAGE_BITS) / bpl();

    Hpt *s = static_cast<Hpt *> (src.walk(quota, v, l, false));
    if (!s)
        return false;

    Hpt *d = static_cast<Hpt *> (walk(quota, v, l));
    assert(d);

    if (d->val == s->val)
        return false;
    // if d->val == (s->val|Hpt::HPT_COW), so the previous comparison must have been tested true.
    if (d->val == (s->val | Hpt::HPT_COW))
        return false;
    //        if (Ec::debug) {
    //            Console::print("v: %08lx  d: %p  d.val: %08lx  s: %p  s.val: %08lx", v, d, d->val, s, s->val);
    //    if (v < USER_ADDR)
    //        Pd::current->big_page_check();
    //            Paddr phys1;
    //            mword attr1;
    //            lookup(reinterpret_cast<mword> (&(d->val)), phys1, attr1);
    //            Console::print("&(e->val): %08lx", phys1);
    //        }

    d->val = s->val;

    return true;
}

void Hpt::sync_master_range(Quota & quota, mword s, mword e) {
    for (mword l = (bit_scan_reverse(LINK_ADDR ^ CPU_LOCAL) - PAGE_BITS) / bpl(); s < e; s += 1UL << (l * bpl() + PAGE_BITS))
        sync_from(quota, Hptp(reinterpret_cast<mword> (&PDBR)), s, CPU_LOCAL);
}

/**
 * ---Parfait---
 * replace the frame mapped to the address v page by an other frame starting at
 * physical address p
 * @param quota
 * @param v
 * @param p
 * @return the new page table entry value
 */
Paddr Hpt::replace(Quota &quota, mword v, mword p) {
    Hpt o, *e = walk(quota, v, 0);
    assert(e);

    do o = *e; while (o.val != p && !(o.attr() & HPT_W) && !e->set(o.val, p));

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

    Paddr old;
    mword attr;
    if (hpt.lookup(SPC_LOCAL_REMAP, old, attr)) {
        hpt.update(quota, SPC_LOCAL_REMAP, bpl(), 0, 0, Hpt::TYPE_DN);
        flush(SPC_LOCAL_REMAP);
        hpt.update(quota, SPC_LOCAL_REMAP + size, bpl(), 0, 0, Hpt::TYPE_DN);
        flush(SPC_LOCAL_REMAP + size);
    }

    hpt.update(quota, SPC_LOCAL_REMAP, bpl(), phys, HPT_W | HPT_P);
    hpt.update(quota, SPC_LOCAL_REMAP + size, bpl(), phys + size, HPT_W | HPT_P);

    return reinterpret_cast<void *> (SPC_LOCAL_REMAP + offset);
}

void *Hpt::remap_cow(Quota &quota, Paddr phys, mword addr) {
    Hptp hpt(current());
    addr += COW_ADDR;
    hpt.update(quota, addr, 0, phys, Hpt::HPT_W | Hpt::HPT_P, Hpt::TYPE_UP);
    Hpt::cow_flush(addr);
    return reinterpret_cast<void *> (addr);
}

bool Hpt::is_cow_fault(Quota &quota, mword v, mword err) {
    Paddr phys;
    mword a;
    if (lookup(v, phys, a) && (a & Hpt::HPT_COW) && (a & Hpt::HPT_U)) {
        //        Ec::cow_count++;
        Ec *ec = Ec::current;
        if (!(a & Hpt::HPT_P) && (a & Hpt::PTE_COW_IO)) { //Memory mapped IO
            //            if (Ec::current->ec_debug) {
            //                            Console::print("Cow error in IO: v: %p  phys: %p, attr: %p",
            //                                    v, phys, a);
            ////                Ec::current->ec_debug = false;
            //            }
            ec->check_memory(1257);
            update(quota, v, 0, phys, a | Hpt::HPT_P, Hpt::TYPE_UP, false); // the old frame may have been released; so we have to retain it
            cow_flush(v);
            //            Console::print("Read MMIO");
            ec->enable_step_debug(v, phys, a, Ec::MMIO);
            return true;
        } else if ((err & Hpt::ERR_W) && !(a & Hpt::HPT_W)) {
            //            if (Ec::current->ec_debug) {
            //                Console::print("Cow error in Memory: v: %p  phys: %08p, attr: %08p",
            //                        v, phys, a);
            //                Ec::current->ec_debug = false;
            //            }
            if (v >= USER_ADDR) {
                //Normally, this must not happen since this is not a user space here but...                
                update(quota, v, 0, phys, a | Hpt::HPT_W, Type::TYPE_UP, false);
                //              Console::print("Cow Error above USER_ADDR");
            } else {
                ec->cow_error_happened = true;
                Cow::cow_elt *ce = ec->cowlist_contains(v, phys);
                if (ce) {
                    Console::print("cow elt exist %p", ce);
                    ce->cowed = true;
                }else{
                    if (!Cow::get_cow_list_elt(&ce)) //get new cow_elt
                        ec->die("Cow elt exhausted");

                    if (ec->is_mapped_elsewhere(phys & ~PAGE_MASK, ce) || Cow::subtitute(phys & ~PAGE_MASK, ce, v & ~PAGE_MASK)) {
                        ce->page_addr_or_gpa = v & ~PAGE_MASK;
                        ce->attr = a;
                        //                    ce->used = true;
                    } else // Cow::subtitute will fill cow's fields old_phys, new_phys and frame_index 
                        ec->die("Cow frame exhausted");
                    ec->add_cow(ce);
                }
                update(quota, v, 0, ce->new_phys[0]->phys_addr, a | Hpt::HPT_W, Type::TYPE_UP, false);
                //                update(quota, v, 0, phys, a | Hpt::HPT_W, Type::TYPE_UP, false); // the old frame may have been released; so we have to retain it
                cow_flush(v);
                Console::print("Cow error Ec: %p  v: %p  phys: %p  ce: %p  phys1: %p  phys2: %p", ec, v, phys, ce, ce->new_phys[0]->phys_addr, ce->new_phys[1]->phys_addr);
            }
            return true;
        } else
            return false;
    } else
        return false;
}

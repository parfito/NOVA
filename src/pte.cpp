/*
 * Page Table Entry (PTE)
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012 Udo Steinberg, Intel Corporation.
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

#include "dpt.hpp"
#include "ept.hpp"
#include "hpt.hpp"
#include "pte.hpp"
#include "vtlb.hpp"

mword Dpt::ord = ~0UL;
mword Ept::ord = ~0UL;
mword Hpt::ord = ~0UL;

template <typename P, typename E, unsigned L, unsigned B, bool F>
P *Pte<P, E, L, B, F>::walk(Quota &quota, E v, unsigned long n, bool a) {
    unsigned long l = L;

    for (P *p, *e = static_cast<P *>(this);; e = static_cast<P *>(Buddy::phys_to_ptr (e->addr())) + (v >> (--l * B + PAGE_BITS) & ((1UL << B) - 1))) {

        if (l == n)
            return e;

        if (!e->val) {

            if (!a)
                return nullptr;

            if (!e->set (0, Buddy::ptr_to_phys (p = new (quota) P) | (l == L ? 0 : P::PTE_N)))
                Pte::destroy(p, quota); // no need to delete cow_field for the first entry level
        }
    }
}

template <typename P, typename E, unsigned L, unsigned B, bool F>
size_t Pte<P, E, L, B, F>::lookup(E v, Paddr &p, mword &a) {
    unsigned long l = L;

    for (P *e = static_cast<P *> (this);; e = static_cast<P *> (Buddy::phys_to_ptr(e->addr())) + (v >> (--l * B + PAGE_BITS) & ((1UL << B) - 1))) {

        if (EXPECT_FALSE(!e->val))
            return 0;

        if (EXPECT_FALSE(l && !e->super()))
            continue;

        size_t s = 1UL << (l * B + e->order());

        p = static_cast<Paddr> (e->addr() | (v & (s - 1)));

        a = e->attr();

        return s;
    }
}

template <typename P, typename E, unsigned L, unsigned B, bool F>
bool Pte<P, E, L, B, F>::update(Quota &quota, E v, mword o, E p, mword a, Type t, 
        Queue<Cow_field> *cow_field, bool is_cowed) {
    unsigned long l = o / B, n = 1UL << o % B, s;

    P *e = walk(quota, v, l, t == TYPE_UP);

    if (!e)
        return false;
    
    if (a) {
        p |= P::order (o % B) | (l ? P::PTE_S : 0) | a;
        s = 1UL << (l * B + PAGE_BITS);
    } else
        p = s = 0;

    bool flush_tlb = false;

    for (unsigned long i = 0; i < n; e[i].val = p, i++, p += s, v += s) {
                                
        if(cow_field && !l)
            Cow_field::set_cow(cow_field, v, is_cowed);

        if (l && e[i].val != p)
            flush_tlb = true;

        if (!e[i].val)
            continue;

        if (t == TYPE_DF)
            continue;

        if (l && !e[i].super()) {
            // No need to delete cowfield because l is greater than 0 (-> big page)
            Pte::destroy(static_cast<P *> (Buddy::phys_to_ptr(e[i].addr())), quota);
            flush_tlb = true;
        }
    }

    if (F)
        flush(e, n * sizeof (E));

    return flush_tlb;
}

template <typename P, typename E, unsigned L, unsigned B, bool F>
void Pte<P, E, L, B, F>::clear(Quota &quota, bool (*d) (Paddr, mword, unsigned), 
        bool (*il) (unsigned, mword), Queue<Cow_field> *cf) {
    if (!val)
        return;

    P * e = static_cast<P *> (Buddy::phys_to_ptr(this->addr()));

    e->free_up(quota, L - 1, e, 0, d, il, cf);

    Pte::destroy(e, quota); // No need to delete cow_field for the first level entry
}

template <typename P, typename E, unsigned L, unsigned B, bool F>
void Pte<P, E, L, B, F>::free_up(Quota &quota, unsigned l, P * e, mword v, 
        bool (*d)(Paddr, mword, unsigned), bool (*il) (unsigned, mword), Queue<Cow_field> *cf) {
    if (!e)
        return;

    for (unsigned long i = 0; i < (1 << B); i++) {
        if (!e[i].val || e[i].super())
            continue;

        P *p = static_cast<P *> (Buddy::phys_to_ptr(e[i].addr()));
        mword virt = v + (i << (l * B + PAGE_BITS));

        if (il ? il(l, virt) : l > 1)
            p->free_up(quota, l - 1, p, virt, d, il);

        if (!d || d(e[i].addr(), virt, l))
            Pte::destroy(p, quota, virt, cf);
    }
}

template <typename P, typename E, unsigned L, unsigned B, bool F>
P *Pte<P,E,L,B,F>::cow_walk (E v) {
    unsigned long l = L;

    for (P *e = static_cast<P *>(this);; e = static_cast<P *>(Buddy::phys_to_ptr (e->addr())) + (v >> (--l * B + PAGE_BITS) & ((1UL << B) - 1))) {

        if (!e->val) {
            return nullptr;
        }
        
        if (l == 0)
            return e;
    }
}

template class Pte<Dpt, uint64, 4, 9, true>;
template class Pte<Ept, uint64, 4, 9, false>;
template class Pte<Hpt, mword, PTE_LEV, PTE_BPL, false>;

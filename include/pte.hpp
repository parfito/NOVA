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

#pragma once

#include "atomic.hpp"
#include "buddy.hpp"
#include "x86.hpp"
#include "cow_field.hpp"
/**
 * P: Type (Hpt, Dpt or Ept)
 * E: length (mword (64 bits or 32 bits)
 * L: level (3 or 4)
 * B: base page length (offset length: 10 for 32 bits (L = 3) or 9 for 64 bits (L = 4))
 * 
 * |**********|**********|************|
 * P = Hpt
 * E = 32 bits (mword)
 * L = 3
 * B = 10  
 */
template <typename P, typename E, unsigned L, unsigned B, bool F>
class Pte {
protected:
    E val;

    P *walk(Quota &quota, E, unsigned long, bool = true);

    ALWAYS_INLINE
    inline bool present() const { return val & P::PTE_P; }

    ALWAYS_INLINE
    inline bool super() const { return val & P::PTE_S; }

    ALWAYS_INLINE
    inline mword attr() const { return static_cast<mword>(val) & PAGE_MASK; }

    ALWAYS_INLINE
    inline Paddr addr() const { return static_cast<Paddr>(val) & ~((1UL << order()) - 1); }

    ALWAYS_INLINE
    inline mword order() const { return PAGE_BITS; }

    ALWAYS_INLINE
    static inline mword order (mword) { return 0; }

    ALWAYS_INLINE
    inline bool set (E o, E v)
    {
        bool b = Atomic::cmp_swap (val, o, v);

        if (F && b)
            flush(this);

        return b;
    }

    ALWAYS_INLINE
    static inline void *operator new (size_t, Quota &quota) {
        void *p = Buddy::allocator.alloc(0, quota, Buddy::FILL_0);

        if (F)
            flush(p, PAGE_SIZE);

        return p;
    }

    ALWAYS_INLINE
    static inline void destroy(Pte *obj, Quota &quota, mword v = ~0ull, Queue<Cow_field> *cf = nullptr) { 
        if(cf) {
            assert(v != ~0ull);
            Cow_field::set_cow(cf, v, false);
        }
        obj->~Pte(); 
        Buddy::allocator.free (reinterpret_cast<mword>(obj), quota); 
    }

    void free_up(Quota &quota, unsigned l, P *, mword, bool (*) (Paddr, mword, unsigned), bool (*) (unsigned, mword), Queue<Cow_field>* = nullptr);

public:

        Pte() : val(0) {}

    enum {
        ERR_P = 1UL << 0,
        ERR_W = 1UL << 1,
        ERR_U = 1UL << 2,
    };

    enum Type {
        TYPE_UP,
        TYPE_DN,
        TYPE_DF,
    };

    ALWAYS_INLINE
    static inline unsigned bpl() { return B; }

    ALWAYS_INLINE
    static inline unsigned max() { return L; }

    ALWAYS_INLINE
    inline E root (Quota &quota, mword l = L - 1) { return Buddy::ptr_to_phys (walk (quota, 0, l)); }

    size_t lookup(E, Paddr &, mword &);

    bool update(Quota &quota, E, mword, E, mword, Type = TYPE_UP, Queue<Cow_field>* = nullptr, bool = false);

    void clear(Quota &quota, bool (*) (Paddr, mword, unsigned) = nullptr, bool (*) (unsigned, mword) = nullptr, Queue<Cow_field>* = nullptr);

    bool check(Quota_guard &qg, mword o) {
        return qg.check(o / (4096 / sizeof (E)) + L);
    }
    
    void print_walk(Quota &quota, E, mword);
    
    bool pub_super() const { return val & P::PTE_S; };
    
    size_t cow_walk (E, Paddr&, mword&, P*&);
        
};

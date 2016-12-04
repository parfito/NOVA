/*
 * Protection Domain
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

#include "crd.hpp"
#include "space_mem.hpp"
#include "space_obj.hpp"
#include "space_pio.hpp"
#include "cow.hpp"

class Pd : public Kobject, public Refcount, public Space_mem, public Space_pio, public Space_obj {
private:
    static Slab_cache cache;

    WARN_UNUSED_RESULT
    mword clamp(mword, mword &, mword, mword);

    WARN_UNUSED_RESULT
    mword clamp(mword &, mword &, mword, mword, mword);

    static void pre_free(Rcu_elem * a) {
        Pd * pd = static_cast<Pd *> (a);

        Crd crd(Crd::MEM);
        pd->revoke<Space_mem>(crd.base(), crd.order(), crd.attr(), true, false);

        crd = Crd(Crd::PIO);
        pd->revoke<Space_pio>(crd.base(), crd.order(), crd.attr(), true, false);

        crd = Crd(Crd::OBJ);
        pd->revoke<Space_obj>(crd.base(), crd.order(), crd.attr(), true, false);
    }

    static void free(Rcu_elem * a) {
        Pd * pd = static_cast<Pd *> (a);

        if (pd->del_ref()) {
            assert(pd != Pd::current);
            delete pd;
        }
    }

public:
    static Pd *current CPULOCAL_HOT;
    static Pd kern, root;

    Quota quota;
    Paddr io_remap1, io_remap2;

    /*--------Copy on write treatement--------*/
    Cow::cow_elt *cow_list = nullptr;
    Spinlock cow_lock;

    INIT
    Pd(Pd *);
    ~Pd();

    Pd(Pd *own, mword sel, mword a);

    ALWAYS_INLINE HOT
    inline void make_current() {
        mword pcid = did;

        if (EXPECT_FALSE(htlb.chk(Cpu::id)))
            htlb.clr(Cpu::id);

        else {

            if (EXPECT_TRUE(current == this))
                return;

            if (pcid != NO_PCID)
                pcid |= static_cast<mword> (1ULL << 63);
        }

        Pd * del_pd = nullptr;
        if (current->del_ref()) {
            assert(current != this);
            del_pd = current;
        }

        current = this;

        current->add_ref();

        loc[Cpu::id].make_current(Cpu::feature(Cpu::FEAT_PCID) ? pcid : 0);

        if (del_pd)
            delete del_pd;
    }

    ALWAYS_INLINE
    static inline Pd *remote(unsigned c) {
        return *reinterpret_cast<volatile typeof current *> (reinterpret_cast<mword> (&current) - CPU_LOCAL_DATA + HV_GLOBAL_CPUS + c * PAGE_SIZE);
    }

    ALWAYS_INLINE
    inline Space *subspace(Crd::Type t) {
        switch (t) {
            case Crd::MEM: return static_cast<Space_mem *> (this);
            case Crd::PIO: return static_cast<Space_pio *> (this);
            case Crd::OBJ: return static_cast<Space_obj *> (this);
        }

        return nullptr;
    }

    template <typename>
    bool delegate(Pd *, mword, mword, mword, mword, mword = 0, char const * = nullptr);
    bool chunk_delegate(Pd *, mword, mword, mword, mword, mword = 0);
    template <typename>
    void revoke(mword, mword, mword, bool, bool);

    void xfer_items(Pd *, Crd, Crd, Xfer *, Xfer *, unsigned long);

    void xlt_crd(Pd *, Crd, Crd &);
    void del_crd(Pd *, Crd, Crd &, mword = 0, mword = 0);
    void rev_crd(Crd, bool, bool, bool);

    ALWAYS_INLINE
    static inline void *operator new (size_t, Quota &quota) {
        return cache.alloc(quota);
    }

    ALWAYS_INLINE
    static inline void operator delete (void *ptr) {
        Pd *pd_del = static_cast<Pd *> (ptr);
        Pd *pd_to = static_cast<Pd *> (static_cast<Space_obj *> (pd_del->space));

        pd_del->quota.free_up(pd_to->quota);

        cache.free(ptr, pd_to->quota);
    }
    
    Cow::cow_elt* find_cow_elt(mword gpa);
    bool is_mapped_elsewhere(Paddr phys, Cow::cow_elt* cow);
    void add_cow(Cow::cow_elt *ce);
    Cow::cow_elt* cowlist_contains(mword, Paddr);
    bool compare_and_commit();
    void restore_state();
    void rollback();
    
};

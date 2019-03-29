/*
 * Memory Space
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

#include "counter.hpp"
#include "hazards.hpp"
#include "hip.hpp"
#include "lapic.hpp"
#include "mtrr.hpp"
#include "pd.hpp"
#include "stdio.hpp"
#include "svm.hpp"
#include "vectors.hpp"

mword Space_mem::did_c [4096 / 8 / sizeof(mword)];
mword Space_mem::did_f = 0;

void Space_mem::init (Quota &quota, unsigned cpu)
{
    if (cpus.set (cpu)) {
        loc[cpu].sync_from (quota, Pd::kern.loc[cpu], CPU_LOCAL, SPC_LOCAL);
        loc[cpu].sync_master_range (quota, LINK_ADDR, CPU_LOCAL);
    }
}

bool Space_mem::update (Quota_guard &quota, Mdb *mdb, mword r)
{
    assert (this == mdb->space && this != &Pd::kern);

    Lock_guard <Spinlock> guard (mdb->node_lock);

    Paddr p = mdb->node_phys << PAGE_BITS;
    mword b = mdb->node_base << PAGE_BITS;
    mword o = mdb->node_order;
    mword a = mdb->node_attr & ~r;
    mword s = mdb->node_sub;

    if (s & 1 && Dpt::ord != ~0UL) {
        mword ord = min (o, Dpt::ord);
        for (unsigned long i = 0; i < 1UL << (o - ord); i++) {
            if (!r && !dpt.check(quota, ord)) {
                Cpu::hazard |= HZD_OOM;
                return false;
            }

            dpt.update (quota, b + i * (1UL << (ord + PAGE_BITS)), ord, p + i * (1UL << (Dpt::ord + PAGE_BITS)), a, r ? Dpt::TYPE_DN : Dpt::TYPE_UP);
        }
    }

    if (s & 2) {
        if (Vmcb::has_npt()) {
            mword ord = min (o, Hpt::ord);
            for (unsigned long i = 0; i < 1UL << (o - ord); i++) {
                if (!r && !npt.check(quota, ord)) {
                    Cpu::hazard |= HZD_OOM;
                    return false;
                }

                npt.update (quota, b + i * (1UL << (ord + PAGE_BITS)), ord, p + i * (1UL << (ord + PAGE_BITS)), Hpt::hw_attr (a), r ? Hpt::TYPE_DN : Hpt::TYPE_UP);
            }
        } else {
            mword ord = min (o, Ept::ord);
            trace (TRACE_EPT, "EPT update p:%#010lx b:%#010lx o:%#lx, a:%#lx s:%#lx", p, b, o, a, s);
            for (unsigned long i = 0; i < 1UL << (o - ord); i++) {
                if (!r && !ept.check(quota, ord)) {
                    Cpu::hazard |= HZD_OOM;
                    return false;
                }

                if(ord < Ept::bpl())
                    ept.update (quota, b + i * (1UL << (ord + PAGE_BITS)), ord, p + i * (1UL << (ord + PAGE_BITS)), Ept::hw_attr (a, mdb->node_type), r ? Ept::TYPE_DN : Ept::TYPE_UP);
                else{
                    mword max_ord = ord - Ept::bpl() + 1;
                    for(unsigned long j = 0; j < 1UL << max_ord; j++)
                        ept.update (quota, b + i * (1UL << (ord + PAGE_BITS)) + j * (1UL << (Ept::bpl() + PAGE_BITS - 1)), Ept::bpl() - 1, p + i * (1UL << (ord + PAGE_BITS)) + j * (1UL << (Ept::bpl() + PAGE_BITS - 1)), Ept::hw_attr (a, mdb->node_type), r ? Ept::TYPE_DN : Ept::TYPE_UP);
                }            
            }
        }
        if (r)
            gtlb.merge (cpus);
    }

    if (s & 4) {
        if (a)
            a |= Hpt::HPT_PWT;
    }


    if ((mdb->node_base >= USER_ADDR >> PAGE_BITS) ||
        (mdb->node_base + (1UL << o) > USER_ADDR >> PAGE_BITS) ||
        (mdb->node_base + (1UL << o) <= mdb->node_base))
        return false;

    mword ord = min (o, Hpt::ord);
    bool f = false;

    for (unsigned long i = 0; i < 1UL << (o - ord); i++) {
        if (!r && !hpt.check(quota, ord)) {
            Cpu::hazard |= HZD_OOM;
            return f;
        }

        if(ord < Hpt::bpl() || !(a & Hpt::HPT_W))
            f |= hpt.update (quota, b + i * (1UL << (ord + PAGE_BITS)), ord, p + i * (1UL << (ord + PAGE_BITS)), Hpt::hw_attr (a), r ? Hpt::TYPE_DN : Hpt::TYPE_UP);
        else{
            mword max_ord = ord - Hpt::bpl() + 1;
            for(unsigned long j = 0; j < 1UL << max_ord; j++)
                f |= hpt.update (quota, b + i * (1UL << (ord + PAGE_BITS)) + j * (1UL << (Hpt::bpl() + PAGE_BITS - 1)), Hpt::bpl() - 1, p + i * (1UL << (ord + PAGE_BITS)) + j * (1UL << (Hpt::bpl() + PAGE_BITS - 1)), Hpt::hw_attr (a), r ? Hpt::TYPE_DN : Hpt::TYPE_UP);
        }
    }

    if (r || f) {

        for (unsigned j = 0; j < sizeof (loc) / sizeof (*loc); j++) {
            if (!loc[j].addr())
                continue;

            for (unsigned long i = 0; i < 1UL << (o - ord); i++) {
                if (!r && !loc[j].check(quota, ord)) {
                    Cpu::hazard |= HZD_OOM;
                    return (r || f);
                }

                if(ord < Hpt::bpl() || !(a & Hpt::HPT_W))
                    loc[j].update (quota, b + i * (1UL << (ord + PAGE_BITS)), ord, p + i * (1UL << (ord + PAGE_BITS)), Hpt::hw_attr (a), Hpt::TYPE_DF);
                else{
                    mword max_ord = ord - Hpt::bpl() + 1;
                    for(unsigned long k = 0; k < 1UL << max_ord; k++)
                        loc[j].update (quota, b + i * (1UL << (ord + PAGE_BITS)) + k * (1UL << (Hpt::bpl() + PAGE_BITS - 1)), Hpt::bpl() - 1, p + i * (1UL << (ord + PAGE_BITS)) + k * (1UL << (Hpt::bpl() + PAGE_BITS - 1)), Hpt::hw_attr (a), Hpt::TYPE_DF);
                }
            }
        }

        htlb.merge (cpus);
    }

    return (r || f);
}

void Space_mem::shootdown(Pd * local)
{
    for (unsigned cpu = 0; cpu < NUM_CPU; cpu++) {

        if (!Hip::cpu_online (cpu))
            continue;

        if (!local->cpus.chk(cpu))
            continue;

        Pd *pd = Pd::remote (cpu);

        if (!pd->htlb.chk (cpu) && !pd->gtlb.chk (cpu))
            continue;

        if (Cpu::id == cpu) {
            Cpu::hazard |= HZD_SCHED;
            continue;
        }

        unsigned ctr = Counter::remote (cpu, 1);

        Lapic::send_ipi (cpu, VEC_IPI_RKE);

        if (!Cpu::preemption)
            asm volatile ("sti" : : : "memory");

        while (Counter::remote (cpu, 1) == ctr)
            pause();

        if (!Cpu::preemption)
            asm volatile ("cli" : : : "memory");
    }
}

void Space_mem::insert_root (Quota &quota, Slab_cache &cache, uint64 s, uint64 e, mword a)
{
    for (uint64 p = s; p < e; s = p) {

        unsigned t = Mtrr::memtype (s, p);

        for (uint64 n; p < e; p = n)
            if (Mtrr::memtype (p, n) != t)
                break;

        if (s > ~0UL)
            break;

        if ((p = min (p, e)) > ~0UL)
            p = static_cast<uint64>(~0UL) + 1;

        addreg (quota, cache, static_cast<mword>(s >> PAGE_BITS), static_cast<mword>(p - s) >> PAGE_BITS, a, t);
    }
}

static void free_mdb(Rcu_elem * e)
{
    Mdb       *mdb   = static_cast<Mdb *>(e);
    Space_mem *space = static_cast<Space_mem *>(mdb->space);
    Pd        *pd    = static_cast<Pd *>(space);

    Mdb::destroy (mdb, pd->quota, pd->mdb_cache);
}

bool Space_mem::insert_utcb (Quota &quota, Slab_cache &cache, mword b, mword phys)
{
    if (!phys)
       return true;

    if (!b)
        return true;

    Mdb *mdb = new (quota, cache) Mdb (this, free_mdb, phys, b >> PAGE_BITS, 0, 0x3);

    if (tree_insert (mdb))
        return true;

    Mdb::destroy (mdb, quota, cache);

    return false;
}

bool Space_mem::remove_utcb (mword b)
{
    if (!b)
        return false;

    Mdb *mdb = tree_lookup(b >> PAGE_BITS, false);
    if (!mdb)
        return false;

    mdb->demote_node(0x3);

    if (mdb->remove_node() && tree_remove(mdb)) {
        Rcu::call (mdb);
        return true;
    }

    return false;
}

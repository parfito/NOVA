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

#include "mtrr.hpp"
#include "pd.hpp"
#include "stdio.hpp"
#include "hip.hpp"
#include "ec.hpp"

INIT_PRIORITY(PRIO_SLAB)
Slab_cache Pd::cache(sizeof (Pd), 32);

Pd *Pd::current;

INIT_PRIORITY(PRIO_BUDDY)
ALIGNED(32) Pd Pd::kern(&Pd::kern);
ALIGNED(32) Pd Pd::root(&Pd::root, NUM_EXC, 0x1f);

const char *Pd::names[] = {"root", "init", "init -> timer", "init -> rtc_drv", "init -> ps2_drv", "init -> acpi_drv",
    "init -> acpi_report_rom", "init -> platform_drv", "init -> nic_drv", "init -> fb_drv",
    "init -> seoul", "init -> platform_drv -> nic_drv", nullptr};

Pd::Pd(Pd *own) : Kobject(PD, static_cast<Space_obj *> (own)) {
    copy_string(name, const_cast<char* const> ("kern_pd"));
    hpt = Hptp(reinterpret_cast<mword> (&PDBR));

    Mtrr::init();

    Space_mem::insert_root(own->quota, 0, reinterpret_cast<mword> (&LINK_P));
    Space_mem::insert_root(own->quota, reinterpret_cast<mword> (&LINK_E), 1ULL << 52);

    // HIP
    Space_mem::insert_root(own->quota, reinterpret_cast<mword> (&FRAME_H), reinterpret_cast<mword> (&FRAME_H) + PAGE_SIZE, 1);

    // I/O Ports
    Space_pio::addreg(own->quota, 0, 1UL << 16, 7);
}

Pd::Pd(Pd *own, mword sel, mword a, char* const s) : Kobject(PD, static_cast<Space_obj *> (own), sel, a, free, pre_free) {
    if (this == &Pd::root) {
        copy_string(name, const_cast<char* const> ("root"));
        bool res = Quota::init.transfer_to(quota, Quota::init.limit());
        assert(res);
    } else {
        copy_string(name, s);
    }
    set_to_be_cowed();
}

template <typename S>
static void free_mdb(Rcu_elem * e) {
    Mdb *mdb = static_cast<Mdb *> (e);
    Pd *pd = &Pd::root;

    if (!mdb->invalid()) {
        S *space = static_cast<S *> (mdb->space);
        pd = static_cast<Pd *> (space);
    }

    Mdb::destroy(mdb, pd->quota);
}

template <typename S>
bool Pd::delegate(Pd *snd, mword const snd_base, mword const rcv_base, mword const ord, mword const attr, mword const sub, char const * deltype) {
    bool s = false;

    Quota_guard qg(this->quota);

    Mdb *mdb;
    for (mword addr = snd_base; (mdb = snd->S::tree_lookup(addr, true)); addr = mdb->node_base + (1UL << mdb->node_order)) {

        mword o, b = snd_base;
        if ((o = clamp(mdb->node_base, b, mdb->node_order, ord)) == ~0UL)
            break;

        if (quota.hit_limit(1)) {
            Cpu::hazard |= HZD_OOM;
            return s;
        }

        Mdb *node = new (qg) Mdb(static_cast<S *> (this), free_mdb<S>, b - mdb->node_base + mdb->node_phys, b - snd_base + rcv_base, o, 0, mdb->node_type, S::sticky_sub(mdb->node_sub) | sub);

        if (!S::tree_insert(node)) {
            Mdb::destroy(node, qg);

            Mdb * x = S::tree_lookup(b - snd_base + rcv_base);
            if (!x || x->prnt != mdb || x->node_attr != attr)
                trace(0, "overmap attempt %s - tree - PD:%p->%p SB:%#010lx RB:%#010lx O:%#04lx A:%#lx SUB:%lx", deltype, snd, this, snd_base, rcv_base, ord, attr, sub);

            continue;
        }

        if (!node->insert_node(mdb, attr)) {
            S::tree_remove(node);
            Mdb::destroy(node, qg);
            trace(0, "overmap attempt %s - node - PD:%p->%p SB:%#010lx RB:%#010lx O:%#04lx A:%#lx SUB:%lx", deltype, snd, this, snd_base, rcv_base, ord, attr, sub);
            continue;
        }
        s |= S::update(qg, node, to_be_cowed);

        if (Cpu::hazard & HZD_OOM) {
            S::update(qg, node, to_be_cowed, attr);
            node->demote_node(attr);
            if (node->remove_node() && S::tree_remove(node))
                Rcu::call(node);
            return s;
        }
    }

    if (!qg.check(0))
        Cpu::hazard |= HZD_OOM;

    return s;
}

template <typename S>
void Pd::revoke(mword const base, mword const ord, mword const attr, bool self, bool kim) {
    Mdb *mdb;
    for (mword addr = base; (mdb = S::tree_lookup(addr, true)); addr = mdb->node_base + (1UL << mdb->node_order)) {

        mword o, p, b = base;
        if ((o = clamp(mdb->node_base, b, mdb->node_order, ord)) == ~0UL)
            break;

        /* keep in mapping database if requested and at least one child node exists */
        if (kim && (ACCESS_ONCE(mdb->next)->dpth > mdb->dpth)) {
            Quota_guard qg(this->quota);
            if (mdb->node_attr & 0x1f) {
                static_cast<S *> (mdb->space)->update(qg, mdb, this->get_name(), 0x1f);
                mdb->demote_node(0x1f);
            }
            static_cast<S *> (mdb->space)->tree_remove(mdb, Avl::State::KIM);
            continue;
        }

        Mdb *node = mdb;

        unsigned d = node->dpth;
        bool demote = false;

        for (Mdb *ptr;; node = ptr) {

            if (node->dpth == d + !self)
                demote = clamp(node->node_phys, p = b - mdb->node_base + mdb->node_phys, node->node_order, o) != ~0UL;

            if (demote && node->node_attr & attr) {
                Quota_guard qg(this->quota);
                static_cast<S *> (node->space)->update(qg, node, this->get_name(), attr);
                node->demote_node(attr);
            }

            ptr = ACCESS_ONCE(node->next);

            if (ptr->dpth <= d)
                break;
        }

        Mdb *x = ACCESS_ONCE(node->next);
        assert(x->dpth <= d || (x->dpth == node->dpth + 1 && !(x->node_attr & attr)));

        bool preempt = Cpu::preemption;

        for (Mdb *ptr;; node = ptr) {

            if (preempt)
                Cpu::preempt_disable();

            if (node->remove_node() && static_cast<S *> (node->space)->tree_remove(node))
                Rcu::call(node);

            if (preempt)
                Cpu::preempt_enable();

            ptr = ACCESS_ONCE(node->prev);

            if (node->dpth <= d)
                break;
        }

        assert(node == mdb);
    }
}

mword Pd::clamp(mword snd_base, mword &rcv_base, mword snd_ord, mword rcv_ord) {
    if ((snd_base ^ rcv_base) >> max(snd_ord, rcv_ord))
        return ~0UL;

    rcv_base |= snd_base;

    return min(snd_ord, rcv_ord);
}

mword Pd::clamp(mword &snd_base, mword &rcv_base, mword snd_ord, mword rcv_ord, mword h) {
    assert(snd_ord < sizeof (mword) * 8);
    assert(rcv_ord < sizeof (mword) * 8);

    mword s = (1ul << snd_ord) - 1;
    mword r = (1ul << rcv_ord) - 1;

    snd_base &= ~s;
    rcv_base &= ~r;

    if (EXPECT_TRUE(s < r)) {
        rcv_base |= h & r & ~s;
        return snd_ord;
    } else {
        snd_base |= h & s & ~r;
        return rcv_ord;
    }
}

void Pd::xlt_crd(Pd *pd, Crd xlt, Crd &crd) {
    Crd::Type t = xlt.type();

    if (t && t == crd.type()) {

        Space *snd = pd->subspace(t), *rcv = subspace(t);
        mword sb = crd.base(), so = crd.order(), rb = xlt.base(), ro = xlt.order();
        Mdb *mdb, *node;

        for (node = mdb = snd->tree_lookup(sb); node; node = node->prnt)
            if (node->space == rcv && node != mdb && node->accessible())
                if ((ro = clamp(node->node_base, rb, node->node_order, ro)) != ~0UL)
                    break;

        if (!node) {
            /* Special handling on Genode:
             * If a translate of an item inside the same PD (receiver/sender in same PD)
             * are of no success, then return the very same item.
             */
            Mdb *first = snd->tree_lookup(crd.base());
            if (first && first->space == rcv && first == mdb) {
                rb = xlt.base();
                ro = xlt.order();
                if ((ro = clamp(first->node_base, rb, first->node_order, ro)) != ~0UL)
                    node = first;
            }
        }

        if (node) {

            so = clamp(mdb->node_base, sb, mdb->node_order, so);
            sb = (sb - mdb->node_base) + (mdb->node_phys - node->node_phys) + node->node_base;

            if ((ro = clamp(sb, rb, so, ro)) != ~0UL) {
                trace(TRACE_DEL, "XLT OBJ PD:%p->%p SB:%#010lx RB:%#010lx O:%#04lx", pd, this, crd.base(), rb, so);
                crd = Crd(crd.type(), rb, ro, mdb->node_attr);
                return;
            }
        }
    }

    crd = Crd(0);
}

bool Pd::chunk_delegate(Pd* pd, mword sb, mword rb, mword ord, mword a, mword sub) {
//    if (ord < (sub & 2 ? 9 : 10)) {//if sub & 2 == 1: ept or npt mapping, else hpt mapping 
    if (ord < Hpt::bpl()) {//Seoul allocate 2M pages if ord = Hpt::bpl(), we must construct 2M cow page before allowing this
        bool s = delegate<Space_mem>(pd, sb, rb, ord, a, sub, "MEM");
        //        Console::print("s in chunk %d", s);
        return s;
    } else {
        ord--;
        uint32 trans = 1U << ord;
        bool chunk1 = chunk_delegate(pd, sb, rb, ord, a, sub);
        bool chunk2 = chunk_delegate(pd, sb + trans, rb + trans, ord, a, sub);
        /*TODO
         * We must later handle when some succeed and other fail */
        return ( chunk1 || chunk2); // because delegate return 0 if ok
    }
}

void Pd::del_crd(Pd *pd, Crd del, Crd &crd, mword sub, mword hot) {
    Crd::Type st = crd.type(), rt = del.type();
    bool s = false;

    mword a = crd.attr() & del.attr(), sb = crd.base(), so = crd.order(), rb = del.base(), ro = del.order(), o = 0;

    if (EXPECT_FALSE(st != rt || !a)) {
        crd = Crd(0);
        return;
    }

    switch (rt) {

        case Crd::MEM:
            o = clamp(sb, rb, so, ro, hot);
            trace(TRACE_DEL, "DEL MEM PD:%p->%p SB:%#010lx RB:%#010lx O:%#04lx A:%#lx", pd, this, sb, rb, o, a);
            s = delegate<Space_mem>(pd, sb, rb, o, a, sub);
            break;

        case Crd::PIO:
            o = clamp(sb, rb, so, ro);
            trace(TRACE_DEL, "DEL I/O PD:%p->%p SB:%#010lx RB:%#010lx O:%#04lx A:%#lx", pd, this, rb, rb, o, a);
            delegate<Space_pio>(pd, rb, rb, o, a, sub, "PIO");
            break;

        case Crd::OBJ:
            o = clamp(sb, rb, so, ro, hot);
            trace(TRACE_DEL, "DEL OBJ PD:%p->%p SB:%#010lx RB:%#010lx O:%#04lx A:%#lx", pd, this, sb, rb, o, a);
            delegate<Space_obj>(pd, sb, rb, o, a, 0, "OBJ");
            break;
    }

    crd = Crd(rt, rb, o, a);

    if (s)
        shootdown();
}

void Pd::rev_crd(Crd crd, bool self, bool preempt, bool kim) {
    if (preempt)
        Cpu::preempt_enable();

    switch (crd.type()) {

        case Crd::MEM:
            trace(TRACE_REV, "REV MEM PD:%p B:%#010lx O:%#04x A:%#04x %s", this, crd.base(), crd.order(), crd.attr(), self ? "+" : "-");
            revoke<Space_mem>(crd.base(), crd.order(), crd.attr(), self, kim);
            break;

        case Crd::PIO:
            trace(TRACE_REV, "REV I/O PD:%p B:%#010lx O:%#04x A:%#04x %s", this, crd.base(), crd.order(), crd.attr(), self ? "+" : "-");
            revoke<Space_pio>(crd.base(), crd.order(), crd.attr(), self, kim);
            break;

        case Crd::OBJ:
            trace(TRACE_REV, "REV OBJ PD:%p B:%#010lx O:%#04x A:%#04x %s", this, crd.base(), crd.order(), crd.attr(), self ? "+" : "-");
            revoke<Space_obj>(crd.base(), crd.order(), crd.attr(), self, kim);
            break;
    }

    if (preempt)
        Cpu::preempt_disable();

    if (crd.type() == Crd::MEM)
        shootdown();
}

void Pd::xfer_items(Pd *src, Crd xlt, Crd del, Xfer *s, Xfer *d, unsigned long ti) {
    mword set_as_del;

    for (Crd crd; ti--; s--) {

        crd = *s;
        set_as_del = 0;

        switch (s->flags() & 3) {

            case 0:
                xlt_crd(src, xlt, crd);
                break;

            case 2:
                xlt_crd(src, xlt, crd);
                if (crd.type()) break;

                crd = *s;
                set_as_del = 1;

            case 1:
            {
                bool r = src == &root && s->flags() & 0x800;
                del_crd(r ? &kern : src, del, crd, (s->flags() >> 8) & (r ? 7 : 3), s->hotspot());
                if (Cpu::hazard & HZD_OOM)
                    return;
                break;
            }
            default:
                crd = Crd(0);

        };

        if (d)
            *d-- = Xfer(crd, s->flags() | set_as_del);
    }
}

void Pd::add_cow(Cow::cow_elt *ce) {
    Lock_guard <Spinlock> guard(cow_lock);
    Cow::cow_elt *tampon = cow_list;
    cow_list = ce;
    ce->next = tampon;
}

Cow::cow_elt* Pd::cowlist_contains(mword addr, Paddr phys) {
    phys = phys & ~PAGE_MASK;
    addr = addr & ~PAGE_MASK;
    Lock_guard <Spinlock> guard(cow_lock);
    Cow::cow_elt *c = cow_list;
    while (c != nullptr) {
        if (c->page_addr_or_gpa == addr && c->old_phys == phys)
            return c;
        c = c->next;
    }
    return nullptr;
}

bool Pd::is_mapped_elsewhere(Paddr phys, Cow::cow_elt* cow) {
    Lock_guard <Spinlock> guard(cow_lock);
    bool is_mapped = false;
    Cow::cow_elt *c = cow_list;
    while ((c != nullptr) && (c != cow)) {
        if (c->old_phys == phys) {//frame already mapped elsewhere
            cow->old_phys = phys;
            cow->new_phys[0] = c->new_phys[0];
            cow->new_phys[1] = c->new_phys[1];
            is_mapped = true;
        }
        if (c->new_phys[0] && c->new_phys[0]->phys_addr == phys) {//mapping created before subtitute(v)
            cow->old_phys = c->old_phys;
            cow->new_phys[0] = c->new_phys[0];
            cow->new_phys[1] = c->new_phys[1];
            is_mapped = true;
        }

        c = c->next;
    }
    if (is_mapped)
        return true;
    else
        return false;
}

Cow::cow_elt* Pd::find_cow_elt(mword gpa) {
    int n = 0;
    Lock_guard <Spinlock> guard(cow_lock);
    Cow::cow_elt *c = cow_list, *result = nullptr;
    while (c != nullptr) {
        if (c->old_phys == (gpa & ~PAGE_MASK)) {
            result = c;
            n++;
        }
    }
    if (n != 1) {
        Ec::die("Cow elt not find");
        Console::print("Cow elt not find");
    }
    return result;
}

void Pd::restore_state() {
    Lock_guard <Spinlock> guard(cow_lock);
    Cow::cow_elt *cow = cow_list;
    Quota q = this->quota;
    while (cow != nullptr) {
        mword v = cow->page_addr_or_gpa;
        loc[Cpu::id].replace_cow(q, v, cow->new_phys[1]->phys_addr | (cow->attr & ~Hpt::HPT_W));
//        Hpt::cow_flush(v);
        cow = cow->next;
    }
}

void Pd::restore_state1() {
    Lock_guard <Spinlock> guard(cow_lock);
    Cow::cow_elt *cow = cow_list;
    Quota q = this->quota;
    while (cow != nullptr) {
        mword v = cow->page_addr_or_gpa;
        loc[Cpu::id].replace_cow(q, v, cow->new_phys[0]->phys_addr | (cow->attr & ~Hpt::HPT_W));
//        Hpt::cow_flush(v);
        cow = cow->next;
    }
}

void Pd::rollback(bool is_vm) {
    Lock_guard <Spinlock> guard(cow_lock);
    Cow::cow_elt *cow = cow_list;
    Quota q = this->quota;
    if(is_vm){
        while (cow != nullptr) {
            *(cow->vtlb_entry) = cow->old_phys|(cow->attr & ~Hpt::HPT_W);
            Cow::free_cow_elt(cow);
            cow = cow->next;
        }
    }else{
        while (cow != nullptr) {
            Paddr old_phys = cow->old_phys;
            mword v = cow->page_addr_or_gpa;
            loc[Cpu::id].replace_cow(q, v, old_phys|(cow->attr & ~Hpt::HPT_W));
            Hpt::cow_flush(v);
            Cow::free_cow_elt(cow);
            cow = cow->next;
        }
    }
}

void Pd::set_to_be_cowed(){    
    int i = 0; 
    while(names[i] != nullptr){
        if(!strcmp(name, names[i])){
            to_be_cowed = true;
            return;
        }
        i++;
    }
    to_be_cowed = false; 
}

bool Pd::compare_and_commit() {
    Lock_guard <Spinlock> guard(cow_lock);
    Cow::cow_elt *cow = cow_list;
    Quota q = this->quota;
    while (cow != nullptr) {
        //        Console::print("Compare v: %p  phys: %p  ce: %p  phys1: %p  phys2: %p", cow->page_addr_or_gpa, cow->old_phys, cow, cow->new_phys[0]->phys_addr, cow->new_phys[1]->phys_addr);
        mword *ptr1 = reinterpret_cast<mword*> (Hpt::remap_cow(q, cow->new_phys[0]->phys_addr)),
                *ptr2 = reinterpret_cast<mword*> (cow->page_addr_or_gpa);
        int missmatch_addr = memcmp(ptr1, ptr2, PAGE_SIZE);
        if (missmatch_addr) {
            mword index = PAGE_SIZE / 4 - missmatch_addr - 1;
            mword val1 = *(ptr1 + index);
            mword val2 = *(ptr2 + index);
            Console::print("Pd: %p  phys1 %lx phys2 %lx ptr1: %p  ptr2: %p  val1: %lx  val2: %lx  missmatch_addr: %p",
                    this, cow->new_phys[0]->phys_addr, cow->new_phys[1]->phys_addr, ptr1, ptr2, val1, val2, ptr2 + index);
            return true;
        }
        Paddr old_phys = cow->old_phys;
        mword v = cow->page_addr_or_gpa;
        void *ptr = Hpt::remap_cow(q, old_phys);
        memcpy(ptr, reinterpret_cast<const void*> (v), PAGE_SIZE);
        loc[Cpu::id].replace_cow(q, v, old_phys | (cow->attr & ~Hpt::HPT_W)); // the old frame may have been released; so we have to retain it
        Hpt::cow_flush(v);
        Cow::free_cow_elt(cow);
        cow = cow->next;
    }
    return false;
}

bool Pd::vtlb_compare_and_commit(){
    Lock_guard <Spinlock> guard(cow_lock);
    Cow::cow_elt *cow = cow_list;
    Quota q = this->quota;
    while (cow != nullptr) {
        //        Console::print("Compare v: %p  phys: %p  ce: %p  phys1: %p  phys2: %p", cow->page_addr_or_gpa, cow->old_phys, cow, cow->new_phys[0]->phys_addr, cow->new_phys[1]->phys_addr);
        mword *ptr1 = reinterpret_cast<mword*> (Hpt::remap_cow(q, cow->new_phys[0]->phys_addr)),
                *ptr2 = reinterpret_cast<mword*> (Hpt::remap_cow(q, cow->new_phys[1]->phys_addr, PAGE_SIZE));
        int missmatch_addr = memcmp(ptr1, ptr2, PAGE_SIZE);
        if (missmatch_addr) {
            mword index = PAGE_SIZE /sizeof(mword) - missmatch_addr * 4/sizeof(mword) - 1;
            mword val1 = *(ptr1 + index);
            mword val2 = *(ptr2 + index);
            Console::print("addr: %lx  phys1 %lx phys2 %lx ptr1: %p  ptr2: %p  val1: %lx  val2: %lx  missmatch_addr: %p mword size %ld",
                    cow->page_addr_or_gpa, cow->new_phys[0]->phys_addr, cow->new_phys[1]->phys_addr, ptr1, ptr2, val1, val2, ptr2 + index, sizeof(mword));
            return true;
        }
        void *ptr = Hpt::remap_cow(q, cow->old_phys);
        memcpy(ptr, ptr2, PAGE_SIZE);
        *(cow->vtlb_entry) = cow->old_phys|(cow->attr & ~Hpt::HPT_W);
        Cow::free_cow_elt(cow);
        cow = cow->next;
    }
    return false;
}

Pd::~Pd() {
    pre_free(this);

    Space_mem::hpt.clear(quota, Space_mem::hpt.dest_hpt, Space_mem::hpt.iter_hpt_lev);
    Space_mem::dpt.clear(quota);
    Space_mem::npt.clear(quota);
    for (unsigned cpu = 0; cpu < NUM_CPU; cpu++)
        if (Hip::cpu_online(cpu))
            Space_mem::loc[cpu].clear(quota, Space_mem::hpt.dest_loc, Space_mem::hpt.iter_loc_lev);
}

extern "C" int __cxa_atexit(void (*)(void *), void *, void *) {
    return 0;
}
void * __dso_handle = nullptr;

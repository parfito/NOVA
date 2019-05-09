/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Cow_elt.hpp
 * Author: parfait
 *
 * Created on 7 octobre 2018, 21:29
 */

#pragma once
#include "types.hpp"
#include "slab.hpp"
#include "compiler.hpp"
#include "queue.hpp"
#include "vtlb.hpp"
#include "hpt.hpp"
#include "pd.hpp"

class Cow_elt {
    friend class Queue<Cow_elt>;
    static Slab_cache cache;
    static Queue<Cow_elt> cow_elts;

public:

    enum Page_type {
        NORMAL,
        BIG_PAGE,
    };
    Cow_elt(mword, Paddr, mword, Page_type = NORMAL);
    Cow_elt(const Cow_elt& orig);
    ~Cow_elt();

    ALWAYS_INLINE
    static inline void *operator new (size_t, Quota &quota){return cache.alloc(quota);}

    ALWAYS_INLINE
    static inline void destroy(Cow_elt *obj, Quota &quota) {
        obj->~Cow_elt();
        cache.free(obj, quota);
    }

    ALWAYS_INLINE
    static inline void operator delete (void *ptr, Quota &quota) {
        Cow_elt* ce = static_cast<Cow_elt*> (ptr);
        ce->~Cow_elt();
        cache.free(ptr, quota);
    }

    Cow_elt &operator=(Cow_elt const &);

    static size_t get_number() { return number; }

    static void resolve_cow_fault(Vtlb*, Hpt*, mword virt, Paddr phys, mword attr);
    static bool is_mapped_elsewhere(Paddr, Cow_elt*);
    static void copy_frames(Cow_elt*, void*);
    static void remove_cow(Vtlb*, Hpt*, mword virt, Paddr phys, mword attr);

    static bool is_empty() {
        return !cow_elts.head();
    }
    static void restore_state();
    static bool compare();
    static void commit();
    static void restore_state1();
    static void rollback();
    
private:
    Page_type type;
    mword page_addr = {}; // if VM, this will hold the gla, else hold page addr
    Paddr old_phys = {};
    mword attr = {};
    Paddr new_phys[2];
    /*---These should moved to Pe class when it will be used -----*/
    Vtlb *vtlb = nullptr;
    Hpt *hpt = nullptr;
    /*------------------------------------------------------------*/
    void* linear_add = nullptr;
    Cow_elt *prev;
    Cow_elt *next;
    static size_t number;
};

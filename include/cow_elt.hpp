/* 
 * File:   cow_elt.hpp
 * Author: Parfait Tokponnon <mahoukpego.tokponnon@uclouvain.be>
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

class Cow_elt {
    friend class Queue<Cow_elt>;
    static Slab_cache cache;
    static Queue<Cow_elt> cow_elts;

public:

    enum Page_type {
        NORMAL,
        BIG_PAGE,
    };
    Cow_elt(mword, Paddr, mword, Page_type = NORMAL, mword = 0);
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

    static size_t get_number() { return cow_elts.size(); }

    static void resolve_cow_fault(Vtlb*, Hpt*, mword virt, Paddr phys, mword attr);
    static Cow_elt* is_mapped_elsewhere(Paddr);
    static void copy_frames(Paddr, Paddr, void*);
    static void remove_cow(Vtlb*, Hpt*, mword virt, Paddr phys, mword attr);

    static bool is_empty() {
        if(!cow_elts.head())
            assert(!current_ec_cow_elts_size);
        return !cow_elts.head();
    }
    static void restore_state0();
    static void restore_vm_stack_state0();
    static bool compare();
    static bool compare_vm_stack();
    static void commit();
    static void commit_vm_stack();
    static void commit_vm_stack_ce(Cow_elt*, uint32, mword*);
    static void restore_state1();
    static void restore_vm_stack_state1();
    static void rollback();
    static void rollback_vm_stack();
    static void place_phys0();
    static bool would_have_been_cowed_in_place_phys0(mword);
    static bool is_kernel_vm_modified();
    static void free(Cow_elt*);
    
private:
    Page_type type;
    mword page_addr = {}; // if VM, this will hold the gla, else hold page addr
    Paddr old_phys = {};
    mword attr = {};
    Paddr new_phys[2];
    mword ec_rip = 0, ec_rcx = 0, ec_rsp = 0, ec_rsp_content = 0, m_fault_addr = 0;
    uint32 crc = 0, crc1 = 0, not_pointed = 0;
    Cow_elt* v_is_mapped_elsewhere = nullptr;
    /*---These should moved to Pe class when it will be used -----*/
    Vtlb *vtlb = nullptr;
    Hpt *hpt = nullptr;
    /*------------------------------------------------------------*/
    void* linear_add = nullptr;
    Cow_elt *prev;
    Cow_elt *next;
    static size_t number, current_ec_cow_elts_size;
};

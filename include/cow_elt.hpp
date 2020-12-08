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
#include "ept.hpp"

class Cow_elt {
    friend class Queue<Cow_elt>;
    static Slab_cache cache;

private:
    enum Page_type {
        NORMAL,
        BIG_PAGE,
    };
    
    enum Physic {
        PHYS0 = 0, 
        PHYS1 = 1,
        PHYS2 = 2,
    };
    
    enum Pte_type {
        HPT     = 0,
        VTLB    = 1,
        EPT     = 2,
    };
    
    union {
        Vtlb *vtlb;
        Ept *ept;
        Hpt *hpt;
    };
    static const char *pte[3];
    static Queue<Cow_elt> *cow_elts;
    Pte_type pte_type;
    Page_type type;
    mword page_addr = 0; // if VM, this will hold the gla, else hold page addr
    mword attr = 0;
    Paddr phys_addr[3];
    mword ec_rip = 0, ec_rax = 0, ec_rcx = 0, ec_rsp = 0, ec_rsp_content = 0, 
    m_fault_addr = 0, ec_ss = 0, ec_es = 0;
    char ec_rip_content[STR_MIN_LENGTH];
    uint32 crc = 0, crc1 = 0;
    int age = 0;
    Cow_elt* v_is_mapped_elsewhere = nullptr;
    void* linear_add = nullptr;
    Cow_elt *prev;
    Cow_elt *next;
    static size_t number, current_ec_cow_elts_size;

public:

    
    Cow_elt(Pte_type, mword, Paddr, mword, Page_type = NORMAL);
    Cow_elt(const Cow_elt& orig);
    ALWAYS_INLINE
    inline ~Cow_elt();
    
    void update_pte(Physic, bool);
    void to_log(const char*);
    
    ALWAYS_INLINE
    static inline void *operator new (size_t);

    ALWAYS_INLINE
    static inline void operator delete (void *ptr);
    
    Cow_elt &operator=(Cow_elt const &);

    static size_t get_number() { return cow_elts->size(); }

    static void resolve_cow_fault_hpt(Hpt*, mword virt, Paddr phys, mword attr);
    static void resolve_cow_fault_ept(Ept*, mword virt, Paddr phys, mword attr);
    static void resolve_cow_fault_vtlb(Vtlb*, mword virt, Paddr phys, mword attr);
    static Cow_elt* is_mapped_elsewhere(Paddr, mword);
    static void copy_frames(Paddr, Paddr, Paddr);
    static void remove_cow(Vtlb*, Hpt*, mword virt, Paddr phys, mword attr);

    static bool is_empty() {
        return !cow_elts || !cow_elts->head();
    }
    static void restore_state0();
    static bool compare();
    static void commit();
    static void restore_state1();
    static void restore_state2();
    static void rollback();
    static void free_current_pd_cowelts();
    static void free(Cow_elt*);    
    static void debug_rollback();
    static void abort();
    static bool is_pe_empty();
};

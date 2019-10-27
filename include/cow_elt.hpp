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

private:
    enum Page_type {
        NORMAL,
        BIG_PAGE,
    };
    
    enum Physic {
        PHYS0, 
        PHYS1,
        PHYS2,
    };
    
    enum Right {
        RO,
        RW,
    };
    
    struct Table_Entry {
        bool is_hpt = true;
        union {
            Vtlb *vtlb;
            Hpt *hpt;
        };
       ~Table_Entry() {};
    };
    static Queue<Cow_elt> *cow_elts;
    Page_type type;
    mword page_addr = {}; // if VM, this will hold the gla, else hold page addr
    mword attr = {};
    Paddr phys_addr[3];
    mword ec_rip = 0, ec_rcx = 0, ec_rsp = 0, ec_rsp_content = 0, m_fault_addr = 0;
    uint32 crc = 0, crc1 = 0;
    int age = 0;
    Cow_elt* v_is_mapped_elsewhere = nullptr;
    /*---These should moved to Pe class when it will be used -----*/
    Table_Entry pte = {};
    /*------------------------------------------------------------*/
    void* linear_add = nullptr;
    Cow_elt *prev;
    Cow_elt *next;
    static size_t number, current_ec_cow_elts_size;

public:

    
    Cow_elt(mword, Paddr, mword, Hpt*, Vtlb*, Page_type = NORMAL, mword = 0);
    Cow_elt(const Cow_elt& orig);
    ~Cow_elt();
    
    void update_pte(Physic, Right);
    void to_log(const char*);
    
    ALWAYS_INLINE
    static inline void *operator new (size_t);

    ALWAYS_INLINE
    static inline void operator delete (void *ptr);
    
    Cow_elt &operator=(Cow_elt const &);

    static size_t get_number() { return cow_elts->size(); }

    static void resolve_cow_fault(Vtlb*, Hpt*, mword virt, Paddr phys, mword attr);
    static Cow_elt* is_mapped_elsewhere(Paddr);
    static void copy_frames(Paddr, Paddr, void*);
    static void remove_cow(Vtlb*, Hpt*, mword virt, Paddr phys, mword attr);

    static bool is_empty() {
        return !cow_elts || !cow_elts->head();
    }
    static void restore_state0();
    static void restore_vm_stack_state0();
    static bool compare();
    static bool compare_vm_stack();
    static void commit();
    static void commit_vm_stack();
    static void commit_vm_stack_ce(Cow_elt*, uint32, void*);
    static void restore_state1();
    static void restore_vm_stack_state1();
    static void rollback();
    static void debug_rollback();
    static void rollback_vm_stack();
    static void place_phys0();
    static bool is_kernel_vm_modified();
    static void free(Cow_elt*);
    
};

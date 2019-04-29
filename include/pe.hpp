/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pe.hpp
 * Author: parfait
 *
 * Created on 3 octobre 2018, 14:34
 */

#pragma once
#include "types.hpp"
#include "slab.hpp"
#include "compiler.hpp"
#include "queue.hpp"
#include "console.hpp"
#include "regs.hpp"

class Pe {
    friend class Queue<Pe>;
    static Slab_cache cache;    
    static Queue<Pe> pes;
    
    static size_t number;
    char ec[MAX_STR_LENGTH];
    char pd[MAX_STR_LENGTH];
    Cpu_regs regs;
    Pe* prev;
    Pe* next;
    size_t numero = 0;
    bool marked = false;
    mword attr = 0; 
    
public:
    /**
     These static variables are for statistics
     */
    static unsigned ipi[2][NUM_IPI];
    static unsigned msi[2][NUM_MSI];
    static unsigned lvt[2][NUM_LVT];
    static unsigned gsi[2][NUM_GSI];
    static unsigned exc[2][NUM_EXC];
    static unsigned vmi[2][NUM_VMI];
    static unsigned vtlb_gpf[2];
    static unsigned vtlb_hpf[2];
    static unsigned vtlb_fill[2];
    static unsigned vtlb_flush[2];
    static unsigned rep_io[2];
    static unsigned simple_io[2];
    static unsigned io[2];
    static unsigned pmi_ss[2];
    static unsigned pio[2];
    static unsigned mmio[2];
    static unsigned rep_prefix[2];
    static unsigned hlt_instr[2];
    //----------------------------------------------
    /**
     * These static variables are for Pe environment
     */
    static unsigned vmlaunch;
    
    static char current_ec[MAX_STR_LENGTH];
    static char current_pd[MAX_STR_LENGTH];
    static Cpu_regs c_regs[4]; //current_regs
    static mword vmcsRIP[4], vmcsRSP[4];
    static bool inState1;
    static bool pmi_pending;
    /**
     * 
     * @param ec
     * @param pd
     * @param counter
     */
    Pe(const char* ec, const char* pd, Cpu_regs);
    Pe &operator = (Pe const &);

    ALWAYS_INLINE
    static inline void *operator new (size_t, Quota &quota) { return cache.alloc(quota); }

    ALWAYS_INLINE
    static inline void destroy (Pe *obj, Quota &quota) { obj->~Pe(); cache.free (obj, quota); }
    
    Pe(const Pe& orig);    
    ~Pe();
    
    ALWAYS_INLINE
    static inline void operator delete (void *ptr, Quota &quota) {
        Pe* pe = static_cast<Pe*> (ptr);
        pe->~Pe();
        cache.free (ptr, quota);
    }

    char* GetEc_name() {
        return ec;
    }

    char* GetPd_name() {
        return pd;
    }

    Pe* get_next(){
        return next;
    };
    
    Pe* get_previous(){
        return prev;
    };
    
    static void print_current(bool isvCPU = false){
        Console::print("%s %s \n"
        "RAX %#8lx %#8lx %#8lx %#8lx\n"
        "RBX %#8lx %#8lx %#8lx %#8lx\n"
        "RCX %#8lx %#8lx %#8lx %#8lx\n"
        "RDX %#8lx %#8lx %#8lx %#8lx\n"
        "RSI %#8lx %#8lx %#8lx %#8lx\n"
        "RDI %#8lx %#8lx %#8lx %#8lx\n"
        "RBP %#8lx %#8lx %#8lx %#8lx\n"
        "RSP %#8lx %#8lx %#8lx %#8lx\n"
        "RIP %#8lx %#8lx %#8lx %#8lx\n"
        "R8  %#8lx %#8lx %#8lx %#8lx\n"
        "R9  %#8lx %#8lx %#8lx %#8lx\n"
        "R10 %#8lx %#8lx %#8lx %#8lx\n"
        "R11 %#8lx %#8lx %#8lx %#8lx\n"
        "R12 %#8lx %#8lx %#8lx %#8lx\n"
        "R13 %#8lx %#8lx %#8lx %#8lx\n"
        "R14 %#8lx %#8lx %#8lx %#8lx\n"
        "R15 %#8lx %#8lx %#8lx %#8lx\n", current_ec, current_pd, 
                c_regs[0].REG(ax), c_regs[1].REG(ax), c_regs[2].REG(ax), c_regs[3].REG(ax),
                c_regs[0].REG(bx), c_regs[1].REG(bx), c_regs[2].REG(bx), c_regs[3].REG(bx),
                c_regs[0].REG(cx), c_regs[1].REG(cx), c_regs[2].REG(cx), c_regs[3].REG(cx),
                c_regs[0].REG(dx), c_regs[1].REG(dx), c_regs[2].REG(dx), c_regs[3].REG(dx),
                c_regs[0].REG(si), c_regs[1].REG(si), c_regs[2].REG(si), c_regs[3].REG(si),
                c_regs[0].REG(di), c_regs[1].REG(di), c_regs[2].REG(di), c_regs[3].REG(di),
                c_regs[0].REG(bp), c_regs[1].REG(bp), c_regs[2].REG(bp), c_regs[3].REG(bp),
                c_regs[0].REG(sp), c_regs[1].REG(sp), c_regs[2].REG(sp), c_regs[3].REG(sp),
                c_regs[0].REG(ip), c_regs[1].REG(ip), c_regs[2].REG(ip), c_regs[3].REG(ip),
                c_regs[0].r8, c_regs[1].r8, c_regs[2].r8, c_regs[3].r8,
                c_regs[0].r9, c_regs[1].r9, c_regs[2].r9, c_regs[3].r9,
                c_regs[0].r10, c_regs[1].r10, c_regs[2].r10, c_regs[3].r10,
                c_regs[0].r11, c_regs[1].r11, c_regs[2].r11, c_regs[3].r11,
                c_regs[0].r12, c_regs[1].r12, c_regs[2].r12, c_regs[3].r12,
                c_regs[0].r13, c_regs[1].r13, c_regs[2].r13, c_regs[3].r13,
                c_regs[0].r14, c_regs[1].r14, c_regs[2].r14, c_regs[3].r14,
                c_regs[0].r15, c_regs[1].r15, c_regs[2].r15, c_regs[3].r15
                );
        if(isvCPU){
            Console::print("RAX %#8lx %#8lx %#8lx %#8lx\n"
                "RBX %#8lx %#8lx %#8lx %#8lx\n",
                    vmcsRIP[0], vmcsRIP[1], vmcsRIP[2], vmcsRIP[3],
                    vmcsRSP[0], vmcsRSP[1], vmcsRSP[2], vmcsRSP[3]);
        }
    }

    void mark();
    void print(){
        
    };
    
    bool is_marked() { return marked; }
    
    static size_t get_number(){
        return number;
    }
    
    static void add_pe(Pe*);
    
    static void free_recorded_pe();
    
    static void dump(bool = false);
    
    static void reset_counter();    
};

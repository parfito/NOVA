/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pe.cpp
 * Author: parfait
 * 
 * Created on 3 octobre 2018, 14:34
 */

#include "pe.hpp"
#include "pd.hpp"
#include "string.hpp"
#include "regs.hpp"
#include "ec.hpp"
#include "lapic.hpp"
Slab_cache Pe::cache(sizeof (Pe), 32);
size_t Pe::number = 0;
bool Pe::inState1 = false, Pe::in_recover_from_stack_fault_mode = false, Pe::in_debug_mode = false;
bool Pe::pmi_pending = false;
mword Pe::missmatch_addr;

Queue<Pe> Pe::pes;
unsigned Pe::ipi[2][NUM_IPI];
unsigned Pe::msi[2][NUM_MSI];
unsigned Pe::lvt[2][NUM_LVT];
unsigned Pe::gsi[2][NUM_GSI];
unsigned Pe::exc[2][NUM_EXC];
unsigned Pe::vmi[2][NUM_VMI];
unsigned Pe::vtlb_gpf[2];
unsigned Pe::vtlb_hpf[2];
unsigned Pe::vtlb_fill[2];
unsigned Pe::vtlb_flush[2];
unsigned Pe::rep_io[2];
unsigned Pe::simple_io[2];
unsigned Pe::io[2];
unsigned Pe::pmi_ss[2];
unsigned Pe::pio[2];
unsigned Pe::mmio[2];
unsigned Pe::rep_prefix[2];
unsigned Pe::hlt_instr[2];
unsigned Pe::vmlaunch = 0;

char Pe::current_ec[], Pe::current_pd[];
Cpu_regs Pe::c_regs[];
mword Pe::vmcsRIP[], Pe::vmcsRSP[], Pe::vmcsRIP_0, Pe::vmcsRIP_1, Pe::vmcsRIP_2, 
        Pe::vmcsRSP_0, Pe::vmcsRSP_1, Pe::vmcsRSP_2;
/**
 * 
 * @param pd_name
 * @param ec_name
 * @param eip
 * @param cr
 * @param n : 
 * @param t
 */
Pe::Pe(const char* pd_name, const char* ec_name, mword eip, mword cr, unsigned n, const char* t) : 
rip0(eip), cr3(cr), pe_number(n), prev(nullptr), next(nullptr){
    copy_string(ec, ec_name);
    copy_string(pd, pd_name);  
    copy_string(type, t);
    numero = number;
    number++;
};

Pe::~Pe() {
    number--;
}

void Pe::add_pe(const char* pd_name, const char* ec_name, mword eip, mword cr, unsigned n, const 
        char* t){
    if(!Ec::current->is_debug_requested_from_user_space())
        return;
    Pe* pe = new (Pd::kern.quota)Pe(pd_name, ec_name, eip, cr, n, t);
    pes.enqueue(pe);
}

void Pe::free_recorded_pe() {
    Pe *pe = nullptr;
    while (pes.dequeue(pe = pes.head())) {
        Pe::destroy(pe, Pd::kern.quota);
    }
}

void Pe::dump(bool from_head){   
    trace(0, "PE nb %lu", number);
    Pe *p = from_head ? pes.head() : pes.tail(), *end = from_head ? pes.head() : pes.tail(), 
            *n = nullptr;
    while(p) {
        p->print(true);
        n = from_head ? p->next : p->prev;
        p = (p == n || n == end) ? nullptr : n;
    }
}

void Pe::reset_counter(){
    for(unsigned i=0 ; i < 2; i++) {
        vtlb_gpf[i] = vtlb_hpf[i] = vtlb_fill[i] = vtlb_flush[i] = rep_io[i] = simple_io[i] = io[i] = pmi_ss[i] = pio[i] = mmio[i] = rep_prefix[i] = hlt_instr[i] = 0;
        for (unsigned j = 0; j < NUM_IPI; j++)
            ipi[i][j] = 0;
        for (unsigned j = 0; j < NUM_MSI; j++)
            msi[i][j] = 0;
        for (unsigned j = 0; j < NUM_LVT; j++)
            lvt[i][j] = 0;
        for (unsigned j = 0; j < NUM_GSI; j++)
            gsi[i][j] = 0;
        for (unsigned j = 0; j < NUM_EXC; j++)
            exc[i][j] = 0;
        for (unsigned j = 0; j < NUM_VMI; j++)
            vmi[i][j] = 0;
    }
}

void Pe::counter(char* str){
    char s[20];
    *str = '\0';
    unsigned n = 0;
    for (unsigned j = 0; j < NUM_IPI; j++)
        if(ipi[0][j] || ipi[1][j]) {
            n = Console::sprint(s, "IPI%u %u %u ", j, ipi[0][j], ipi[1][j]);
            strcat(str, s, n);
        }
    for (unsigned j = 0; j < NUM_MSI; j++)
        if(msi[0][j] || msi[1][j]) {
            n = Console::sprint(s, "MSI%u %u %u ", j, msi[0][j], msi[1][j]);
            strcat(str, s, n);
        }
    for (unsigned j = 0; j < NUM_LVT; j++)
        if(lvt[0][j] || lvt[1][j]) {
            n = Console::sprint(s, "lvt%u %u %u ", j,  lvt[0][j], lvt[1][j]);
            strcat(str, s, n);
        }
    for (unsigned j = 0; j < NUM_GSI; j++)
        if(gsi[0][j] || gsi[1][j]) {
            n = Console::sprint(s, "gsi%u %u %u ", j, gsi[0][j], gsi[1][j]);
            strcat(str, s, n);
        }
    for (unsigned j = 0; j < NUM_EXC; j++)
        if(exc[0][j] || exc[1][j]) {
            n = Console::sprint(s, "exc%u %u %u ", j, exc[0][j], exc[1][j]);
            strcat(str, s, n);
        }
    for (unsigned j = 0; j < NUM_VMI; j++)
        if(vmi[0][j] || vmi[1][j]) {
            n = Console::sprint(s, "vmi%u %u %u ", j, vmi[0][j], vmi[0][j]);
            strcat(str, s, n);
        }
}

void Pe::set_val(mword v){
    if(!Ec::current->is_debug_requested_from_user_space())
        return;    
    Pe *p = pes.tail();
    if(p)
        p->val = v;
}


void Pe::set_ss_val(mword v){
    if(!Ec::current->is_debug_requested_from_user_space())
        return;    
    Pe *p = pes.tail();
    if(p)
        p->ss_val = v;
}

void Pe::set_froms(uint8 run, int from){
    if(!Ec::current->is_debug_requested_from_user_space())
        return;    
    Pe *p = pes.tail();
    if(p){
        if (run) 
            p->from1 = from;
        else
            p->from2 = from;
    }
}

void Pe::set_mmio(mword v, Paddr p){
    if(!Ec::current->is_debug_requested_from_user_space())
        return;    
    Pe *pe = pes.tail();
    if(pe){
        pe->mmio_v = v;
        pe->mmio_p = p;
    }
}

void Pe::add_pe_state(size_t c, int mm, mword pa, Paddr p0, Paddr p1, Paddr p2, mword pta,
        mword pti){
    if(!Ec::current->is_debug_requested_from_user_space())
        return;    
    Pe *p = pes.tail();
    assert(p);
    Pe_state* pe_state = new(Pd::kern.quota) Pe_state(c, mm, pa, p0, p1, p2, pta, pti);
    p->pe_states.enqueue(pe_state);  
}

void Pe::add_pe_state(mword addr, Paddr p0, Paddr p1, Paddr p2, mword ptap){
    if(!Ec::current->is_debug_requested_from_user_space())
        return;    
    Pe *p = pes.tail();
    assert(p);
    Pe_state* pe_state = new(Pd::kern.quota) Pe_state(addr, p0, p1, p2, ptap);
    p->pe_states.enqueue(pe_state);  
}

void Pe::add_pe_state(mword eip, uint8 run_number, mword interrupt_number){
    if(!Ec::current->is_debug_requested_from_user_space())
        return;    
    Pe *p = pes.tail();
    assert(p);
    Pe_state* pe_state = new(Pd::kern.quota) Pe_state(eip, run_number, interrupt_number, 
            Lapic::read_instCounter());
    p->pe_states.enqueue(pe_state);  
}

void Pe::set_rip1(mword r){
    if(!Ec::current->is_debug_requested_from_user_space())
        return;    
     Pe *p = pes.tail();
    assert(p);
    p->rip1 = r;
}

void Pe::set_rip2(mword r){
    if(!Ec::current->is_debug_requested_from_user_space())
        return;    
     Pe *p = pes.tail();
    assert(p);
    p->rip2 = r;
}

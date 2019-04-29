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
Slab_cache Pe::cache(sizeof (Pe), 32);
size_t Pe::number = 0;
bool Pe::inState1 = false;
bool Pe::pmi_pending = false;
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
mword Pe::vmcsRIP[], Pe::vmcsRSP[];

Pe::Pe(const char* ec_name, const char* pd_name, Cpu_regs cpu_regs) : regs(cpu_regs), prev(nullptr), next(nullptr){
    copy_string(ec, ec_name);
    copy_string(pd, pd_name);  
    numero = number;
    number++;
};

Pe::~Pe() {
    number--;
}

void Pe::mark(){
    marked = true;
}

void Pe::add_pe(Pe* pe){
    pes.enqueue(pe);
}

void Pe::free_recorded_pe() {
    Pe *pe = nullptr;
    while (pes.dequeue(pe = pes.head())) {
        Pe::destroy(pe, Pd::kern.quota);
    }
}

void Pe::dump(bool all){    
    Pe *p = pes.head(), *head = pes.head(), *n = nullptr;
    while(p) {
        if(all || p->is_marked())
            p->print();
        n = p->next;
        p = (p == n || n == head) ? nullptr : n;
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

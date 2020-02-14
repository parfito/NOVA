/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pending_int.cpp
 * Author: parfait
 * 
 * Created on 5 octobre 2018, 13:26
 */

#include "pending_int.hpp"
#include "pd.hpp"
#include "gsi.hpp"
#include "lapic.hpp"
#include "counter.hpp"
#include "vectors.hpp"

Slab_cache Pending_int::cache(sizeof (Pending_int), 32);
Queue<Pending_int> Pending_int::pendings;
size_t Pending_int::number = 0, Pending_int::max_number = 0;

Pending_int::Pending_int(unsigned v):vector(v), prev(nullptr), next(nullptr) {
    number++;
    if(number > max_number)
        max_number = number;
    time_stampt = rdtsc();
}

Pending_int::~Pending_int() {
    assert(number);
    number--;
}

void Pending_int::add_pending_interrupt(unsigned v){
    pendings.enqueue(new Pending_int(v));
}

void Pending_int::free_recorded_interrupt() {
    Pending_int *pi = nullptr;
    while (pendings.dequeue(pi = pendings.head())) {
        delete pi;
    }
}

void Pending_int::exec_pending_interrupt(){
    Pending_int *pi = nullptr;
    while (pendings.dequeue(pi = pendings.head())) {
        uint64 lag = rdtsc() - pi->time_stampt;
        switch(pi->vector){
            case VEC_GSI ... VEC_LVT - 1:
                Counter::delayed_gsi[pi->vector - VEC_GSI]++;
                Counter::lag_gsi[pi->vector - VEC_GSI] += lag;
                Gsi::exec_gsi(pi->vector, true);
                break;
            case VEC_LVT ... VEC_MSI - 1:
                Counter::delayed_lvt[pi->vector - VEC_LVT]++;
                Counter::lag_lvt[pi->vector - VEC_LVT] += lag;
                Lapic::exec_lvt(pi->vector, true);
                break;
            case VEC_MSI ... VEC_IPI - 1:
                Counter::lag_msi[pi->vector - VEC_MSI] += lag;
                Dmar::exec_msi(pi->vector, true);
                break;
            default:
                Console::panic("Unhandled pending interrupt");
        }
        delete pi;
    }
}

size_t Pending_int::get_number(){
    return number;
}

void Pending_int::dump() {
    call_log_funct(Logstore::add_entry_in_buffer, 1, "Dumping %lu interrupts ", number);        
    Pending_int *pi = pendings.head(), *h = pi, *next = nullptr;
    while(pi) {
        call_log_funct(Logstore::add_entry_in_buffer, 1, "Pi vec %u", pi->vector);        
        next = pi->next; 
        pi = (next == h) ? nullptr : next;          
    } 
}
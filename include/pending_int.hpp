/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pending_int.hpp
 * Author: parfait
 *
 * Created on 5 octobre 2018, 13:26
 */

#pragma once

#include "types.hpp"
#include "slab.hpp"
#include "compiler.hpp"
#include "queue.hpp"
#include "pd.hpp"
#include "stdio.hpp"

class Pending_int {
    friend class Queue<Pending_int>;
    static Slab_cache cache; 
    static  Queue<Pending_int> pendings;
        
public:
    Pending_int(unsigned v);
    Pending_int(const Pending_int& orig);
    ~Pending_int();
    ALWAYS_INLINE
    static inline void *operator new (size_t) { return cache.alloc(Pd::kern.quota); }
    ALWAYS_INLINE
    static inline void operator delete (void *ptr) {
        cache.free(ptr, Pd::kern.quota);
    }

    Pending_int &operator = (Pending_int const &);
    
    static void add_pending_interrupt(unsigned);
    
    static void free_recorded_interrupt();
    
    static void exec_pending_interrupt();
    
    static size_t get_number();
    
    static size_t get_max_number() {return max_number; }
    
    static void dump();
    
private:
    unsigned vector = 0;
    uint64 time_stampt = 0;
    Pending_int* prev;
    Pending_int* next; 
    static size_t number;
    static size_t max_number;
    
};
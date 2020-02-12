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

class Pending_int {
    friend class Queue<Pending_int>;
    static Slab_cache cache; 
    static  Queue<Pending_int> pendings;
        
public:
    Pending_int(unsigned v);
    Pending_int(const Pending_int& orig);
    ~Pending_int();
    ALWAYS_INLINE
    static inline void *operator new (size_t, Quota &quota) { return cache.alloc(quota); }
    ALWAYS_INLINE
    static inline void destroy (Pending_int *obj, Quota &quota) { obj->~Pending_int(); cache.free (obj, quota);}
    ALWAYS_INLINE
    static inline void operator delete (void *ptr, Quota &quota) {
        Pending_int* pi = static_cast<Pending_int*> (ptr);
        pi->~Pending_int();
        cache.free (ptr, quota);
    }

    Pending_int &operator = (Pending_int const &);
    
    static void add_pending_interrupt(unsigned);
    
    static void free_recorded_interrupt();
    
    static void exec_pending_interrupt();
    
    static size_t get_numero();
    
private:
    unsigned vector = 0;
    uint64 time_stampt = 0;
    Pending_int* prev;
    Pending_int* next; 
    static size_t number;
    
};
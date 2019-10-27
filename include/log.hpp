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
#include "queue.hpp"
#include "string.hpp"
class Log;
    
class Log_entry {
    friend class Queue<Log_entry>;
    friend class Log;
    friend class Queue_logs;
    friend class Table_logs;

    static Slab_cache cache; 
    static size_t log_entry_number;

    String *log_entry = nullptr;
    Log_entry *prev = nullptr, *next = nullptr;
//        size_t numero = 0;

    ALWAYS_INLINE
    static inline void *operator new (size_t) {return cache.alloc(Pd::kern.quota);}

    ALWAYS_INLINE
    static inline void operator delete (void *ptr) {
        cache.free (ptr, Pd::kern.quota);
    }

    ~Log_entry() {
        delete log_entry;
        assert(log_entry_number);
        log_entry_number--;
    }
    Log_entry(){}

    Log_entry(const Log_entry& orig);

    Log_entry &operator=(Log_entry const &);

//  Log_entry(char* l, Log* log) {
    Log_entry(char* l);
        
    void print(){
        Console::print("%s", log_entry->get_string());
    }
public:
    static size_t get_total_log_size() { return log_entry_number; }
    
};

class Log {
    friend class Queue<Log>;
    friend class Logstore;
    friend class Log_entry;
    friend class Queue_logs;
    friend class Table_logs;
    
    static Slab_cache cache;    
    static size_t log_number;
    
    size_t entry_count = 0;
    size_t numero = 0;
    String *info = nullptr;
    Queue<Log_entry> log_entries = {};
    Log* prev = nullptr;
    Log* next = nullptr;
    
public:
    Log(){}
    
    Log(const char*);
    Log &operator = (Log const &);

    ALWAYS_INLINE
    static inline void *operator new (size_t) { return cache.alloc(Pd::kern.quota); }
    
    Log(const Log& orig);    
    
    ~Log() {
        Log_entry *li = nullptr;
        while(log_entries.dequeue(li = log_entries.head())){
            delete li;
        } 
        delete info;
        assert(log_number);
        log_number--;
    } 
    
    ALWAYS_INLINE
    static inline void operator delete (void *ptr) {
        cache.free (ptr, Pd::kern.quota);
    }
    
    void print(bool = true);
};

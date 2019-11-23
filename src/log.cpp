/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Log.cpp
 * Author: Parfait Tokponnon <pafait.tokponnon@uclouvain.be>
 * The Log : provide a doubled linked circular queue to hold all created logs
 * 
 * Created on 3 octobre 2018, 14:34
 */

#include "log.hpp"
#include "string.hpp"
#include "stdio.hpp"

Slab_cache Log::cache(sizeof (Log), 32), Log_entry::cache(sizeof (Log_entry), 32);
size_t Log::log_number = 0, Log_entry::log_entry_number = 0;

Log::Log(const char* title) : prev(nullptr), next(nullptr){
    info = new String(title);
    numero = log_number++;
};

/**
 * Prints this log's entries, if queue were used, print from log_entries, else,
 * logstore was used, print from logstore, 
 * @param from_tail
 */
void Log::print(bool from_tail){
    trace(0, "LOG %lu size %lu %s", numero, entry_count, info->get_string());
    if(entry_count) {
        Log_entry *log_info = from_tail ? log_entries.tail() : log_entries.head(), *end = from_tail ? 
            log_entries.tail() : log_entries.head(), 
            *n = nullptr;
        while(log_info) {
            log_info->print();
            n = from_tail ? log_info->prev : log_info->next;
            log_info = (n == end) ? nullptr : n;
        }
    }
}

/**
 * Add a log entry. This constructor is to be used only for queue logentries. 
 * @param l
 */
Log_entry::Log_entry(char* l) {
    log_entry = new String(l);
    log_entry_number++;
}

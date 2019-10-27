/*
 * File:   log_store.hpp
 * Author: Parfait Tokponnon <pafait.tokponnon@uclouvain.be>
 * The Log store : provide almost ready-to-be-used logs, so it does not create 
 * new log by resorting to new keyword. It can hold up to LOG_MAX logs and 
 * LOG_ENTRY_MAX log entries
 *
 * Created on 17 octobre 2019, 19:50
 */
#pragma once

#include "config.hpp"
#include "log.hpp"

class Logstore {
    
private:
    static char *log_buffer, *log_buffer_cursor, *entry_buffer, *entry_buffer_cursor;
    static size_t entry_offset, buffer_size;

    static void add_log(const char*);
        
    static void add_log_entry(const char*);
    
    static void append_log_info(const char*);
        
    
public:
    Logstore();
    Logstore(const Logstore& orig);
    ~Logstore();
    
    static bool log_on, logs_in_table;
    
    static void free_logs(size_t=0, bool=false);
        
    static void dump(char const*, bool = true, size_t = 5);
            
    static void add_entry_in_buffer(const char*);
    
    static void add_log_in_buffer(const char*);
    
    static void commit_buffer();
    
    static size_t get_number();
    
};

class Queue_logs {
    friend class Logstore;
    
private:
    static Queue<Log> logs;
    
    static void add_log(const char*);
    
    static void free_logs(size_t=0, bool=false);
    
    static void dump(char const*, bool = true, size_t = 5);
            
    static void add_log_entry(const char*);
    
    static void append_log_info(const char*);
    
public:
    Queue_logs();
    Queue_logs(const Queue_logs& orig);
    ~Queue_logs();
    
    static size_t get_number() { return logs.size(); }
};

class Table_logs {
    friend class Logstore;
        
private:
    static Log logs[LOG_MAX];
    static size_t cursor, start, total_logs;
    
    static void add_log(const char*);
    
    static void free_logs(size_t=0, bool=false);
    
    static void dump(char const*, bool = true, size_t = 5);
    
    static void append_log_info(const char*);
    
    static size_t get_number();
    
public:
    Table_logs();
    Table_logs(const Table_logs& orig);
    ~Table_logs();                
};

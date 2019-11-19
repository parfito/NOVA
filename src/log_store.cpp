/*
 * File:   log_store.cpp
 * Author: Parfait Tokponnon <pafait.tokponnon@uclouvain.be>
 * The Log store : provide almost ready-to-be-used logs, so it does not create 
 * new log by resorting to new keyword. It can hold up to LOG_MAX logs and 
 * LOG_ENTRY_MAX log entries
 * 
 * Created on 17 octobre 2019, 19:50
 */

#include "log_store.hpp"
#include "assert.hpp"
#include "log.hpp"
#include "counter.hpp"
#include "util.hpp"
#include "stdio.hpp"

Queue<Log> Queue_logs::logs;
Log Table_logs::logs[LOG_MAX];
bool Logstore::log_on = false, Logstore::logs_in_table = true, Logstore::has_been_dumped = false;
size_t Table_logs::cursor = 0, Table_logs::start = 0, Table_logs::total_logs = 0, 
        Logstore::entry_offset = static_cast<size_t>(ENTRY_OFFSET),
        Logstore::buffer_size = (1ul<<BUFFER_ORDER)*PAGE_SIZE;
char *Logstore::log_buffer = reinterpret_cast<char*>(Buddy::allocator.alloc (BUFFER_ORDER, Pd::kern.quota, Buddy::FILL_0)),
        *Logstore::entry_buffer = Logstore::log_buffer + Logstore::entry_offset,
        *Logstore::log_buffer_cursor = Logstore::log_buffer,
        *Logstore::entry_buffer_cursor = Logstore::entry_buffer;

Logstore::Logstore() {
}

Logstore::~Logstore() {
}

/**
 * Add new log. If the log at cursor index does have a string, it just replaces 
 * its content, if not, it creates a new one. The creation process is supposed to 
 * be called only for the first LOG_MAX logs; after the LOG_MAX_th log, just replace string
 * @param log : Log string to be added
 */
void Logstore::add_log(const char* log){
    if(!log_on || !strlen(log))
        return;
    if(logs_in_table)
        Table_logs::add_log(log);
    else
        Queue_logs::add_log(log);
}

/**
 * Frees (100 - left) percent logs (if in_percent == true) or left logs (if in_percent == false)
 * in order to reclaim their memory. The function start by the oldest log. 
 * @param left
 * @param in_percent
 */
void Logstore::free_logs(size_t left, bool in_percent) {
    if(logs_in_table) {
        Table_logs::free_logs(left, in_percent);
    } else {
        Queue_logs::free_logs(left, in_percent);
    }
}

/**
 * 
 * @param funct_name : Where we come from
 * @param from_tail : From the first log (from_tail == false) or from the last
 * @param log_depth : the number of log to be printed; default is 5; we will print
 * all logs if this is 0
 */
void Logstore::dump(char const *funct_name, bool from_tail, size_t log_depth, bool force){
    if(has_been_dumped && !force)
        return;
    Logstore::commit_buffer();
    if(logs_in_table) {
        Table_logs::dump(funct_name, from_tail, log_depth);
    } else {
        Queue_logs::dump(funct_name, from_tail, log_depth);
    }
    has_been_dumped = true;
}

/**
 * Append new string to the log info. It does this by destroying the last buffer
 * and allocating a new one, wide enough, to hold the the old and the new strings
 * @param s
 */
void Logstore::append_log_info(const char* s){
    if(!log_on || !strlen(s))
        return;    
    if(logs_in_table) {
        Table_logs::append_log_info(s);
    } else {
        Queue_logs::append_log_info(s);
    }
}

size_t Logstore::get_number() {
    if(logs_in_table) {
        return Queue_logs::get_number();
    } else {
        return Table_logs::get_number();
    }
}
/**
 * Add new log. If the log at cursor index does have a string, it just replaces 
 * its content, if not, it creates a new one. The creation process is supposed to 
 * be called only on time
 * @param pd_name
 * @param ec_name
 */
void Queue_logs::add_log(const char* s){
    if(logs.size() > LOG_MAX){
        Log *head = logs.head();
        logs.dequeue(head);
        delete head;
    }
    Log* log = new Log(s);
    logs.enqueue(log);
}

/**
 * Frees (100 - left) percent logs (if in_percent == true) or left logs (if in_percent == false)
 * in order to reclaim their memory. The function start by the oldest log. 
 * @param left
 * @param in_percent
 */
void Queue_logs::free_logs(size_t left, bool in_percent) {
    size_t log_number = logs.size();
    if(!log_number)
        return;
    Log *log = nullptr;
    
    if(in_percent) {
        assert(left && left < 100);
        left = left * log_number/100;
    }
// In no case should all logs be deleted, in order to avoid null pointer bug in logs queue         
    if(!left) 
        left = 1; 
    
    while (left < log_number && logs.dequeue(log = logs.head())) {
        delete log;
        log_number--;
    }

//Renumber the remaining logs    
    size_t i = 0, log_entry_count = 0;
    log = logs.head();
    Log *n = nullptr;
    while(log) {
        log->numero = ++i;
        log_entry_count += log->entry_count;
        n = log->next;
        log = (n == logs.head()) ? nullptr : n;
    }
    
    assert (log_number == left && Log_entry::log_entry_number == log_entry_count);
}

/**
 * 
 * @param funct_name : Where we come from
 * @param from_tail : From the first log (from_tail == false) or from the last
 * @param log_depth : the number of log to be printed; default is 5; we will print
 * all logs if this is 0
 */
void Queue_logs::dump(char const *funct_name, bool from_tail, size_t log_depth){ 
    size_t log_number = logs.size();
    if(!log_number)
        return;
    trace(0, "%s Log %lu log entries %lu", funct_name, log_number, Log_entry::log_entry_number);
    Log *p = from_tail ? logs.tail() : logs.head(), *end = from_tail ? logs.tail() : logs.head(), 
            *n = nullptr;
    if(log_depth == 0)
        log_depth = 100000000ul;
    uint32 count = 0;
    while(p && count<log_depth) {
        p->print(false);
        n = from_tail ? p->prev : p->next;
        p = (n == end) ? nullptr : n;
        count++;
    }
}


/**
 * This will add a log entry with new string the first time the log at the cursor
 * is used, subsequent times it will just replace its content
 * @param log
 */
void Queue_logs::add_log_entry(const char* log){
    if(!Logstore::log_on || !strlen(log))
        return;    
    Log *l = logs.tail();
    assert(l);
    char buff[STR_MAX_LENGTH];
    String::print(buff, "%lu %s", l->entry_count, log);
    Log_entry *log_info = new Log_entry(buff);
    l->log_entries.enqueue(log_info);  
    l->entry_count++;
}

/**
 * Append new string to the log info. It does this by destroying the last buffer
 * and allocating a new one, wide enough, to hold the the old and the new strings
 * @param s
 */
void Queue_logs::append_log_info(const char* s){
    Log *l = logs.tail();
    assert(l);
    l->info->append(s);
}

/**
 * Add new log. If the log at cursor index does have a string, it just replaces 
 * its content, if not, it creates a new one. The creation process is supposed to 
 * be called only for the first LOG_MAX logs; after the LOG_MAX_th log, just replace string
 * @param log : Log string to be added
 */
void Table_logs::add_log(const char* log){
    size_t log_max = static_cast<size_t>(LOG_MAX), curr = cursor;
    Log *l = &logs[curr];
    if(l->info) { // this log'string already exists
        l->info->replace_with(log);  // Replace its string object      
    } else {
        l->info = new String(log); // Create this curr_th log string's object
    }
    l->numero = total_logs++; // Assign its number
    cursor = (cursor == log_max - 1) ? 0 : cursor + 1; // set cursor to 0 if we reach LOG_MAX
    if(cursor == start) // increase start whith 1 if cursor goes around the table        
        start = (start == log_max - 1) ? 0 : start + 1; 
}

/**
 * Frees (100 - left) percent logs (if in_percent == true) or left logs (if in_percent == false)
 * in order to reclaim their memory. The function start by the oldest log. 
 * @param left
 * @param in_percent
 */
void Table_logs::free_logs(size_t left, bool in_percent) {
    if(!total_logs)
        return;
    size_t log_max = static_cast<size_t>(LOG_MAX),
            log_number = total_logs < log_max ? cursor - start : 
                cursor > start ? cursor - start : cursor + log_max - start;
    if(in_percent){
        assert(left && left < 100);
        left = left * log_number/100;
    }
// In no case should all logs be deleted, in order to avoid null pointer bug in logs queue         
    if(!left) 
        left = 1; 
    assert(log_number > left);
    size_t i_start = start,
            i_end = (i_start + log_number - left) % log_max,
    // If we reach the laxt index in the table, we will continue with index 0
            s = i_start, e = i_start < i_end ? i_end : log_max; 
    for(size_t i = s; i < e; i++) {
        Log* l = &logs[i];
        l->entry_count = 0;        // free its memory
        l->numero = 0;
        l->info->free_buffer();
        if(i_start > i_end && i == log_max - 1){ // If we were to round from the last
            i = ~static_cast<size_t>(0ul);
            e = i_end;
        }
    }
    trace(0, "log_number %lu left %lu start %lu cursor %lu i_start %lu i_end %lu "
            "s %lu e %lu", log_number, left, start, cursor, i_start, i_end, s, e);
    start = e;
        }

/**
 * 
 * @param funct_name : Where we come from
 * @param from_tail : From the first log (from_tail == false) or from the last
 * @param log_depth : the number of log to be printed; default is 5; we will print
 * all logs if this is 0
 */
void Table_logs::dump(char const *funct_name, bool from_tail, size_t log_depth){   
    if(!total_logs)
        return;
    size_t log_max = static_cast<size_t>(LOG_MAX), 
            log_number = total_logs < log_max ? cursor - start : 
            cursor > start ? cursor - start : cursor + log_max - start;
    if(log_depth == 0 || log_depth > log_number) {
        log_depth = log_number;
    }
    trace(0, "%s Log %lu %s cursor %lu start %lu depth %lu", funct_name, log_number, 
            from_tail ? "from_last" : "from_first", cursor, start, log_depth);                
    if(log_number == 1) {
        logs[cursor ? cursor - 1 : log_max].print(false);
        return;
    }
    if(from_tail){
        size_t i_start = cursor ? cursor - 1 : log_max,
                i_end = (i_start - log_depth > start ? i_start - log_depth : 
                    i_start + log_max - log_depth) % log_max,
                s = i_start, e = i_start > i_end ? i_end : 0;
        trace(0, "i_start %lu i_end %lu s %lu e %lu", i_start, i_end, s, e);
        for(size_t i = s; i >= e; i--) {
            logs[i].print(false);
            if(i_start < i_end && i == 0){
                i = log_max;
                e = i_end;
            }
        }
    } else {
        size_t i_start = start,
                i_end = (i_start + log_number - log_depth) % log_max,
                s = i_start, e = i_start < i_end ? i_end : log_max;
        trace(0, "start %lu cursor %lu log_depth %lu i_start %lu i_end %lu s %lu "
                "e %lu", start, cursor, log_depth, i_start, i_end, s, e);
        for(size_t i = s; i < e; i++) {
            logs[i].print(false);
            if(i_start > i_end && i == log_max - 1){
                i = ~static_cast<size_t>(0ul);
                e = i_end;
            }
        }
    }    
}

/**
 * Append new string to the log info. It does this by destroying the last buffer
 * and allocating a new one, wide enough, to hold the the old and the new strings
 * @param s
 */
void Table_logs::append_log_info(const char* s){
    size_t log_max = static_cast<size_t>(LOG_MAX);
    Log* l = &logs[(cursor-1)%log_max];
    l->info->append(s);
}

size_t Table_logs::get_number() {
    size_t log_max = static_cast<size_t>(LOG_MAX);
    return total_logs < log_max ? cursor - start : 
                cursor > start ? cursor - start : cursor + log_max - start;
}
/**
 * store new log to the logs'buffer
 * @param s
 */
void Logstore::append_log_in_buffer(const char* s){
    size_t size = strlen(s); 
    if(!log_on || !size)
        return;    
    if(log_buffer_cursor + size + 1 > log_buffer + entry_offset) {
// We cannot store in the buffer beyond its size which is ENTRY_OFFSET,    
        commit_buffer();
        add_log_in_buffer("Append Log (Suite)");        
    }
    if(log_buffer_cursor == log_buffer)
        *(log_buffer_cursor++) = ' '; // replace the final '\0' one space
    copy_string(log_buffer_cursor, s, size + 1);  
    log_buffer_cursor += size;     
}

/**
 * store new log to the logs'buffer
 * @param s
 */
void Logstore::add_log_in_buffer(const char* s){
    size_t size = strlen(s); 
    if(!log_on || !size)
        return;    
    if(log_buffer_cursor + size + 2 > log_buffer + entry_offset) {
// We cannot store in the buffer beyond its size which is ENTRY_OFFSET,    
        commit_buffer();
        add_log_in_buffer("Log (Suite)");        
    }
    
    if(log_buffer_cursor != log_buffer)
        *(log_buffer_cursor++) = '\n'; // replace the final '\0' by new line
    copy_string(log_buffer_cursor, s, size + 1);  
    log_buffer_cursor += size;     
}

/**
 * store new log entry to the entries'buffer
 * @param s
 */
void Logstore::add_entry_in_buffer(const char* s){
    size_t size = strlen(s); 
    if(!log_on || !size)
        return;    
    if(entry_buffer_cursor + size + 1 > entry_buffer + (buffer_size - entry_offset)) {
// We cannot store in the entry buffer beyond its size which is BUFFER_SIZE - ENTRY_OFFSET, 
        char buff[STR_MAX_LENGTH];
        size_t n = copy_string(buff, "Entry (Suite) for log ");
        copy_string(buff + n, log_buffer, STR_MAX_LENGTH - n);
        commit_buffer();
        add_log_in_buffer(buff);
    }
    if(entry_buffer_cursor != entry_buffer)
        *entry_buffer_cursor++ = '\n'; // replace the final '\0' by new line
    copy_string(entry_buffer_cursor, s, size + 1);        
    entry_buffer_cursor += size; 
}

/**
 * Commit log buffer and entries buffer
 */
void Logstore::commit_buffer(){
    if(!log_on)
        return;    
    size_t log_length = strlen(log_buffer), log_entry_length = strlen(entry_buffer);
    if(!log_length && !log_entry_length)
        return;
    *log_buffer_cursor = '\n';
    if(log_entry_length) {
        copy_string(log_buffer_cursor + 1, entry_buffer, log_entry_length);
    }
    add_log(log_buffer);
    
    memset(log_buffer, 0, buffer_size);
    log_buffer_cursor = log_buffer;
    entry_buffer_cursor = entry_buffer;
}

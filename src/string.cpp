/*
 * String Functions
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Copyright (C) 2019-     Parfait Tokponnon <mahoukpego.tokponnon@uclouvain.be>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * This file is part of the NOVA microhypervisor.
 *
 * NOVA is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * NOVA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License version 2 for more details.
 */

#include "string.hpp"
#include "bits.hpp"
#include "log.hpp"
#include "log_store.hpp"
#include "stdio.hpp"

unsigned String::count;
Slab_cache String::cache(sizeof (String), 32), Block::cache(sizeof(Block), 32);
void* Block::memory;
unsigned short Block::memory_order = 15;
size_t Block::tour, Block::memory_size = (1ul << memory_order) * PAGE_SIZE, 
        Block::free_memory = Block::memory_size;
bool Block::reallocated, Block::initialized;
Block* Block::cursor;

Queue<Block> Block::free_blocks, Block::used_blocks;

/**
 * Create a new string and allocate a new buffer for it
 * @param p
 */
String::String(const char *p) : length(strlen(p)){
    buffer = Block::alloc(length+1); // +1 is for the \0 string null character at the end     
    copy_string(buffer->start, p, length);
}
/**
 * Create a new string and allocate a new buffer for it
 * @param p
 */
String::String(size_t u) : length(u){
    buffer = Block::alloc(length+1); // +1 is for the \0 string null character at the end     
}

int String::vprintf_help(int c, void **ptr) {
    char *dst;

    dst = reinterpret_cast<char*> (*ptr);
    *dst++ = static_cast<char> (c);
    *ptr = dst;
    count++;
    return 0;
}

void String::print_num(uint64 val, unsigned base, unsigned width, unsigned flags, void **pointer) {
    bool neg = false;

    if (flags & FLAG_SIGNED && static_cast<signed long long> (val) < 0) {
        neg = true;
        val = -val;
    }

    char buffer[24], *ptr = buffer + sizeof buffer;

    do {
        uint32 r;
        val = div64(val, base, &r);
        *--ptr = r["0123456789abcdef"];
    } while (val);

    if (neg)
        *--ptr = '-';

    unsigned long c = buffer + sizeof buffer - ptr;
    unsigned long n = c + (flags & FLAG_ALT_FORM ? 2 : 0);

    if (flags & FLAG_ZERO_PAD) {
        if (flags & FLAG_ALT_FORM) {
            vprintf_help('0', pointer);
            vprintf_help('x', pointer);
        }
        while (n++ < width)
            vprintf_help('0', pointer);
    } else {
        while (n++ < width)
            vprintf_help(' ', pointer);
        if (flags & FLAG_ALT_FORM) {
            vprintf_help('0', pointer);
            vprintf_help('x', pointer);
        }
    }

    while (c--)
        vprintf_help(*ptr++, pointer);
}

void String::print_str(char const *s, unsigned width, unsigned precs, void **ptr) {
    if (EXPECT_FALSE(!s))
        return;

    unsigned n;

    for (n = 0; *s && precs--; n++)
        vprintf_help(*s++, ptr);

    while (n++ < width)
        vprintf_help(' ', ptr);
}

void String::vprintf(void *ptr, char const *format, va_list args) {
    while (*format) {

        if (EXPECT_TRUE(*format != '%')) {
            vprintf_help(*format++, &ptr);
            continue;
        }

        unsigned flags = 0, width = 0, precs = 0, len = 0, mode = MODE_FLAGS;

        for (uint64 u;;) {

            switch (*++format) {

                case '0'...'9':
                    switch (mode) {
                        case MODE_FLAGS:
                            if (*format == '0') {
                                flags |= FLAG_ZERO_PAD;
                                break;
                            }
                            mode = MODE_WIDTH;
                        case MODE_WIDTH: width = width * 10 + *format - '0';
                            break;
                        case MODE_PRECS: precs = precs * 10 + *format - '0';
                            break;
                    }
                    continue;

                case '.':
                    mode = MODE_PRECS;
                    continue;

                case '#':
                    if (mode == MODE_FLAGS)
                        flags |= FLAG_ALT_FORM;
                    continue;

                case 'l':
                    len++;
                    continue;

                case 'c':
                    vprintf_help(va_arg(args, int), &ptr);
                    break;

                case 's':
                    print_str(va_arg(args, char *), width, precs ? precs : ~0u, &ptr);
                    break;

                case 'd':
                    switch (len) {
                        case 0: u = va_arg(args, int);
                            break;
                        case 1: u = va_arg(args, long);
                            break;
                        default: u = va_arg(args, long long);
                            break;
                    }
                    print_num(u, 10, width, flags | FLAG_SIGNED, &ptr);
                    break;

                case 'u':
                case 'x':
                    switch (len) {
                        case 0: u = va_arg(args, unsigned int);
                            break;
                        case 1: u = va_arg(args, unsigned long);
                            break;
                        default: u = va_arg(args, unsigned long long);
                            break;
                    }
                    print_num(u, *format == 'x' ? 16 : 10, width, flags, &ptr);
                    break;

                case 'p':
                    print_num(reinterpret_cast<mword> (va_arg(args, void *)), 16, width, FLAG_ALT_FORM, &ptr);
                    break;

                case 0:
                    format--;
                default:
                    vprintf_help(*format, &ptr);
                    break;
            }

            format++;

            break;
        }
    }
}

unsigned String::print(char *buffer, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(reinterpret_cast<void*> (buffer), fmt, args);
    va_end(args);
    *(buffer + count) = '\0';
    unsigned n = count;
    count = 0;
    return n;
}

void String::print_page(char *buffer, void* page_addr){
    uint32* uint32_page_addr = reinterpret_cast<uint32*>(page_addr);
    print(buffer, "%p ========================================", page_addr);
    for(int i = 0; i< 0x100; i++){
        print(buffer, "%p: %08x %08x %08x %08x", uint32_page_addr, *uint32_page_addr, *(uint32_page_addr+1), *(uint32_page_addr+2), *(uint32_page_addr+3));
        uint32_page_addr+=4;
    }
}
void String::print_memory(char *buffer, void* start_addr, int length = 32){
    uint8* uint8_addr = reinterpret_cast<uint8*>(start_addr);
    int line = length / 32;
    print(buffer, "*p: %p", uint8_addr);
    for(int i = 0; i < line; i++){
        for(int j = 0; j < 32; j++){
            print(buffer, "%02x", *uint8_addr);
            uint8_addr++;
        }
        *buffer++ =' ';
    }
    for(int j = 0; j < length - 32*line; j++){
        print(buffer, "%02x", *uint8_addr);
        uint8_addr++;
    }
    print(buffer, "\n");
}

/**
 * this function creates allocates and returns a block of nb_of_bytes octets from 
 * free_blocks circular list. It runs through the free_blocks list and pick the first fit.
 * Inspired from Marc Lobelle, http://www.foditic.org/C2_08/missions/malloc_free_solution.php
 * @param nb_of_bytes : number of querried octets
 * @return 
 */
Block* Block::alloc(size_t nb_bytes) {
    assert(nb_bytes);
    if(!initialized) // If this is the first time it is called
        initialize();
    Block* curr = alloc_from_cursor(nb_bytes);
    if(!curr) {
        curr = free_blocks.head();
        Block *h = free_blocks.head();
        if(curr) {
            bool loop_started = false;
            while (curr->size < nb_bytes) {
                if(loop_started && curr == h) // A complete tour has been done
                    break;
                curr = curr->next;
                loop_started = true;
            }
            // We got the first fit free_blocks
            if (curr->size == nb_bytes) {
                //No need to create a new block, just dequeue and return it 
                curr->is_free = false;
                cursor = (curr == curr->next) ? nullptr : curr->next;
                assert(free_blocks.dequeue(curr));
                used_blocks.enqueue(curr);
            } else if (curr->size > nb_bytes) { 
                //Truncate it in order to create a new block and set it not free.
                Block *b = new Block(curr->start, nb_bytes, false);
                curr->start += nb_bytes;
                curr->size -= nb_bytes;
                curr->is_free = true;
                cursor = curr;
                curr = b;
            } else {
                curr = realloc(nb_bytes);
            }
        } else {
//            trace(0, "Head Null : No sufficient memory to allocate to string, Tour %lu required %lu", tour, nb_bytes);
            curr = realloc(nb_bytes);
        }
    }
    if(!reallocated) {
        free_memory -= nb_bytes;
//        trace(0, "curr %p freeblock %p %lu required %lx left %lx", curr->start, free_blocks.head()->start, free_blocks.size(), nb_bytes, left());    
    }
    reallocated = false;
    return curr;    
}

/**
 * called to delete a certain percentage of log (default 10%), defragment if needed 
 * and try to alloc again
 */
Block* Block::realloc(size_t nb_bytes) {
    // Heap exhausted, free 100% - LOG_PERCENT_TO_BE_LEFT of log to recover fresh memory. 
    size_t l = left(), s = free_blocks.size();
    trace(0, "No sufficient memory to allocate to string, Tour %lu required %lu "
            "free_memory %lu left %lu nbBlocks %lu moyenne %luo", tour, nb_bytes, 
            free_memory, l, s, s ? l/s : 0);
    assert(l == free_memory);
    Logstore::free_logs(LOG_PERCENT_TO_BE_LEFT, true);   
    l = left(); s = free_blocks.size(); free_memory = l; 
    assert(s > 0);// s should > 0
    trace(0, "After left %lu nbBlocks %lu moyenne %luo", l, s, s ? l/s : 0);
    if(l / s < static_cast<size_t>(STR_MAX_LENGTH*(memory_order + 
            static_cast<unsigned short>(PAGE_BITS)))){
        defragment();        
        print();
    }
    tour++;
    cursor = free_blocks.head();
    if(reallocated) {
        Console::panic("free_logs() (and may be defragment()) didn't solve space problem");
    }
    reallocated = true;
        // Try to alloc again. This should succed.
    return alloc(nb_bytes);
}

/**
 * called to alloc from the last allocation place called cursor.
 * This is the first allocation attempt
 * @param nb_bytes
 * @return 
 */
Block* Block::alloc_from_cursor(size_t nb_bytes) {
    if(!cursor)
        return nullptr;
    if (cursor->size == nb_bytes) {
// curr->size == nb_of_bytes: No need to create a new block, just dequeue and return it 
        Block *b = cursor;
        cursor = (cursor == cursor->next) ? nullptr : cursor->next; 
        b->is_free = false;
        assert(free_blocks.dequeue(b));
        used_blocks.enqueue(b);
        return b;
//        trace(0, "%lu %p required %lx left %lx", curr->numero, curr->start, nb_of_bytes, left());
    } else if (cursor->size > nb_bytes) { 
        // size > nb_of_bytes : Truncate it in order to create a new block and 
        // set it not free.
        Block *b = new Block(cursor->start, nb_bytes, false);
        cursor->start += nb_bytes;
        cursor->size -= nb_bytes;
        cursor->is_free = true;
        return b;
    } else {
        return nullptr;
    }
}
/**
 * Free the current bloc by returning it to free_blocks list. Merge it with 
 * adjacent previous block and delete its object if it is mergeable, if not, 
 * insert it in the right place. In free_blocks, blocks are ordered by their address
 * This fuction is called only if the block free state is false.
 */
void Block::free_mem() {
    bool to_be_deleted = false; // to record if this block is to be deleted (mergeable) 
    free_memory += size; // this->size may be modified in this function, so do this quickly
    used_blocks.dequeue(this);
    Block *curr = free_blocks.head(), *h = free_blocks.head(), *curr_prev = nullptr;
//    assert(curr && !is_free);
    is_free = true;  // set its free state to true;   
    bool loop_started = false;
    while (curr && curr->start < start){
        if(loop_started && curr == h) // Complete tour of the circular list is done
            break;
        curr_prev = curr;
        curr = curr->next;
        loop_started = true;
    }
    if (curr == h) {
        if(loop_started) {
// we made a complete tour; right place is at the botom of the list
            free_blocks.enqueue(this);
            curr_prev = prev;
        } else {
// if right place is at the head of free_blocks list, insert it at the head
            free_blocks.enhead(this); 
            curr_prev = this;         /* we'll need that in the next step */
        }
    } else if(curr_prev->start + curr_prev->size == start) { // mergeable?
        curr_prev->size += size;
        to_be_deleted = true; // This object exists no more, should be deleted
    } else { // Insert it betwen curr_prev and curr
        next = curr;
        prev = curr_prev;
        curr_prev->next = this;
        curr->prev = this;
    }
    /* if previousarea is now contiguous with previousarea->nextchunk, attach them */
    Block *curr_prev_next = curr_prev->next;
    if(curr_prev->start + curr_prev->size == curr_prev_next->start){ // mergeable ?
        curr_prev->size += curr_prev_next->size;
        curr_prev->next = curr_prev_next->next;
        curr_prev_next->next->prev = curr_prev;
        if(curr_prev_next == cursor)
            cursor = curr_prev;
        delete curr_prev_next;
    }
    if(to_be_deleted)
        delete this;
}

/**
 * For debugging, Just to know the total remaining free size
 * @return 
 */
size_t Block::left() { 
    if(!initialized)
        initialize();
    size_t total_size = 0;
    Block *curr = free_blocks.head(), *n = nullptr;
    while (curr) {
        total_size += curr->size;
        n = curr->next;
        curr = (n == free_blocks.head()) ? nullptr : n;
    }
    return total_size;
}

/**
 * For debugging, Just to know the total remaining free size
 * @return 
 */
void Block::print() { 
    Block *b = free_blocks.head(), *n = nullptr;
    if(!b)
        return;
    trace(0, "Beging==========================================================");
    while (b) {
        trace(0, "Prev %p :: B %p (%p -> %p : %lx) : %s :: Next %p", 
                b->prev, b, b->start, b->start + b->size, b->size, b->start, b->next);
        n = b->next;
        assert(n->prev == b);
        b = (n == free_blocks.head()) ? nullptr : n;
    }
    trace(0, "End    ==========================================================\n");    
}

void Block::defragment() {
    Block *b = used_blocks.head(), *h = used_blocks.head(), *n = nullptr;
    char* start_ptr1 = reinterpret_cast<char*>(memory);
    size_t total_used_size = 0, used = memory_size - free_memory, init = used/PAGE_SIZE;
    unsigned short order = 0;
    while(init) {
        order++;
        init /=2;
    }
    trace(0, "Defrag used %lu order %u", used, order);
    char *buff = reinterpret_cast<char*>(Buddy::allocator.alloc (order, Pd::kern.quota, Buddy::FILL_0)); 
    char* start_ptr2 = buff;
    b = used_blocks.head(); h = used_blocks.head(); n = nullptr;
    while(b) {
        total_used_size += b->size;
        copy_string(start_ptr2, b->start, b->size);
        b->start = start_ptr1;
        start_ptr1 += b->size; 
        start_ptr2 += b->size;
        n = b->next;
        b = (n == h) ? nullptr : n;
    }
    assert(total_used_size == memory_size - free_memory);
    memset(memory, 0, memory_size);
    memcpy(memory, reinterpret_cast<void*>(buff), total_used_size);
    Buddy::allocator.free(reinterpret_cast<mword>(buff), Pd::kern.quota);
    while(free_blocks.dequeue(b = free_blocks.head())) {
        delete b;
    }
    cursor = new Block(start_ptr1, memory_size - total_used_size, true);
}

/**
 * Append a string of character to this string. The old buffer is destroyed; a 
 * new one is allocated, wide enough to hold the entire new string of characters
 * @param s
 */
void String::append(const char* s){
    if(buffer) { // This string didn't have a buffer yet, we shall allocate one with 1 byte
        size_t len1 = length, len2 = strlen(s);
        length += len2 + 1;
        Block* old_buffer = buffer;
        buffer = Block::alloc(length + 1);
        copy_string(buffer->start, old_buffer->start, len1);
        *(buffer->start + len1) = ' ';
        copy_string(buffer->start + len1 + 1, s, len2);
        old_buffer->~Block();
    } else {
        length = strlen(s);
        buffer = Block::alloc(length + 1);
        copy_string(buffer->start, s, length);
    }
}

/**
 * Replace this string old buffer with a new one and fill it with the provided 
 * string of character s
 * @param s
 */
void String::replace_with(const char* s) {
    length = strlen(s);
    if(buffer)
        buffer->~Block();
    buffer = Block::alloc(length + 1);
    copy_string(buffer->start, s, length);
}

/**
 * Frees this string's buffer but do not destroy it.
 */
void String::free_buffer() {
    if(buffer) {
        buffer->~Block();
    }
    buffer = nullptr;
    length = 0;
}
  

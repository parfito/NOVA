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
 * The String class implementation relies heavily on 
 * http://www.cplusplus.com/forum/general/168314/
 */

#pragma once

#include "compiler.hpp"
#include "types.hpp"
#include "config.hpp"
#include "util.hpp"
#include "pd.hpp"
#include "queue.hpp"

extern "C" NONNULL
inline void *memcpy(void *dst, const void *src, size_t n) {
    const char *s;
    char *d;

    s = reinterpret_cast<const char*> (src);
    d = reinterpret_cast<char*> (dst);
    if (s < d && s + n > d) {
        s += n;
        d += n;
        if ((mword) s % 4 == 0 && (mword) d % 4 == 0 && n % 4 == 0)
            asm volatile("std; rep movsl\n"
                        ::"D" (d - 4), "S" (s - 4), "c" (n / 4) : "cc", "memory");
        else
            asm volatile("std; rep movsb\n"
                        ::"D" (d - 1), "S" (s - 1), "c" (n) : "cc", "memory");
        // Some versions of GCC rely on DF being clear
        asm volatile("cld" :: : "cc");
    } else {
        if ((mword) s % 4 == 0 && (mword) d % 4 == 0 && n % 4 == 0)
            asm volatile("cld; rep movsl\n"
                        ::"D" (d), "S" (s), "c" (n / 4) : "cc", "memory");
        else
            asm volatile("cld; rep movsb\n"
                        ::"D" (d), "S" (s), "c" (n) : "cc", "memory");
    }
    return dst;
}

/**
 * 
 * @param dest
 * @param source
 * @param max_length : is the buffer size of dest when it was declared
 */
extern "C" NONNULL
inline size_t copy_string(char *target, const char *source, size_t dest_max_length = STR_MAX_LENGTH) {
    size_t length = 0;
    while (*source && length<dest_max_length) {
        *target = *source;
        source++;
        target++;
        length++;
    }
    *target = '\0';
    return length;
}

//extern "C" NONNULL
//inline void *memcpy(void *d, void const *s, size_t n) {
//    mword dummy;
//    asm volatile ("rep; movsb"
//                : "=D" (dummy), "+S" (s), "+c" (n)
//                : "0" (d)
//                : "memory");
//    return d;
//}

extern "C" NONNULL
inline void *memset(void *d, int c, size_t n) {
    mword dummy;
    asm volatile ("rep; stosb"
                : "=D" (dummy), "+c" (n)
                : "0" (d), "a" (c)
                : "memory");
    return d;
}

extern "C" NONNULL
inline int strcmp(char const *s1, char const *s2) {
    while (*s1 && *s1 == *s2)
        s1++, s2++;

    return *s1 - *s2;
}

extern "C" NONNULL
inline bool strmatch (char const *s1, char const *s2, size_t n)
{
    if (!n) return false;

    while (*s1 && *s1 == *s2 && n)
        s1++, s2++, n--;

    return n == 0;
}

extern "C" NONNULL
inline int strmemcmp(char const *s1, char const *s2, int &addr, int n) {
    while (n && *s1 == *s2)
        s1++, s2++, n--;
    addr = n;
    return n;
}

/**
 * fonction a n'utiliser que pour comparer des tailles multiples de 4 et page aligned ex: 4ko
 * @param s1
 * @param s2
 * @param len
 * @return 
 */
extern "C" NONNULL
inline int page_comp(const void *s1, const void *s2, size_t &addr, size_t size) {
    size_t len = size / 4; // cmpsl compare double word (4 bytes)
    int diff = 0;
    asm volatile (
    	"cld;"
	"repe cmpsl;"
	"jne	1f;"			
	"movl	$0, %1;"		
        "jmp    2f;"
"1:	movl	$1, %1;"			
"2:	movq	%%rcx, %0\n"
        : "=qm" (addr), "=qm" (diff), "+D" (s1), "+S" (s2), "+c" (len));
    addr = size - 4*(addr + 1);
    return diff;
}

/*
 * Normalizes an instruction printing in hexadecimal format so that it may be given as input to 
 * disassembler (in https://defuse.ca/online-x86-assembler.htm#disassembly2)  
 * Eg of input  : 8348eb7530483948 as mword
 * Eg of output : 4839483075eb4883 as char*
 */
extern "C" NONNULL

inline void instruction_in_hex(mword instr, char *buffer ) {
    uint8* u = reinterpret_cast<uint8*>(&instr);
    int size = sizeof(mword);
    assert(size < 9);
    char buff[3]; // 2 (each uint8 (byte) is two characters long) + 1 ('\0')
    char *p_buffer = buffer, *p_buff ;
    for(int i = 0; i<size; i++){
        to_string(*(u+i), buff);
        p_buff = buff;
        uint8 j = 0;
        while(*p_buff){
            *p_buffer++ = *p_buff++;            
            assert(j++ < 3);
        }
    }
    *p_buffer = '\0';
}

extern "C" NONNULL
inline int str_equal(char const *s1, char const *s2) {
    return !strcmp(s1, s2) ? 1 : 0;
}

extern "C" NONNULL
inline size_t strlen(const char* str){
    const char *p = str;
    size_t n = 0;
    while(*p++ != '\0'){
        n++;
    }
    return n;
}

class Block {
    friend class String;
    friend class Queue<Block>;
private:
    static Slab_cache cache;   // To make place for the block object in memory 
    static void *memory;       // Our heap start pointer
    static unsigned short memory_order; // 2^memory_order *4Ko will be dedicated to this heap 
    static size_t tour, memory_size, free_memory;  
    static bool reallocated, initialized, first_realloc;
    static Block* cursor;
    static Queue<Block> free_blocks, used_blocks;  // circular list of available blocks
    
    char* start; // start address of block
    size_t size; // size of block
    bool is_free; // free state of block                             
    Block *prev = nullptr; // previous block in the free_blocks list
    Block *next = nullptr; // next block in the free_blocks list
    
    Block(char* st, size_t s, bool is_f) : start(st), size(s), is_free(is_f) {
        if(is_f)
            free_blocks.enqueue(this);
        else
            used_blocks.enqueue(this);
        
    }

    /**
     * Called when the first block is requested to allocate the heap.
     * At this stage, free_blocks is constitued of one big block of 
     * memory_size ==  2^memory_order *4Ko 
     */
    static void initialize() {
        memory = Buddy::allocator.alloc (memory_order, Pd::kern.quota, Buddy::FILL_0);
        cursor = new Block(reinterpret_cast<char*>(memory), memory_size, true);
        initialized = true;
    }
    
    /**
     * To reset memory. This function is not used now
     */
    static void reset_string_mem() {
        memset(memory, 0, memory_size);
        Block *b = nullptr;
        while(free_blocks.dequeue(b = free_blocks.head())) {
            delete b;
    }
        cursor = new Block(reinterpret_cast<char*>(memory), memory_size, true); 
    }

    void free_mem(); // To free the memory backend of a block;
    
public:
    ALWAYS_INLINE
    static inline void *operator new(size_t) {return cache.alloc(Pd::kern.quota);}

    ALWAYS_INLINE
    static inline void operator delete(void *ptr) {cache.free (ptr, Pd::kern.quota);}
    
    Block(const Block& orig);
        
    Block &operator=(Block const &);
    
    ~Block() { 
        if(!is_free) free_mem(); 
    };

    static Block* alloc(size_t);    
    static Block* realloc(size_t);    
    static Block* alloc_from_cursor(size_t);    
    static size_t left();
    static void print();
    static void defragment();
};

class String {
private:
    static Slab_cache cache;    
    enum
    {
        MODE_FLAGS      = 0,
        MODE_WIDTH      = 1,
        MODE_PRECS      = 2,
        FLAG_SIGNED     = 1UL << 0,
        FLAG_ALT_FORM   = 1UL << 1,
        FLAG_ZERO_PAD   = 1UL << 2,
    };
    size_t length = 0;
    Block* buffer = nullptr;
    static unsigned count;
    static void print_num (uint64, unsigned, unsigned, unsigned, void**);
    static void print_str (char const *, unsigned, unsigned, void**);
    static int vprintf_help(int , void **);
        
    FORMAT (2,0)
    static void vprintf (void *, char const *, va_list);
        
public:
    ALWAYS_INLINE
    static inline void *operator new (size_t) {return cache.alloc(Pd::kern.quota);}

    ALWAYS_INLINE
    static inline void operator delete (void *ptr) {
        cache.free (ptr, Pd::kern.quota);
    }
    
    String(const String& orig);
    String(){}
        
    String &operator=(String const &);

    String(const char *);
    String(size_t);
    ~String() { buffer->~Block(); }
    char* get_string() {
        if(buffer)
            return buffer->start;
        else {
            return nullptr;
        }
    }
    void append(const char*);
    void replace_with(const char*);
    void free_buffer();
    
    FORMAT (2,3)
    static unsigned print (char *, char const *, ...);
    static void print_page(char *, void *);
    static void print_memory(char *, void*, int);
};
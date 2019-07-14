/*
 * String Functions
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
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

#pragma once

#include "compiler.hpp"
#include "types.hpp"
#include "config.hpp"
#include "util.hpp"

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

extern "C" NONNULL
inline void copy_string(char *target, const char *source) {
    uint32 length = 1;
    while (*source) {
        *target = *source;
        source++;
        target++;
        length++;
    }
    *target = '\0';
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
inline int memcmp(const void *s1, const void *s2, size_t &addr, size_t size) {
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
    char buff[3]; // 2 (each uint8 (byte) is two characters long) + 1 ('\0')
    char *p_buffer = buffer, *p_buff ;
    for(int i = 0; i<size; i++){
        to_string(*(u+i), buff);
        p_buff = buff;
        while(*p_buff){
            *p_buffer++ = *p_buff++;
        }
    }
    *p_buffer = '\0';
}

extern "C" NONNULL
inline int str_equal(char const *s1, char const *s2) {
    return !strcmp(s1, s2) ? 1 : 0;
}

/*
 * http://bxr.su/OpenBSD/lib/libc/string/strncat.c
 * Concatenate src on the end of dst.  At most strlen(dst)+n+1 bytes
 * are written at dst (at most n+1 bytes being appended).  Return dst.
 */
extern "C" NONNULL 
inline char* strcat(char *dst, const char *src, size_t n){
    if (n != 0) {
        char *d = dst;
        const char *s = src;

        while (*d != '\0')
            d++;
        do {
            if ((*d = *s++) == '\0')
                break;
            d++;
        } while (--n != 0);
        *d = '\0';
    }
    return (dst);
}
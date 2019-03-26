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

extern "C" NONNULL
inline void *memcpy (void *d, void const *s, size_t n)
{
    mword dummy;
    asm volatile ("rep; movsb"
                  : "=D" (dummy), "+S" (s), "+c" (n)
                  : "0" (d)
                  : "memory");
    return d;
}

extern "C" NONNULL
inline void *memset (void *d, int c, size_t n)
{
    mword dummy;
    asm volatile ("rep; stosb"
                  : "=D" (dummy), "+c" (n)
                  : "0" (d), "a" (c)
                  : "memory");
    return d;
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
inline int strcmp(char const *s1, char const *s2) {
    while (*s1 && *s1 == *s2)
        s1++, s2++;

    return *s1 - *s2;
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
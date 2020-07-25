/*
 * Utility Functions
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

template <typename T>
ALWAYS_INLINE
static inline T min(T v1, T v2) {
    return v1 < v2 ? v1 : v2;
}

template <typename T>
ALWAYS_INLINE
static inline T max(T v1, T v2) {
    return v1 > v2 ? v1 : v2;
}

template <typename T>
ALWAYS_INLINE
static inline T distance(T v1, T v2) {
    return v1 > v2 ? v1 - v2 : v2 - v1;
}


template <typename T>
inline uint32 log16(T num) {
    uint32 log = 0;
    while (num >= 16) {
        num /= 16;
        log += 1;
    }
    return log;
}
/**
 * store a number as hexadecimal string format  
 * @param number : the number to convert
 * @param string : holds its hexadecimal form
 */
template <typename T>
inline void to_string(T number, char *string) {
    uint32 n = log16(number) + 1;
    uint32 i;
    for (i = 0; i < n; ++i, number /= 16) {
        T mod = number%16;
        uint32 shift = mod<10 ? '0' : 87; // 'a' - 10
        string[n-i-1] = static_cast<char> ((number % 16) + shift);
    }
    string[n] = '\0';
}

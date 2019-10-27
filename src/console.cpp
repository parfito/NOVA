/*
 * Generic Console
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012-2013 Udo Steinberg, Intel Corporation.
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

#include "bits.hpp"
#include "console.hpp"
#include "lock_guard.hpp"
#include "x86.hpp"
#include "log_store.hpp"

Console *Console::list;
Spinlock Console::lock;
unsigned Console::count;
bool Console::print_on = false;

void Console::print_num (uint64 val, unsigned base, unsigned width, unsigned flags)
{
    bool neg = false;

    if (flags & FLAG_SIGNED && static_cast<signed long long>(val) < 0) {
        neg = true;
        val = -val;
    }

    char buffer[24], *ptr = buffer + sizeof buffer;

    do {
        uint32 r;
        val = div64 (val, base, &r);
        *--ptr = r["0123456789abcdef"];
    } while (val);

    if (neg)
        *--ptr = '-';

    unsigned long count = buffer + sizeof buffer - ptr;
    unsigned long n = count + (flags & FLAG_ALT_FORM ? 2 : 0);

    if (flags & FLAG_ZERO_PAD) {
        if (flags & FLAG_ALT_FORM) {
            putc ('0');
            putc ('x');
        }
        while (n++ < width)
            putc ('0');
    } else {
        while (n++ < width)
            putc (' ');
        if (flags & FLAG_ALT_FORM) {
            putc ('0');
            putc ('x');
        }
    }

    while (count--)
        putc (*ptr++);
}

void Console::print_str (char const *s, unsigned width, unsigned precs)
{
    if (EXPECT_FALSE (!s))
        return;

    unsigned n;

    for (n = 0; *s && precs--; n++)
        putc (*s++);

    while (n++ < width)
        putc (' ');
}

void Console::vprintf (char const *format, va_list args)
{
    while (*format) {

        if (EXPECT_TRUE (*format != '%')) {
            putc (*format++);
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
                        case MODE_WIDTH: width = width * 10 + *format - '0'; break;
                        case MODE_PRECS: precs = precs * 10 + *format - '0'; break;
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
                    putc (va_arg (args, int));
                    break;

                case 's':
                    print_str (va_arg (args, char *), width, precs ? precs : ~0u);
                    break;

                case 'd':
                    switch (len) {
                        case 0:  u = va_arg (args, int);        break;
                        case 1:  u = va_arg (args, long);       break;
                        default: u = va_arg (args, long long);  break;
                    }
                    print_num (u, 10, width, flags | FLAG_SIGNED);
                    break;

                case 'u':
                case 'x':
                    switch (len) {
                        case 0:  u = va_arg (args, unsigned int);        break;
                        case 1:  u = va_arg (args, unsigned long);       break;
                        default: u = va_arg (args, unsigned long long);  break;
                    }
                    print_num (u, *format == 'x' ? 16 : 10, width, flags);
                    break;

                case 'p':
                    print_num (reinterpret_cast<mword>(va_arg (args, void *)), 16, width, FLAG_ALT_FORM);
                    break;

                case 0:
                    format--;

                default:
                    putc (*format);
                    break;
            }

            format++;

            break;
        }
    }

    putc ('\n');
}

void Console::print (char const *format, ...)
{
    Lock_guard <Spinlock> guard (lock);

    for (Console *c = list; c; c = c->next) {
        va_list args;
        va_start (args, format);
        c->vprintf (format, args);
        va_end (args);
    }
}

void Console::vprintf_no_newline (char const *format, va_list args)
{
    while (*format) {

        if (EXPECT_TRUE (*format != '%')) {
            putc (*format++);
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
                        case MODE_WIDTH: width = width * 10 + *format - '0'; break;
                        case MODE_PRECS: precs = precs * 10 + *format - '0'; break;
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
                    putc (va_arg (args, int));
                    break;

                case 's':
                    print_str (va_arg (args, char *), width, precs ? precs : ~0u);
                    break;

                case 'd':
                    switch (len) {
                        case 0:  u = va_arg (args, int);        break;
                        case 1:  u = va_arg (args, long);       break;
                        default: u = va_arg (args, long long);  break;
                    }
                    print_num (u, 10, width, flags | FLAG_SIGNED);
                    break;

                case 'u':
                case 'x':
                    switch (len) {
                        case 0:  u = va_arg (args, unsigned int);        break;
                        case 1:  u = va_arg (args, unsigned long);       break;
                        default: u = va_arg (args, unsigned long long);  break;
                    }
                    print_num (u, *format == 'x' ? 16 : 10, width, flags);
                    break;

                case 'p':
                    print_num (reinterpret_cast<mword>(va_arg (args, void *)), 16, width, FLAG_ALT_FORM);
                    break;

                case 0:
                    format--;

                default:
                    putc (*format);
                    break;
            }

            format++;

            break;
        }
    }
}

void Console::print_no_newline (char const *format, ...)
{
    Lock_guard <Spinlock> guard (lock);

    for (Console *c = list; c; c = c->next) {
        va_list args;
        va_start (args, format);
        c->vprintf_no_newline (format, args);
        va_end (args);
    }
}

void Console::panic (char const *format, ...)
{
    {   Lock_guard <Spinlock> guard (lock);

        for (Console *c = list; c; c = c->next) {
            va_list args;
            va_start (args, format);
            c->vprintf (format, args);
            va_end (args);
        }
    }
    
    Logstore::dump("Panic", true);                                                          \
    shutdown();
}

void Console::print_page(void* page_addr){
    uint32* uint32_page_addr = reinterpret_cast<uint32*>(page_addr);
    for(int i = 0; i< 0x100; i++){
        print("%p: %08x %08x %08x %08x", uint32_page_addr, *uint32_page_addr, *(uint32_page_addr+1), *(uint32_page_addr+2), *(uint32_page_addr+3));
        uint32_page_addr+=4;
    }
    print("=====================================================");
}

void Console::print_memory(void* start_addr, int length = 32){
    uint8* uint8_addr = reinterpret_cast<uint8*>(start_addr);
    int line = length / 32;
    print("*p: %p", uint8_addr);
    for(int i = 0; i < line; i++){
        for(int j = 0; j < 32; j++){
            print_no_newline("%02x", *uint8_addr);
            uint8_addr++;
        }
        print(" ");
    }
    for(int j = 0; j < length - 32*line; j++){
        print_no_newline("%02x", *uint8_addr);
        uint8_addr++;
    }
    print(" ");
    print("=====================================================");
}

extern "C" NORETURN void __cxa_pure_virtual() { UNREACHED; }

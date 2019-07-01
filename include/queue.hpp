/*
 * Queue
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012-2013 Udo Steinberg, Intel Corporation.
 * Copyright (C) 2014 Udo Steinberg, FireEye, Inc.
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
class Queue
{
    private:
        T *headptr;
        T *tailptr;

    public:
        ALWAYS_INLINE
        inline Queue() : headptr (nullptr), tailptr(nullptr) {}

        ALWAYS_INLINE
        inline T *head() const { return headptr; }

        ALWAYS_INLINE
        inline T *tail() const { return headptr ? headptr->prev : tailptr; }

        ALWAYS_INLINE
        inline void enqueue (T *t)
        {
            if (!headptr)
                headptr = t->prev = t->next = t;
            else {
                t->next = headptr;
                t->prev = headptr->prev;
                t->next->prev = t->prev->next = t;
            }
        }

        /**
         * retrieve t from the head
         * @param t
         * @return true if t is valid object of the queue, in this case it is retrieve from the head
         */
        ALWAYS_INLINE
        inline bool dequeue (T *t)
        {
            if (!t || !t->next || !t->prev)
                return false;

            if (t == t->next)
                headptr = nullptr;

            else {
                t->next->prev = t->prev;
                t->prev->next = t->next;
                if (t == headptr)
                    headptr = t->next;
            }

            t->next = t->prev = nullptr;

            return true;
        }
        
        /**
         * 
         * @return the size of the queue
         */
        ALWAYS_INLINE
        inline size_t size ()
        {
            T *c = headptr, *n = nullptr;
            size_t count = 0;
            while(c) {
                count++;
                n = c->next;
                c = (c == n || n == headptr) ? nullptr : n;
            }
            return count;
        }
};

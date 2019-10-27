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
#include "assert.hpp"

template <typename T>
class Queue
{
    private:
        T *headptr;

    public:
        ALWAYS_INLINE
        inline Queue() : headptr (nullptr) {}

        ALWAYS_INLINE
        inline T *head() const { return headptr; }

        ALWAYS_INLINE
        inline T *tail() const { return headptr ? headptr->prev : nullptr; }

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

        ALWAYS_INLINE
        inline void enhead (T *t)
        {
            if (!headptr)
                headptr = t->prev = t->next = t;
            else {
                t->next = headptr;
                t->prev = headptr->prev;
                headptr->prev = t;
                t->prev->next = t;
                headptr = t;
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
        
        /**
         *
         * @param t
         * @return true if the queue contains t
         */
        ALWAYS_INLINE
        inline bool contains (T *t)
        {
            T *c = headptr, *n = nullptr;
            while(c) {
                if(c == t)
                    return true;
                n = c->next;
                c = (c == n || n == headptr) ? nullptr : n;
            }
            return false;
        }
        
        /**
         * find the index of object t 
         * @param t
         * @param index to fill if t was found
         * @return true if the object t was found, in this case index is valid
         */
        ALWAYS_INLINE
        inline bool index_of (T *t, size_t &index)
        {
            T *c = headptr, *n = nullptr;
            index = 0;
            while(c) {
                if(c == t){
                    return true;
                }
                index++;
                n = c->next;
                c = (c == n || n == headptr) ? nullptr : n;
            }
            return false;
        }
        
        /**
         * swap elements position 
         * @param t1, 
         * @param t2
         * @return true if the object t1 et t2 are valid object of the queue, in this case it swap
         */
        ALWAYS_INLINE
        bool swap(T *&t1, T *&t2){
            if (!t1 || !t1->next || !t1->prev)
                return false;
            if (!t2 || !t2->next || !t2->prev)
                return false;
            T *t1_prev = t1->prev, *t1_next = t1->next, *t2_prev = t2->prev, *t2_next = t2->next;
            
            T *temp = t1;
            t1 = t2;
            t2 = temp;
            t1_prev->next = t1;
            t1_next->prev = t1;
            t2_prev->next = t2;
            t2_next->prev = t2;
            t1->next = t1_next;
            t1->prev = t1_prev;
            t2->next = t2_next;
            t2->prev = t2_prev;
            return true;
        }
};

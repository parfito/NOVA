/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/* 
 * File:   Pe_stack.cpp
 * Author: parfait
 *
 * Created on 6 mai 2019, 13:26
 */

#include "pe_stack.hpp"
#include "pd.hpp"
#include "cow_elt.hpp"
#include "stdio.hpp"

Slab_cache Pe_stack::cache(sizeof (Pe_stack), 32);
Queue<Pe_stack> Pe_stack::detected_stacks;
mword Pe_stack::stack;

Pe_stack::Pe_stack(mword v, Paddr p, mword a, Vtlb *t, Hpt *h): rsp(v), phys(p), attr(a), hpt(h), tlb(t), prev(nullptr), next(nullptr) { }

Pe_stack::~Pe_stack() {
}
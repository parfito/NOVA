/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pe.cpp
 * Author: parfait
 * 
 * Created on 16 septembre 2019, 20:16
 */

#include "pe.hpp"
uint8 Pe::run_number = 0;
bool Pe::inState1 = false, Pe::in_debug_mode = false, Pe::pmi_pending = false, 
    Pe::in_triple_exec = false;
mword Pe::missmatch_addr, Pe::guest_rip[3], Pe::guest_rsp[3], Pe::guest_rflags[3];
void* Pe::missmatch_ptr;
unsigned Pe::vmlaunch = 0;

Cpu_regs Pe::c_regs[];

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
bool Pe::inState1 = false, Pe::in_debug_mode = false, Pe::pmi_pending = false;
mword Pe::missmatch_addr, Pe::vmcsRIP[], Pe::vmcsRSP[], Pe::vmcsRIP_0, 
        Pe::vmcsRIP_1, Pe::vmcsRIP_2, Pe::vmcsRSP_0, Pe::vmcsRSP_1, Pe::vmcsRSP_2;
void* Pe::missmatch_ptr;
unsigned Pe::vmlaunch = 0;

Cpu_regs Pe::c_regs[];

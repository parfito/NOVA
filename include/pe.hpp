/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Pe.hpp
 * Author: parfait
 *
 * Created on 16 septembre 2019, 20:16
 */
#pragma once
#include "types.hpp"
#include "regs.hpp"

class Pe {
public:
    static uint8 run_number;
    static unsigned vmlaunch;
    
    static Cpu_regs c_regs[4]; //current_regs
    static mword vmcsRIP[4], vmcsRSP[4], vmcsRIP_0, vmcsRIP_1, vmcsRIP_2, vmcsRSP_0, vmcsRSP_1, vmcsRSP_2;
    static bool inState1, in_debug_mode;
    static bool pmi_pending;
    static mword missmatch_addr;
    static void* missmatch_ptr;
};

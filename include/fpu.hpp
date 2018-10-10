/*
 * Floating Point Unit (FPU)
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012 Udo Steinberg, Intel Corporation.
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

#include "cpu.hpp"
#include "hazards.hpp"
#include "slab.hpp"
#include "x86.hpp"
#include "string.hpp"

class Fpu
{
    private:
        static unsigned const data_size = 512, state_size = 108;
        char data[data_size];
        static char statedata[state_size], statedata_0[state_size], statedata_1[state_size], statedata_2[state_size], data_0[data_size], data_1[data_size], data_2[data_size];
        static Slab_cache cache;
        static bool is_saved;
        
        ALWAYS_INLINE
        static inline bool is_enabled() { return !(get_cr0() & (Cpu::CR0_TS|Cpu::CR0_EM)); }

        ALWAYS_INLINE
        inline static void save_state(char* to) { asm volatile ("fsave %0" : "=m" (*to)); }

        ALWAYS_INLINE
        inline static void load_state(char *from) { asm volatile ("frstor %0" : : "m" (*from)); }

    public:
        static Fpu *fpu_0, *fpu_1, *fpu_2;
        ALWAYS_INLINE
        inline void save() { asm volatile ("fxsave %0" : "=m" (*data)); }

        ALWAYS_INLINE
        inline void load() { asm volatile ("fxrstor %0" : : "m" (*data)); }

        ALWAYS_INLINE
        static inline void init() { asm volatile ("fninit"); }

        ALWAYS_INLINE
        static inline void enable() { asm volatile ("clts"); Cpu::hazard |= HZD_FPU; }
        
        ALWAYS_INLINE
        static inline void disable() { set_cr0 (get_cr0() | Cpu::CR0_TS); Cpu::hazard &= ~HZD_FPU; }

        ALWAYS_INLINE
        static inline void *operator new (size_t, Quota &quota) { return cache.alloc(quota); }

        ALWAYS_INLINE
        static inline void destroy(Fpu *obj, Quota &quota) { obj->~Fpu(); cache.free (obj, quota); }
        
        static void dwc_save(){ 
            if(get_cr0() & (Cpu::CR0_TS | Cpu::CR0_EM))
                return;
            fpu_0->save();
            save_state(statedata_0);
            load_state(statedata_0);
            is_saved = true;
        }
        
        static void dwc_restore(){
            if(get_cr0() & (Cpu::CR0_TS | Cpu::CR0_EM))
                return;
            if(!is_saved)
                Console::print("TCHA HO HO: Cpu::CR0_TS || Cpu::CR0_EM = 0 but is_saved is false - dwc_restore");// TS ou EM ont été désactivé en cours de route  
            fpu_1->save();
            save_state(statedata_1);
            fpu_0->load();
            load_state(statedata_0);
        }
        
        static void dwc_restore1(){
            if(get_cr0() & (Cpu::CR0_TS | Cpu::CR0_EM))
                return;
            if(!is_saved)
                Console::print("TCHA HO HO: Cpu::CR0_TS || Cpu::CR0_EM = 0 but is_saved is false - dwc_restore1");// TS ou EM ont été désactivé en cours de route  
            fpu_2->save();
            save_state(statedata_2);
            fpu_1->load();
            load_state(statedata_1);
        }
        
        static mword dwc_check(){
            if(get_cr0() & (Cpu::CR0_TS | Cpu::CR0_EM))
                return 0;
            if(!is_saved)
                Console::print("TCHA HO HO: Cpu::CR0_TS || Cpu::CR0_EM = 0 but is_saved is false - dwc_check");// TS ou EM ont été désactivé en cours de route  
            fpu_2->save();
            save_state(statedata_2);
            load_state(statedata_2);
            mword ret = memcmp(fpu_1->data, fpu_2->data, data_size)+memcmp(statedata_1, statedata_2, state_size);
            if(ret){
                mword d1 = memcmp(fpu_1->data, fpu_2->data, data_size),
                s1 = memcmp(statedata_1, statedata_2, state_size);
                mword state_index = (state_size / 4 - s1 - 1)*4;
                mword vals1 = *reinterpret_cast<mword*> (statedata_1 + state_index);
                mword vals2 = *reinterpret_cast<mword*> (statedata_2 + state_index);
                mword fpu_index = (data_size / 4 - d1 - 1)*4;
                mword vald1 = *reinterpret_cast<mword*> (fpu_1->data + fpu_index);
                mword vald2 = *reinterpret_cast<mword*> (fpu_2->data + fpu_index);
                Console::print("s1 %lx d1 %lx statedata_1 %p statedata_2 %p fpu_d1 %p fpu_d2 %p vals1 %lx vals2 %lx vald1 %lx vald2 %lx", 
                    s1, d1, statedata_1+state_index, statedata_2+state_index, fpu_1->data+fpu_index, fpu_2->data+fpu_index, vals1, vals2, vald1, vald2);
            }else
                is_saved = false;                
            return ret;
        }
        
        static void dwc_rollback(){
            if(get_cr0() & (Cpu::CR0_TS | Cpu::CR0_EM))
                return;
            fpu_0->load();
            load_state(statedata_0);
            is_saved = false;            
        }
        
        void save_data(){
            memcpy(data_0, data, data_size);
        }
        
        void restore_data(){
            memcpy(data_1, data, data_size);
            memcpy(data, data_0, data_size);
        }
        
        void restore_data1(){
            memcpy(data_2, data, data_size);
            memcpy(data, data_1, data_size);
        }
        
        void roll_back(){
            memcpy(data, data_0, data_size);
        }
        
        mword data_check(){
            mword ret = memcmp(data, data_1, data_size);
            if(ret){
                mword data_index = (data_size / 4 - ret - 1)*4;
                mword vald1 = *reinterpret_cast<mword*> (data + data_index);
                mword vald2 = *reinterpret_cast<mword*> (data_1 + data_index);
                Console::print("ret %lx data %p data_1 %p vald1 %lx vald2 %lx", 
                    ret, data+data_index, data_1+data_index, vald1, vald2);
            }
            return ret;
        }
};

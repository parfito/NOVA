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
#include "pd.hpp"
#include "string.hpp"
#include "stdio.hpp"
#include "log.hpp"
#include "log_store.hpp"

class Fpu
{
    private:
        static unsigned const data_size = 512, state_size = 108;
        static char statedata[state_size], statedata_0[state_size], statedata_1[state_size], 
        statedata_2[state_size], data_0[data_size], data_1[data_size], data_2[data_size];
        static uint16 fcw0, fcw1, fcw2, fsw0, fsw1, fsw2, fop0, fop1, fop2;
        static uint8 ftw0, ftw1, ftw2, res0, res1, res2;
        static uint64 fip0, fip1, fip2, fdp0, fdp1, fdp2;
        static uint32 mxcsr0, mxcsr1, mxcsr2, mxcsr_mask0, mxcsr_mask1, mxcsr_mask2;
        static Slab_cache cache;
        static bool saved;
        
        ALWAYS_INLINE
        static inline bool is_enabled() { return !(get_cr0() & (Cpu::CR0_TS|Cpu::CR0_EM)); }

        ALWAYS_INLINE
        inline static void save_state(char* to) { asm volatile ("fsave %0" : "=m" (*to)); }

        ALWAYS_INLINE
        inline static void load_state(char *from) { asm volatile ("frstor %0" : : "m" (*from)); }
        union {
            char data[data_size];
            struct {
                uint16 fcw;
                uint16 fsw;
                uint8  ftw;
                uint8  res;
                uint16 fop;
                uint64 fip;
                uint64 fdp;
                uint32 mxcsr;
                uint32 mxcsr_mask;
            };
        };

    public:
        static Fpu *fpu_0, *fpu_1, *fpu_2;
        ALWAYS_INLINE
        inline void save() { asm volatile ("fxsave %0" : "=m" (*data)); }

        ALWAYS_INLINE
        inline void load() { asm volatile ("fxrstor %0" : : "m" (*data)); }

        static void init();

        ALWAYS_INLINE
        static inline void enable() { asm volatile ("clts"); Cpu::hazard |= HZD_FPU; }
        
        ALWAYS_INLINE
        static inline void disable() { set_cr0 (get_cr0() | Cpu::CR0_TS); Cpu::hazard &= ~HZD_FPU; }

        ALWAYS_INLINE
        static inline void *operator new (size_t, Pd &pd) { return pd.fpu_cache.alloc(pd.quota); }

        ALWAYS_INLINE
        static inline void destroy(Fpu *obj, Pd &pd) { obj->~Fpu(); pd.fpu_cache.free (obj, pd.quota); }

        Fpu()
        {
            // Mask exceptions by default according to SysV ABI spec.
            fcw = 0x37f;
            mxcsr = 0x1f80;
        }
        
        static void dwc_save(){ 
            if(get_cr0() & (Cpu::CR0_TS | Cpu::CR0_EM))
                return;
            fpu_0->save();
            save_state(statedata_0);
            load_state(statedata_0);
            saved = true;
        }
        
        static void dwc_restore(){
            if(get_cr0() & (Cpu::CR0_TS | Cpu::CR0_EM))
                return;
            if(!saved){
                Logstore::dump("dwc_restore", false, 5);
                Console::panic("TCHA HO HO: Cpu::CR0_TS || Cpu::CR0_EM = 0 but is_saved is false - dwc_restore");// TS ou EM ont été désactivé en cours de route  
            }
            fpu_1->save();
            save_state(statedata_1);
            fpu_0->load();
            load_state(statedata_0);
        }
        
        static void dwc_restore1(){
            if(get_cr0() & (Cpu::CR0_TS | Cpu::CR0_EM))
                return;
            if(!saved)
                Console::panic("TCHA HO HO: Cpu::CR0_TS || Cpu::CR0_EM = 0 but is_saved is false - dwc_restore1");// TS ou EM ont été désactivé en cours de route  
            fpu_2->save();
            save_state(statedata_2);
            fpu_1->load();
            load_state(statedata_1);
        }
        
        static void dwc_restore2(){
            if(get_cr0() & (Cpu::CR0_TS | Cpu::CR0_EM))
                return;
            if(!saved)
                Console::panic("TCHA HO HO: Cpu::CR0_TS || Cpu::CR0_EM = 0 but is_saved is false - dwc_restore1");// TS ou EM ont été désactivé en cours de route  
            fpu_1->save();
            save_state(statedata_1);
            fpu_2->load();
            load_state(statedata_2);
        }        
        
        static mword dwc_check(){
            if(get_cr0() & (Cpu::CR0_TS | Cpu::CR0_EM))
                return 0;
            if(!saved)
                Console::panic("TCHA HO HO: Cpu::CR0_TS || Cpu::CR0_EM = 0 but is_saved is false - dwc_check");// TS ou EM ont été désactivé en cours de route 
           fpu_2->save();
            save_state(statedata_2);
            load_state(statedata_2);
            size_t  d1= 0, d2 = 0;
            int d_diff = page_comp(fpu_1->data, fpu_2->data, d1, data_size);
            int s_diff = page_comp(statedata_1, statedata_2, d2, state_size);
            bool ret = d_diff || s_diff;
            if(ret){
                if(d_diff){
                    mword fpu_index = d1/sizeof(mword);
                    mword vald1 = *reinterpret_cast<mword*> (fpu_1->data + fpu_index),
                            vald2 = *reinterpret_cast<mword*> (fpu_2->data + fpu_index);
                    Console::print("d1 %lu fpu_d1 %p fpu_d2 %p vald1 %lx vald2 %lx", 
                             d1, fpu_1->data+fpu_index, fpu_2->data+fpu_index, vald1, vald2);
                }
                if(s_diff){
                    mword state_index = d2/sizeof(mword);
                    mword vals1 = *reinterpret_cast<mword*> (statedata_1 + state_index),
                            vals2 = *reinterpret_cast<mword*> (statedata_2 + state_index);
                    Console::print("s1 %lu statedata_1 %p statedata_2 %p vals1 %lx vals2 %lx",
                            d2, statedata_1+state_index, statedata_2+state_index, vals1, vals2);
                }
                
            }else
                saved = false;                
            return ret;
        }
        
        static void dwc_rollback(){
            if(get_cr0() & (Cpu::CR0_TS | Cpu::CR0_EM))
                return;
            fpu_0->load();
            load_state(statedata_0);
            saved = false;            
        }
        
        void save_data(){
            memcpy(data_0, data, data_size);
            fcw0 = fcw; fsw0 = fsw; ftw0 = ftw; res0 = res; fop0 = fop; fip0 = fip; 
            fdp0 = fdp; mxcsr0 = mxcsr; mxcsr_mask0 = mxcsr_mask;
        }
        
        void restore_data(){
            memcpy(data_1, data, data_size);
            memcpy(data, data_0, data_size);
            fcw1 = fcw; fsw1 = fsw; ftw1 = ftw; res1 = res; fop1 = fop; fip1 = fip; 
            fdp1 = fdp; mxcsr1 = mxcsr; mxcsr_mask1 = mxcsr_mask;
            fcw = fcw0; fsw = fsw0; ftw = ftw0; res = res0; fop = fop0; fip = fip0; 
            fdp = fdp0; mxcsr = mxcsr0; mxcsr_mask = mxcsr_mask0;        
        }
        
        void restore_data1(){
            memcpy(data_2, data, data_size);
            memcpy(data, data_1, data_size);
            fcw2 = fcw; fsw2 = fsw; ftw2 = ftw; res2 = res; fop2 = fop; fip2 = fip; 
            fdp2 = fdp; mxcsr2 = mxcsr; mxcsr_mask2 = mxcsr_mask;
            fcw = fcw1; fsw = fsw1; ftw = ftw1; res = res1; fop = fop1; fip = fip1; 
            fdp = fdp1; mxcsr = mxcsr1; mxcsr_mask = mxcsr_mask1;        
        }
        
        void restore_data2(){
            memcpy(data_1, data, data_size);
            memcpy(data, data_2, data_size);
            fcw1 = fcw; fsw1 = fsw; ftw1 = ftw; res1 = res; fop1 = fop; fip1 = fip; 
            fdp1 = fdp; mxcsr1 = mxcsr; mxcsr_mask1 = mxcsr_mask;
            fcw = fcw2; fsw = fsw2; ftw = ftw2; res = res2; fop = fop2; fip = fip2; 
            fdp = fdp2; mxcsr = mxcsr2; mxcsr_mask = mxcsr_mask2;        
        }
        
        void roll_back(){
            memcpy(data, data_0, data_size);
            fcw = fcw0; fsw = fsw0; ftw = ftw0; res = res0; fop = fop0; fip = fip0; 
            fdp = fdp0; mxcsr = mxcsr0; mxcsr_mask = mxcsr_mask0;
         }
        
        mword data_check(){
            size_t d = 0;
            bool member_comp = !(fcw == fcw1 && fsw == fsw1 && ftw == ftw1 && res == res1 && fop == fop1 && 
                    fip == fip1 && fdp == fdp1 && mxcsr == mxcsr1 && mxcsr_mask == mxcsr_mask1);
             int ret = page_comp(data, data_1, d, data_size);
            if(member_comp || ret){
                mword data_index = d/sizeof(mword);
                mword vald1 = *reinterpret_cast<mword*> (data + data_index);
                mword vald2 = *reinterpret_cast<mword*> (data_1 + data_index);
                Console::print("d %lu data %p data_1 %p vald1 %lx vald2 %lx", 
                    d, data+data_index, data_1+data_index, vald1, vald2);
            }
            return ret;
        }
        
        static bool is_saved() { return saved; };
};

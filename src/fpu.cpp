/*
 * Floating Point Unit (FPU)
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

#include "fpu.hpp"
#include "pd.hpp"

INIT_PRIORITY (PRIO_SLAB)
Slab_cache Fpu::cache (sizeof (Fpu), 16);
char Fpu::statedata[state_size], Fpu::statedata_0[state_size], Fpu::statedata_1[state_size], 
        Fpu::statedata_2[state_size], Fpu::data_0[data_size], Fpu::data_1[data_size], Fpu::data_2[data_size];
uint16 Fpu::fcw0, Fpu::fcw1, Fpu::fcw2, Fpu::fsw0, Fpu::fsw1, Fpu::fsw2, Fpu::fop0, Fpu::fop1, Fpu::fop2;
uint8 Fpu::ftw0, Fpu::ftw1, Fpu::ftw2, Fpu::res0, Fpu::res1, Fpu::res2;
uint64 Fpu::fip0, Fpu::fip1, Fpu::fip2, Fpu::fdp0, Fpu::fdp1, Fpu::fdp2;
uint32 Fpu::mxcsr0, Fpu::mxcsr1, Fpu::mxcsr2, Fpu::mxcsr_mask0, Fpu::mxcsr_mask1, Fpu::mxcsr_mask2;
Fpu *Fpu::fpu_0 = new(Pd::kern) Fpu, *Fpu::fpu_1 = new(Pd::kern) Fpu, *Fpu::fpu_2 = new(Pd::kern) Fpu;
bool Fpu::saved = false;

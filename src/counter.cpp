/*
 * Event Counters
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

#include "counter.hpp"
#include "stdio.hpp"
#include "x86.hpp"

unsigned Counter::ipi[NUM_IPI];
unsigned Counter::lvt[NUM_LVT];
unsigned Counter::delayed_lvt[NUM_LVT];
uint64 Counter::lag_lvt[NUM_LVT];
unsigned Counter::gsi[NUM_GSI];
unsigned Counter::delayed_gsi[NUM_GSI];
uint64 Counter::lag_gsi[NUM_GSI];
uint64 Counter::lag_msi[NUM_GSI];
unsigned Counter::exc[NUM_EXC];
unsigned Counter::vmi[NUM_VMI];
unsigned Counter::vtlb_gpf;
unsigned Counter::vtlb_hpf;
unsigned Counter::vtlb_fill;
unsigned Counter::vtlb_flush;
unsigned Counter::vtlb_cow_fault;
unsigned Counter::cow_fault;
unsigned Counter::hpt_cow_fault;
unsigned Counter::used_cows_in_old_cow_elts;
unsigned Counter::schedule;
unsigned Counter::helping;
unsigned Counter::rep_io;
unsigned Counter::simple_io;
unsigned Counter::io;
unsigned Counter::pmi_ss;
unsigned Counter::nb_pe;
unsigned Counter::nb_vm_pe;
unsigned Counter::pio;
unsigned Counter::mmio;
unsigned Counter::vmio;
uint64 Counter::cycles_idle;
unsigned Counter::init;

void Counter::dump() {
    trace(0, "TIME: %16llu", rdtsc());
    trace(0, "IDLE: %16llu", cycles_idle);
//    trace(0, "VGPF: %16u", vtlb_gpf);
//    trace(0, "VHPF: %16u", vtlb_hpf);
//    trace(0, "VFIL: %16u", vtlb_fill);
//    trace(0, "VFLU: %16u", vtlb_flush);
    trace(0, "COWF: %16u", cow_fault);
//    trace(0, "VCOW: %16u", vtlb_cow_fault);
//    trace(0, "SCHD: %16u", schedule);
//    trace(0, "HELP: %16u", helping);
//    trace(0, "REP_IO: %14u", rep_io);
//    trace(0, "SIMPLE_IO: %11u", simple_io);
//    trace(0, "PIO: %17u", pio);
//    trace(0, "MMIO: %16u", mmio);
    trace(0, "VMIO: %16u", vmio);
//    trace(0, "T_IO: %16u", io);
//    trace(0, "PMI_SS: %14u", pmi_ss);
    trace(0, "NB_PE: %15u", nb_pe);

    vtlb_gpf = vtlb_hpf = vtlb_fill = vtlb_flush = vtlb_cow_fault = schedule = helping = rep_io =
    io = simple_io = pmi_ss = pio = mmio = 0;

//    for (unsigned i = 0; i < sizeof (ipi) / sizeof (*ipi); i++)
//        if (ipi[i]) {
//            trace(0, "IPI %#4x: %12u", i, ipi[i]);
//            ipi[i] = 0;
//        }
//
//    for (unsigned i = 0; i < sizeof (lvt) / sizeof (*lvt); i++)
//        if (lvt[i]) {
//            uint64 mean = lag_lvt[i]/(delayed_lvt[i]?delayed_lvt[i]:lvt[i]);
//            trace(0, "LVT %#4x: %12u %12u lag %12llu %12llu", i, lvt[i], delayed_lvt[i], lag_lvt[i], mean);
//            lvt[i] = 0;
//            delayed_lvt[i] = 0;
//            lag_lvt[i] = 0;
//        }
//
//    for (unsigned i = 0; i < sizeof (gsi) / sizeof (*gsi); i++)
//        if (gsi[i]) {
//            uint64 mean = lag_gsi[i]/(delayed_gsi[i]?delayed_gsi[i]:gsi[i]);
//            trace(0, "GSI %#4x: %12u %12u lag %12llu %12llu", i, gsi[i], delayed_gsi[i], lag_gsi[i], mean);
//            gsi[i] = 0;
//            delayed_gsi[i] = 0;
//            lag_gsi[i] = 0;            
//        }
//
//    for (unsigned i = 0; i < sizeof (exc) / sizeof (*exc); i++)
//        if (exc[i]) {
//            trace(0, "EXC %#4x: %12u", i, exc[i]);
//            exc[i] = 0;
//        }
//
//    for (unsigned i = 0; i < sizeof (vmi) / sizeof (*vmi); i++)
//        if (vmi[i]) {
//            trace(0, "VMI %#4x: %12u", i, vmi[i]);
//            vmi[i] = 0;
//        }
}

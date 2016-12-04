/*
 * Execution Context (SVM)
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

#include "ec.hpp"
#include "svm.hpp"
#include "vtlb.hpp"

uint8 Ec::ifetch(mword virt) {
    mword phys, attr = 0, type = 0;
    uint8 opcode;

    if (!Vtlb::gwalk(&current->regs, virt, phys, attr, type))
        die("SVM TLB failure");

    if (User::peek(reinterpret_cast<uint8 *> (phys), opcode) != ~0UL)
        die("SVM ifetch failure");

    return opcode;
}

void Ec::svm_exception(mword reason) {
    if (current->regs.vmcb->exitintinfo & 0x80000000) {

        mword t = static_cast<mword> (current->regs.vmcb->exitintinfo) >> 8 & 0x7;
        mword v = static_cast<mword> (current->regs.vmcb->exitintinfo) & 0xff;

        if (t == 0 || (t == 3 && v != 3 && v != 4))
            current->regs.vmcb->inj_control = current->regs.vmcb->exitintinfo;
    }

    int pmi = 1960;
    switch (reason) {

        default:
            current->regs.dst_portal = reason;
            break;

        case 0x47: // #NM
            check_memory(pmi);
            handle_exc_nm();
            ret_user_vmrun();

        case 0x4e: // #PF
            mword err = static_cast<mword> (current->regs.vmcb->exitinfo1);
            mword cr2 = static_cast<mword> (current->regs.vmcb->exitinfo2);

            mword phys;
            Paddr host;
            switch (Vtlb::miss(&current->regs, cr2, err, phys, host)) {

                case Vtlb::GPA_HPA:
                    current->regs.nst_error = 0;
                    current->regs.dst_portal = NUM_VMI - 4;
                    //                    if (current->debug) {
                    //                                            Console::print("GPA_HPA gla: %08lx  gpa: %08lx  host: %08lx  err: %08lx  rip: %llx", cr2, phys, host, err, current->regs.vmcb->rip);
                    //                    }
                    if (cr2 == 0xc6400008 && phys == 0x06400008) {
                        Console::print("Hardening begin");
                        current->hardening_started = true;
                    }
                    break;

                case Vtlb::GLA_GPA:
                    current->regs.vmcb->cr2 = cr2;
                    current->regs.vmcb->inj_control = static_cast<uint64> (err) << 32 | 0x80000b0e;
                    //                    if (current->debug) {
                    //                                            Console::print("GLA_GPA gla: %08lx  gpa: %08lx  host: %08lx  err: %08lx  rip: %llx", cr2, phys, host, err, current->regs.vmcb->rip);
                    //                    }
                    ret_user_vmrun();

                case Vtlb::SUCCESS:
//                    if (cr2 == 0xc130aedc && phys == 0x0130aedc) {
//                        Console::print("Hardening begin");
//                        current->hardening_started = true;
//                    }
                    //                    if (current->debug) {
                    //                                            Console::print("SUCCESS gla: %08lx  gpa: %08lx  host: %08lx  err: %08lx  rip: %llx", cr2, phys, host, err, current->regs.vmcb->rip);
                    //                    }
                    ret_user_vmrun();

                case Vtlb::SUCCESS_COW:
                    //                    if (current->debug) {
//                                                                Console::print("SUCCESS COW gla: %08lx  gpa: %08lx  host: %08lx  err: %08lx  rip: %llx", cr2, phys, host, err, current->regs.vmcb->rip);
                    //                    }
                    ret_user_vmrun();
            }
    }

    check_memory(pmi);
    send_msg<ret_user_vmrun>();
}

void Ec::svm_invlpg() {
    current->regs.svm_update_shadows();

    mword virt = current->regs.linear_address<Vmcb>(static_cast<mword> (current->regs.vmcb->cs.base) + static_cast<mword> (current->regs.vmcb->rip));

    assert(ifetch(virt) == 0xf && ifetch(virt + 1) == 0x1);

    uint8 mrm = ifetch(virt + 2);
    uint8 r_m = mrm & 7;

    unsigned len = 3;

    switch (mrm >> 6) {
        case 0: len += (r_m == 4 ? 1: r_m == 5 ? 4: 0);
            break;
        case 1: len += (r_m == 4 ? 2: 1);
            break;
        case 2: len += (r_m == 4 ? 5: 4);
            break;
    }

    current->regs.tlb_flush<Vmcb>(true);
    current->regs.vmcb->adjust_rip(len);
    ret_user_vmrun();
}

void Ec::svm_cr() {
    current->regs.svm_update_shadows();

    mword virt = current->regs.linear_address<Vmcb>(static_cast<mword> (current->regs.vmcb->cs.base) + static_cast<mword> (current->regs.vmcb->rip));

    assert(ifetch(virt) == 0xf);

    uint8 opc = ifetch(virt + 1);
    uint8 mrm = ifetch(virt + 2);

    unsigned len, gpr = mrm & 0x7, cr = mrm >> 3 & 0x7;

    switch (opc) {

        case 0x6: // CLTS
            current->regs.write_cr<Vmcb> (0, current->regs.read_cr<Vmcb> (0) & ~Cpu::CR0_TS);
            len = 2;
            break;

        case 0x20: // MOV from CR
            current->regs.svm_write_gpr(gpr, current->regs.read_cr<Vmcb>(cr));
            len = 3;
            break;

        case 0x22: // MOV to CR
            current->regs.write_cr<Vmcb> (cr, current->regs.svm_read_gpr(gpr));
            len = 3;
            break;

        default:
            die("SVM decode failure");
    }

    current->regs.vmcb->adjust_rip(len);
    ret_user_vmrun();
}

void Ec::handle_svm() {
    current->regs.vmcb->tlb_control = 0;

    mword reason = static_cast<mword> (current->regs.vmcb->exitcode);

//    if (current->hardening_started) {
//        Console::print("VM Exit reason: %lx rip: %llx  nrip: %llx  eip: %08lx",
//                reason, current->regs.vmcb->rip, current->regs.vmcb->nrip, current->regs.REG(ip));
//    }

    int pmi = 1961;
    switch (reason) {
        case -1UL: // Invalid state
            reason = NUM_VMI - 3;
            break;
        case 0x400: // NPT
            reason = NUM_VMI - 4;
            current->regs.nst_error = static_cast<mword> (current->regs.vmcb->exitinfo1);
            current->regs.nst_fault = static_cast<mword> (current->regs.vmcb->exitinfo2);
            break;
    }

    Counter::vmi[reason]++;
    if (reason == 0x60) {
        if (current->previous_reason == 0x60) {
            current->nb_extint++;
        } else {
            current->nb_extint = 1;
        }
        current->previous_reason = 0x60;
    } else {
        current->previous_reason = 0;
    }
    switch (reason) {

        case 0x0 ... 0x1f: // CR Access
            //Console::print("Cr access  opc: %02x", opc);
            check_memory(pmi);
            svm_cr();

        case 0x40 ... 0x5f: // Exception
            svm_exception(reason);

        case 0x60: //EXTINT
            //            if (current->debug) {
            //                Console::print("VMINT  vmcb.rip: %08llx  vmcb_copy.rip: %08llx",
            //                        current->regs.vmcb->rip, current->vmcb_backup->rip);
            //            }

            /**
             * Ici mieux vaut collectionner les interruptions et les lui envoyer 
             * au moment propice c'est à dire quand il va trapper normalement
             */
            //            if (current->nb_extint >= 4) {
            //                if(current->nb_extint > 4)
            //                    current->nb_extint = 0;
            //                check_memory(reason);
            //            }
            asm volatile ("sti; nop; cli" : : : "memory");
            ret_user_vmrun();

        case 0x6e: //RDTSC
            //            Console::print("RDTSC in VM");
            check_memory(pmi);
            current->regs.resolve_rdtsc<Vmcb>(rdtsc());
            ret_user_vmrun();

        case 0x79: // INVLPG
            check_memory(pmi);
            svm_invlpg();

        case 0x87: //RDTSCP
            Console::print("RDTSCP in VM");
            ret_user_vmrun();
    }

    check_memory(pmi);
    current->regs.dst_portal = reason;

    send_msg<ret_user_vmrun>();
}

/*
 * Virtual Machine Extensions (VMX)
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

#include "bits.hpp"
#include "cmdline.hpp"
#include "ept.hpp"
#include "gdt.hpp"
#include "hip.hpp"
#include "idt.hpp"
#include "msr.hpp"
#include "stdio.hpp"
#include "tss.hpp"
#include "util.hpp"
#include "vmx.hpp"
#include "x86.hpp"
#include "pd.hpp"

Vmcs *              Vmcs::current;
unsigned            Vmcs::vpid_ctr;
Vmcs::vmx_basic     Vmcs::basic;
Vmcs::vmx_ept_vpid  Vmcs::ept_vpid;
Vmcs::vmx_ctrl_pin  Vmcs::ctrl_pin;
Vmcs::vmx_ctrl_cpu  Vmcs::ctrl_cpu[2];
Vmcs::vmx_ctrl_exi  Vmcs::ctrl_exi;
Vmcs::vmx_ctrl_ent  Vmcs::ctrl_ent;
mword               Vmcs::fix_cr0_set, Vmcs::fix_cr0_clr;
mword               Vmcs::fix_cr4_set, Vmcs::fix_cr4_clr;

Vmcs::Vmcs (mword esp, mword bmp, mword cr3, uint64 eptp) : rev (basic.revision)
{
    make_current();

    uint32 pin = PIN_EXTINT | PIN_NMI | PIN_VIRT_NMI;
    uint32 exi = EXI_INTA;
    uint32 ent = 0;

    write (PF_ERROR_MASK, 0);
    write (PF_ERROR_MATCH, 0);
    write (CR3_TARGET_COUNT, 0);

    write (VMCS_LINK_PTR,    ~0ul);
    write (VMCS_LINK_PTR_HI, ~0ul);

    write (VPID, ++vpid_ctr);

    write (EPTP,    static_cast<mword>(eptp) | (Ept::max() - 1) << 3 | 6);
    write (EPTP_HI, static_cast<mword>(eptp >> 32));

    write (IO_BITMAP_A, bmp);
    write (IO_BITMAP_B, bmp + PAGE_SIZE);

    write (HOST_SEL_CS, SEL_KERN_CODE);
    write (HOST_SEL_SS, SEL_KERN_DATA);
    write (HOST_SEL_DS, SEL_KERN_DATA);
    write (HOST_SEL_ES, SEL_KERN_DATA);
    write (HOST_SEL_TR, SEL_TSS_RUN);

#ifdef __x86_64__
    write (HOST_EFER, Msr::read<uint64>(Msr::IA32_EFER));
    exi |= EXI_SAVE_EFER | EXI_LOAD_EFER | EXI_HOST_64;
    ent |= ENT_LOAD_EFER;
#endif

    write (PIN_CONTROLS, (pin | ctrl_pin.set) & ctrl_pin.clr);
    write (EXI_CONTROLS, (exi | ctrl_exi.set) & ctrl_exi.clr);
    write (ENT_CONTROLS, (ent | ctrl_ent.set) & ctrl_ent.clr);

    write (HOST_CR3, cr3);
    write (HOST_CR0, get_cr0() | Cpu::CR0_TS);
    write (HOST_CR4, get_cr4());

    write (HOST_BASE_TR,   reinterpret_cast<mword>(&Tss::run));
    write (HOST_BASE_GDTR, reinterpret_cast<mword>(Gdt::gdt));
    write (HOST_BASE_IDTR, reinterpret_cast<mword>(Idt::idt));

    write (HOST_SYSENTER_CS,  SEL_KERN_CODE);
    write (HOST_SYSENTER_ESP, reinterpret_cast<mword>(&Tss::run.sp0));
    write (HOST_SYSENTER_EIP, reinterpret_cast<mword>(&entry_sysenter));

    write (HOST_RSP, esp);
    write (HOST_RIP, reinterpret_cast<mword>(&entry_vmx));
}

void Vmcs::init()
{
    if (!Cpu::feature (Cpu::FEAT_VMX) || (Msr::read<uint32>(Msr::IA32_FEATURE_CONTROL) & 0x5) != 0x5) {
        Hip::clr_feature (Hip::FEAT_VMX);
        return;
    }

    fix_cr0_set =  Msr::read<mword>(Msr::IA32_VMX_CR0_FIXED0);
    fix_cr0_clr = ~Msr::read<mword>(Msr::IA32_VMX_CR0_FIXED1);
    fix_cr4_set =  Msr::read<mword>(Msr::IA32_VMX_CR4_FIXED0);
    fix_cr4_clr = ~Msr::read<mword>(Msr::IA32_VMX_CR4_FIXED1);

    basic.val       = Msr::read<uint64>(Msr::IA32_VMX_BASIC);
    ctrl_exi.val    = Msr::read<uint64>(basic.ctrl ? Msr::IA32_VMX_TRUE_EXIT  : Msr::IA32_VMX_CTRL_EXIT);
    ctrl_ent.val    = Msr::read<uint64>(basic.ctrl ? Msr::IA32_VMX_TRUE_ENTRY : Msr::IA32_VMX_CTRL_ENTRY);
    ctrl_pin.val    = Msr::read<uint64>(basic.ctrl ? Msr::IA32_VMX_TRUE_PIN   : Msr::IA32_VMX_CTRL_PIN);
    ctrl_cpu[0].val = Msr::read<uint64>(basic.ctrl ? Msr::IA32_VMX_TRUE_CPU0  : Msr::IA32_VMX_CTRL_CPU0);

    if (has_secondary())
        ctrl_cpu[1].val = Msr::read<uint64>(Msr::IA32_VMX_CTRL_CPU1);
    if (has_ept() || has_vpid())
        ept_vpid.val = Msr::read<uint64>(Msr::IA32_VMX_EPT_VPID);
    if (has_ept())
        Ept::ord = min (Ept::ord, static_cast<mword>(bit_scan_reverse (static_cast<mword>(ept_vpid.super)) + 2) * Ept::bpl() - 1);
    if (has_urg())
        fix_cr0_set &= ~(Cpu::CR0_PG | Cpu::CR0_PE);

    fix_cr0_clr |= Cpu::CR0_CD | Cpu::CR0_NW;

    ctrl_cpu[0].set |= CPU_HLT | CPU_IO | CPU_IO_BITMAP | CPU_SECONDARY;
    ctrl_cpu[1].set |= CPU_VPID | CPU_URG;

    if (Cmdline::vtlb || !ept_vpid.invept)
        ctrl_cpu[1].clr &= ~(CPU_EPT | CPU_URG);
    if (Cmdline::novpid || !ept_vpid.invvpid)
        ctrl_cpu[1].clr &= ~CPU_VPID;

    set_cr0 ((get_cr0() & ~fix_cr0_clr) | fix_cr0_set);
    set_cr4 ((get_cr4() & ~fix_cr4_clr) | fix_cr4_set);

//    vmx_msr_guest_init();
        
    Vmcs *root = new (Pd::kern.quota) Vmcs;

    trace (TRACE_VMX, "VMCS:%#010lx REV:%#x EPT:%d URG:%d VNMI:%d VPID:%d", Buddy::ptr_to_phys (root), basic.revision, has_ept(), has_urg(), has_vnmi(), has_vpid());
}
//
//
//void vmx_msr_guest_init(struct vmx *vmx, int vcpuid) {
//    uint64_t *guest_msrs;
//
//    guest_msrs = vmx->guest_msrs[vcpuid];
//
//    /*
//     * The permissions bitmap is shared between all vcpus so initialize it
//     * once when initializing the vBSP.
//     */
//    if (vcpuid == 0) {
//            guest_msr_rw(vmx, MSR_LSTAR);
//            guest_msr_rw(vmx, MSR_CSTAR);
//            guest_msr_rw(vmx, MSR_STAR);
//            guest_msr_rw(vmx, MSR_SF_MASK);
//            guest_msr_rw(vmx, MSR_KGSBASE);
//    }
//
//    /*
//     * Initialize guest IA32_PAT MSR with default value after reset.
//     */
//    guest_msrs[IDX_MSR_PAT] = PAT_VALUE(0, PAT_WRITE_BACK) |
//        PAT_VALUE(1, PAT_WRITE_THROUGH)	|
//        PAT_VALUE(2, PAT_UNCACHED)		|
//        PAT_VALUE(3, PAT_UNCACHEABLE)	|
//        PAT_VALUE(4, PAT_WRITE_BACK)	|
//        PAT_VALUE(5, PAT_WRITE_THROUGH)	|
//        PAT_VALUE(6, PAT_UNCACHED)		|
//        PAT_VALUE(7, PAT_UNCACHEABLE);
//
//    return;
//}
//
//int msr_bitmap_change_access(char *bitmap, u_int msr, int access) {
//	int byte, bit;
//
//	if (msr <= 0x00001FFF)
//		byte = msr / 8;
//	else if (msr >= 0xC0000000 && msr <= 0xC0001FFF)
//		byte = 1024 + (msr - 0xC0000000) / 8;
//	else
//		return (EINVAL);
//
//	bit = msr & 0x7;
//
//	if (access & MSR_BITMAP_ACCESS_READ)
//		bitmap[byte] &= ~(1 << bit);
//	else
//		bitmap[byte] |= 1 << bit;
//
//	byte += 2048;
//	if (access & MSR_BITMAP_ACCESS_WRITE)
//		bitmap[byte] &= ~(1 << bit);
//	else
//		bitmap[byte] |= 1 << bit;
//
//	return (0);
//}
//
//void msr_bitmap_initialize(char *bitmap) {
//
//	memset(bitmap, 0xff, PAGE_SIZE);
//}
//
//int msr_bitmap_change_access(char *bitmap, u_int msr, int access) {
//    int byte, bit;
//
//    if (msr <= 0x00001FFF)
//        byte = msr / 8;
//    else if (msr >= 0xC0000000 && msr <= 0xC0001FFF)
//        byte = 1024 + (msr - 0xC0000000) / 8;
//    else
//        return (EINVAL);
//
//    bit = msr & 0x7;
//
//    if (access & MSR_BITMAP_ACCESS_READ)
//        bitmap[byte] &= ~(1 << bit);
//    else
//        bitmap[byte] |= 1 << bit;
//
//    byte += 2048;
//    if (access & MSR_BITMAP_ACCESS_WRITE)
//        bitmap[byte] &= ~(1 << bit);
//    else
//        bitmap[byte] |= 1 << bit;
//
//    return (0);
//}
//
///*
// * Generate a bitmask to be used for the VMCS execution control fields.
// *
// * The caller specifies what bits should be set to one in 'ones_mask'
// * and what bits should be set to zero in 'zeros_mask'. The don't-care
// * bits are set to the default value. The default values are obtained
// * based on "Algorithm 3" in Section 27.5.1 "Algorithms for Determining
// * VMX Capabilities".
// *
// * Returns zero on success and non-zero on error.
// */
//int vmx_set_ctlreg(int ctl_reg, int true_ctl_reg, uint32_t ones_mask,
//	       uint32_t zeros_mask, uint32_t *retval) {
//    int i;
//    uint64_t val, trueval;
//    bool true_ctls_avail, one_allowed, zero_allowed;
//
//    /* We cannot ask the same bit to be set to both '1' and '0' */
//    if ((ones_mask ^ zeros_mask) != (ones_mask | zeros_mask))
//        return (EINVAL);
//
//    true_ctls_avail = (rdmsr(MSR_VMX_BASIC) & (1UL << 55)) != 0;
//
//    val = rdmsr(ctl_reg);
//    if (true_ctls_avail)
//        trueval = rdmsr(true_ctl_reg);		/* step c */
//    else
//        trueval = val;				/* step a */
//
//    for (i = 0; i < 32; i++) {
//        one_allowed = vmx_ctl_allows_one_setting(trueval, i);
//        zero_allowed = vmx_ctl_allows_zero_setting(trueval, i);
//
//        KASSERT(one_allowed || zero_allowed,
//                    ("invalid zero/one setting for bit %d of ctl 0x%0x, "
//                     "truectl 0x%0x\n", i, ctl_reg, true_ctl_reg));
//
//            if (zero_allowed && !one_allowed) {		/* b(i),c(i) */
//                if (ones_mask & (1 << i))
//                        return (EINVAL);
//                *retval &= ~(1 << i);
//            } else if (one_allowed && !zero_allowed) {	/* b(i),c(i) */
//                if (zeros_mask & (1 << i))
//                        return (EINVAL);
//                *retval |= 1 << i;
//            } else {
//                if (zeros_mask & (1 << i))	/* b(ii),c(ii) */
//                        *retval &= ~(1 << i);
//                else if (ones_mask & (1 << i)) /* b(ii), c(ii) */
//                        *retval |= 1 << i;
//                else if (!true_ctls_avail)
//                        *retval &= ~(1 << i);	/* b(iii) */
//                else if (vmx_ctl_allows_zero_setting(val, i))/* c(iii)*/
//                        *retval &= ~(1 << i);
//                else if (vmx_ctl_allows_one_setting(val, i)) /* c(iv) */
//                        *retval |= 1 << i;
//                else {
//                        panic("vmx_set_ctlreg: unable to determine "
//                              "correct value of ctl bit %d for msr "
//                              "0x%0x and true msr 0x%0x", i, ctl_reg,
//                              true_ctl_reg);
//                }
//            }
//    }
//
//    return (0);
//}
//

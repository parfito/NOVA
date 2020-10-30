/*
 * Virtual Translation Lookaside Buffer (VTLB)
 *
 * Copyright (C) 2009-2011 Udo Steinberg <udo@hypervisor.org>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2012-2013 Udo Steinberg, Intel Corporation.
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
#include "pd.hpp"
#include "regs.hpp"
#include "stdio.hpp"
#include "vtlb.hpp"
#include "vmx.hpp"
#include "cow_elt.hpp"
#include "ec.hpp"
#include "pe_stack.hpp"
#include "log.hpp"
#include "pe.hpp"
#include "hip.hpp"

bool Vtlb::sysenter_eip_is_cowed = false, Vtlb::sysenter_eip1_is_cowed = false;
size_t Vtlb::gwalk (Exc_regs *regs, mword gla, mword &gpa, mword &attr, mword &error)
{
    if (EXPECT_FALSE (!(regs->cr0_shadow & Cpu::CR0_PG))) {
        gpa = gla;
        return ~0UL;
    }

    bool pse = regs->cr4_shadow & (Cpu::CR4_PSE | Cpu::CR4_PAE);
    bool pge = regs->cr4_shadow &  Cpu::CR4_PGE;
    bool wp  = regs->cr0_shadow &  Cpu::CR0_WP;

    unsigned lev = 2;

    for (uint32 e, *pte= reinterpret_cast<uint32 *>(regs->cr3_shadow & ~PAGE_MASK);; pte = reinterpret_cast<uint32 *>(e & ~PAGE_MASK)) {

        unsigned shift = --lev * 10 + PAGE_BITS;
        pte += gla >> shift & ((1UL << 10) - 1);

        if (User::peek (pte, e) != ~0UL) {
            gpa = reinterpret_cast<Paddr>(pte);
            return ~0UL;
        }

        if (EXPECT_FALSE (!(e & TLB_P)))
            return 0;

        attr &= e & PAGE_MASK;

        if (lev && (!pse || !(e & TLB_S))) {
            mark_pte (pte, e, TLB_A);
            continue;
        }

        if (EXPECT_FALSE (!wp && error == ERR_W))
            attr = (attr & ~TLB_U) | TLB_W;

        if (EXPECT_FALSE ((attr & error) != error)) {
            error |= ERR_P;
            return 0;
        }

        if (!(error & ERR_W) && !(e & TLB_D))
            attr &= ~TLB_W;

        mark_pte (pte, e, static_cast<uint32>((attr & 3) << 5));

        attr |= e & TLB_UC;

        if (EXPECT_TRUE (pge) && (e & TLB_G))
            attr |= TLB_M;

        size_t size = 1UL << shift;

        gpa = (e & ~PAGE_MASK) | (gla & (size - 1));

        return size;
    }
}

size_t Vtlb::hwalk (mword gpa, mword &hpa, mword &attr, mword &error)
{
    mword ept_attr;

    size_t size = Pd::current->ept.lookup (gpa, hpa, ept_attr);

    if (size) {

        if (EXPECT_FALSE (!(ept_attr & Ept::EPT_W)))
            attr &= ~TLB_W;

        if (EXPECT_FALSE ((attr & error) != error)) {
            error = (ept_attr & 7) << 3 | 1UL << !!(error & ERR_W);
            return 0;
        }
    }

    return size;
}

Vtlb::Reason Vtlb::miss (Exc_regs *regs, mword virt, mword &error, Queue<Cow_field> *cow_fields)
{
    assert(cow_fields);
    mword phys, attr = TLB_U | TLB_W | TLB_P;
    Paddr host;
    char buff[STR_MAX_LENGTH];

    error &= ERR_U | ERR_W;

    size_t gsize = gwalk (regs, virt, phys, attr, error);

    if (EXPECT_FALSE (!gsize)) {
        Ec::check_memory(Ec::PES_VMX_EXC);
        Counter::vtlb_gpf++;
        String::print(buff, "VTLB GLA_GPA Pe %llu virt %lx gpa %lx attr %lx err %lx", 
            Counter::nb_pe, virt, phys, attr, error);
        Logstore::add_entry_in_buffer(buff);
        return GLA_GPA;
    }

    size_t hsize = hwalk (phys, host, attr, error);

    if (EXPECT_FALSE (!hsize)) {
        Ec::check_memory(Ec::PES_VMX_EXC);
        regs->nst_fault = phys;
        regs->nst_error = error;
        Counter::vtlb_hpf++;
        String::print(buff, "VTLB GPA_HPA Pe %llu virt %lx gpa %lx hpa %lx attr %lx err %lx", 
            Counter::nb_pe, virt, phys, host, attr, error);
        Logstore::add_entry_in_buffer(buff);
        return GPA_HPA;
    }

    size_t size = min (gsize, hsize);

    if (gsize > hsize)
        attr |= TLB_F;

    Counter::print<1,16> (++Counter::vtlb_fill, Console_vga::COLOR_LIGHT_MAGENTA, SPN_VFI);

    unsigned lev = max();

    for (Vtlb *tlb = regs->vtlb;; tlb = static_cast<Vtlb *>(Buddy::phys_to_ptr (tlb->addr()))) {

        unsigned shift = --lev * bpl() + PAGE_BITS;
        tlb += virt >> shift & ((1UL << bpl()) - 1);

//        asm volatile ("" :: "m" (tlb)); // to avoid gdb "optimized out"
        if (lev) {

            if (lev == 2 || size < 1UL << shift) {

                if (tlb->super())
                    tlb->val = static_cast<typeof tlb->val>(Buddy::ptr_to_phys (new (Pd::current->quota) Vtlb) | (lev == 2 ? 0 : TLB_A | TLB_U | TLB_W) | TLB_M | TLB_P);

                else if (!tlb->present()) {
                    static_cast<Vtlb *>(Buddy::phys_to_ptr (tlb->addr()))->flush_ptab (tlb->mark());
                    tlb->val |= TLB_M | TLB_P;
                }

                tlb->val &= static_cast<typeof tlb->val>(attr | ~TLB_M);
                tlb->val |= static_cast<typeof tlb->val>(attr & TLB_F);

                continue;
            }

            if (!tlb->super())
                Vtlb::destroy(static_cast<Vtlb *>(Buddy::phys_to_ptr (tlb->addr())), Pd::current->quota);

            attr |= TLB_S;
        }
        if((tlb->addr() == (host & ~PAGE_MASK)) && tlb->is_cow(virt, phys, error, cow_fields)){
            mword guest_sysenter_esp = Vmcs::read(Vmcs::GUEST_SYSENTER_ESP); 
            Paddr vtlb_hpa;
            mword vtlb_attr;
            mword* sys_enter_rsp_map; 
            Vtlb *sys_enter_rsp_tlb = nullptr;
            if(guest_sysenter_esp &&  
                regs->vtlb->lookup(guest_sysenter_esp, vtlb_hpa, vtlb_attr, sys_enter_rsp_tlb)){
                mword rsp_bottom = (guest_sysenter_esp & ~PAGE_MASK) - PAGE_SIZE + 4;
                sys_enter_rsp_map = reinterpret_cast<mword*> 
                    (Hpt::remap_cow(Pd::kern.quota, vtlb_hpa, 3, sizeof(mword)));
                call_log_funct(Logstore::add_entry_in_buffer, 0, "guest_sysenter_esp"
                " %lx: ", guest_sysenter_esp);
                int i = 3;
                while (i && (guest_sysenter_esp >= rsp_bottom)) {
                    call_log_funct(Logstore::append_entry_in_buffer, 0, "%lx ", 
                        *sys_enter_rsp_map);
                    sys_enter_rsp_map--; i--;
                    guest_sysenter_esp -= sizeof(mword);
                } 
            }
            mword guest_rsp = Vmcs::read(Vmcs::GUEST_RSP);
            if((virt & ~PAGE_MASK) == (guest_rsp & ~PAGE_MASK)) {
                Ec::remove_resume_flag();
                Ec::guest_single_step_rsp = guest_rsp;
                Ec::guest_rsp_phys = (host & ~PAGE_MASK) | (guest_rsp & PAGE_MASK);
            }
            return SUCCESS;
        }
        Ec::check_memory(Ec::PES_VMX_EXC);
        mword guest_idt = Vmcs::read(Vmcs::GUEST_BASE_IDTR);
        if(guest_idt && (virt & ~PAGE_MASK) == guest_idt) {
            mword guest_rip = Vmcs::read(Vmcs::GUEST_RIP);
            Paddr hpa_rip;
            mword attrib;
            mword *rip_ptr; 
            Vtlb* vtlb = nullptr;
            char instruction[STR_MIN_LENGTH];
            if(regs->vtlb->lookup(static_cast<uint64>(guest_rip), hpa_rip, attrib, vtlb)){
                rip_ptr = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, 
                    hpa_rip, 3, sizeof(mword)));
                assert(rip_ptr);
                instruction_in_hex(*rip_ptr, instruction);
            } else {
                String::print(instruction, "VM RIP NOT MAPPED");
            }
            call_log_funct(Logstore::add_entry_in_buffer, 0, "Page fault on Guest IDT"
                " %lx tlb_val %llx err %lx rip %lx instr %s PE %llu", guest_idt, tlb->val, 
                error, guest_rip, instruction, Counter::nb_pe);
        }
        mword guest_sysenter_eip = Vmcs::read(Vmcs::GUEST_SYSENTER_EIP);
        if(guest_sysenter_eip && ((virt & ~PAGE_MASK) == (guest_sysenter_eip & ~PAGE_MASK))){
            if(sysenter_eip_is_cowed && (virt == guest_sysenter_eip)) {
                call_log_funct(Logstore::add_entry_in_buffer, 0, "Page fault on Guest SYSENTER EIP"
                    " %lx tlb_val %llx err %lx PE %llu", guest_sysenter_eip, tlb->val, 
                    error, Counter::nb_pe);
            } 
            tlb->val |= TLB_P;
        }
        guest_sysenter_eip = Vmcs::read(Vmcs::GUEST_SYSENTER_EIP) + 0x1000;
        if(guest_sysenter_eip && ((virt & ~PAGE_MASK) == (guest_sysenter_eip & ~PAGE_MASK))){
            if(sysenter_eip1_is_cowed && (virt == guest_sysenter_eip)) {
                call_log_funct(Logstore::add_entry_in_buffer, 0, "Page fault on Guest SYSENTER EIP"
                    " %lx tlb_val %llx err %lx PE %llu", guest_sysenter_eip, tlb->val, 
                    error, Counter::nb_pe);
            } 
            tlb->val |= TLB_P;
        }
        bool cowed = false;
        if((attr & TLB_W) && (attr & TLB_P)) {
            attr &= ~TLB_W;
            tlb->val = static_cast<typeof tlb->val>((host & ~((1UL << shift) - 1)) | attr | TLB_D | TLB_A);
            Cow_field::set_cow(cow_fields, virt, true);
            cowed = true;
        } else {
            Cow_field::set_cow(cow_fields, virt, false);            
            tlb->val = static_cast<typeof tlb->val>((host & ~((1UL << shift) - 1)) | attr | TLB_D | TLB_A);
        }
        if(Hip::is_mmio(host & ~PAGE_MASK)){
            trace(0, "Vtlb is MMIO");
        }
        trace (TRACE_VTLB, "VTLB Miss SUCCESS CR3:%#010lx A:%#010lx P:%#010lx A:%#lx "
                "E:%#lx", regs->cr3_shadow, virt, phys, attr, error);
        call_log_funct(Logstore::add_entry_in_buffer, 0, "VTLB SUCCESS Pe %llu "
            "CR3:%#010lx virt %lx gpa %lx hpa %lx tlb->val %llx err %lx %s", 
            Counter::nb_pe, regs->cr3_shadow, virt, phys, host, tlb->val, error,
            cowed ? "Cowed" : "DeCowed");
        return SUCCESS;
    }
}

void Vtlb::flush_ptab (bool full)
{
    for (Vtlb *e = this; e < this + (1UL << bpl()); e++) {

        if (EXPECT_TRUE (!e->present()))
            continue;

        if (EXPECT_FALSE (full))
            e->val |= TLB_M;

        else if (EXPECT_FALSE (e->mark()))
            continue;

        e->val &= ~TLB_P;
    }
}

void Vtlb::flush (mword virt)
{
    unsigned l = max();

    for (Vtlb *e = this;; e = static_cast<Vtlb *>(Buddy::phys_to_ptr (e->addr()))) {

        unsigned shift = --l * bpl() + PAGE_BITS;
        e += virt >> shift & ((1UL << bpl()) - 1);

        if (!e->present())
            return;

        if (l && !e->super() && !e->frag())
            continue;

        e->val |=  TLB_M;
        e->val &= ~TLB_P;

        Counter::print<1,16> (++Counter::vtlb_flush, Console_vga::COLOR_LIGHT_RED, SPN_VFL);

        return;
    }
}

void Vtlb::flush (bool full)
{
    flush_ptab (full);

    Counter::print<1,16> (++Counter::vtlb_flush, Console_vga::COLOR_LIGHT_RED, SPN_VFL);
}

bool Vtlb::is_cow(mword virt, mword gpa, mword error, Queue<Cow_field> *cow_fields){
    if(!(error & ERR_W))
        return false;
//    if((error & ERR_U) || (error & ERR_P))
//        return false;
    mword tlb_attr = attr(); 
    if(Cow_field::is_cowed(cow_fields, virt) && (tlb_attr & TLB_P) && !(tlb_attr & TLB_W)) {
        mword hpa, ept_attr;
        size_t size = Pd::current->Space_mem::ept.lookup (gpa, hpa, ept_attr);
        call_log_funct(Logstore::add_entry_in_buffer, 0, "TLB_COW Pe %llu v: %lx "
            "tlb->addr: %lx attr %lx gpa %lx hpa %lx size %lx", Counter::nb_pe, 
            virt, addr(), tlb_attr, gpa, hpa, size);
        if (size && (addr() == (hpa & ~PAGE_MASK))) { 
            Counter::vtlb_cow_fault++;   
            assert(virt != Pe_stack::stack); 
            Cow_elt::resolve_cow_fault(this, nullptr, virt, addr(), tlb_attr);
            call_log_funct(Logstore::append_entry_in_buffer, 0, " IS_COW new "
            "tlb->val %llx", val);
            return true;            
        } else {
            return false;
        }
    } else {
        return false;
    }
}

/**
 * This update is very specific to our copy on write because it is relative to the entry 
 * directely. So, no page walking is needed.
 * @param phys
 * @param attr
 */
void Vtlb::cow_update(Paddr phys, mword attr){
    val = phys | attr;
}

size_t Vtlb::lookup(uint64 v, Paddr &p, mword &a, Vtlb* &tlb) {
    unsigned l = max();
    unsigned b = bpl();

    for(Vtlb *e = this;; e = static_cast<Vtlb *> (Buddy::phys_to_ptr(e->addr()))) {
//        char buff[STR_MAX_LENGTH];
//        String::print(buff, "lookup v: %llx tlb->addr: %lx attr %lx", v, e ? e->addr() : 0, e ? e->attr() : 0);
//        Logstore::append_log_in_buffer(buff);
        unsigned shift = --l * b + PAGE_BITS;
        e += v >> shift & ((1UL << b) - 1);
        if(!e || EXPECT_FALSE(!e->val) || !e->present())
            return 0;

        if(EXPECT_FALSE(l && !e->super()))
            continue;
        
        size_t s = 1UL << (l * b + e->order());

        p = static_cast<Paddr> (e->addr() | (v & (s - 1)));

        a = e->attr();
        
        tlb = e;

        return s;
    }
}

void Vtlb::reserve_stack(Queue<Cow_field> *cow_fields){
    if(Pe::in_debug_mode)
        return;
    mword guest_rsp = Vmcs::read(Vmcs::GUEST_RSP), vtlb_attr;
    Paddr vtlb_hpa;
    Vtlb* tlb = nullptr;
    size_t size_vtlb = lookup(guest_rsp, vtlb_hpa, vtlb_attr, tlb);
    if(size_vtlb && Cow_field::is_cowed(cow_fields, guest_rsp) && 
        (vtlb_attr & TLB_P) && !(vtlb_attr & TLB_W)) {
        Ec::pe_guest_rsp = guest_rsp;
        Cow_elt::resolve_cow_fault(tlb, nullptr, guest_rsp, vtlb_hpa, vtlb_attr);
    } else {
        Ec::pe_guest_rsp = 0;
    }
    vtlb_hpa = vtlb_attr = 0;
    tlb = nullptr;
    mword guest_idt = Vmcs::read(Vmcs::GUEST_BASE_IDTR);
    if(guest_idt && lookup(guest_idt, vtlb_hpa, vtlb_attr, tlb) && 
            Cow_field::is_cowed(cow_fields, guest_idt) && 
            (vtlb_attr & TLB_P) && !(vtlb_attr & TLB_W)) {
        uint64 prev_val = tlb->val;
        Cow_elt::resolve_cow_fault(tlb, nullptr, guest_idt, vtlb_hpa, vtlb_attr);
        call_log_funct(Logstore::add_entry_in_buffer, 0, "VTLB GUEST_IDT tlb "
            "val %llx:%llx vtlb_attr %lx guest_idt %lx PE %llu", prev_val, tlb->val, vtlb_attr, 
            guest_idt, Counter::nb_pe);
//        tlb->val &= ~TLB_P;
    }
    
    vtlb_hpa = vtlb_attr = 0;
    tlb = nullptr;
    mword guest_sysenter_esp = Vmcs::read(Vmcs::GUEST_SYSENTER_ESP);
    if(guest_sysenter_esp && (guest_sysenter_esp != guest_rsp) && 
        lookup(guest_sysenter_esp, vtlb_hpa, vtlb_attr, tlb) && 
        Cow_field::is_cowed(cow_fields, guest_sysenter_esp) && 
        (vtlb_attr & TLB_P) && !(vtlb_attr & TLB_W)) {
        uint64 prev_val = tlb->val;
        Cow_elt::resolve_cow_fault(tlb, nullptr, guest_sysenter_esp, vtlb_hpa, vtlb_attr);
        call_log_funct(Logstore::add_entry_in_buffer, 0, "VTLB GUEST_SYSENTER_ESP tlb "
            "val %llx:%llx vtlb_attr %lx guest_sysenter_esp %lx PE %llu", prev_val, tlb->val, vtlb_attr, 
            guest_sysenter_esp, Counter::nb_pe);
    }
    
    vtlb_hpa = vtlb_attr = 0;
    tlb = nullptr;
    mword guest_sysenter_eip = Vmcs::read(Vmcs::GUEST_SYSENTER_EIP);
    if(guest_sysenter_eip && lookup(guest_sysenter_eip, vtlb_hpa, vtlb_attr, tlb)
            && (vtlb_attr & TLB_P)) {
        if(sysenter_eip_is_cowed) {
            sysenter_eip_is_cowed = false;
        } else { 
            tlb->val &= ~TLB_P ;
            sysenter_eip_is_cowed = true;
            call_log_funct(Logstore::add_entry_in_buffer, 0, "VTLB GUEST_SYSENTER_EIP tlb "
                "val %llx vtlb_attr %lx guest_sysenter_eip %lx PE %llu", tlb->val, vtlb_attr, 
                guest_sysenter_eip, Counter::nb_pe);            
        }
    }
    
    vtlb_hpa = vtlb_attr = 0;
    tlb = nullptr;
    guest_sysenter_eip = Vmcs::read(Vmcs::GUEST_SYSENTER_EIP) + 0x1000;
    if(guest_sysenter_eip && lookup(guest_sysenter_eip, vtlb_hpa, vtlb_attr, tlb)
            && (vtlb_attr & TLB_P)) {
        if(sysenter_eip1_is_cowed) {
            sysenter_eip1_is_cowed = false;
        } else { 
            tlb->val &= ~TLB_P ;
            sysenter_eip1_is_cowed = true;
            call_log_funct(Logstore::add_entry_in_buffer, 0, "VTLB GUEST_SYSENTER_EIP tlb "
                "val %llx vtlb_attr %lx guest_sysenter_eip %lx PE %llu", tlb->val, vtlb_attr, 
                guest_sysenter_eip, Counter::nb_pe);            
        }
    }
    
    if(Vmcs::read(Vmcs::GUEST_RIP) != 0xc06b014a)
        return;
   
    vtlb_hpa = vtlb_attr = 0;
    tlb = nullptr;
    mword guest_gdt = Vmcs::read(Vmcs::GUEST_BASE_GDTR);
    size_vtlb = lookup(guest_gdt, vtlb_hpa, vtlb_attr, tlb);
    if(size_vtlb && Cow_field::is_cowed(cow_fields, guest_gdt) && 
           tlb && (vtlb_attr & TLB_P) && !(vtlb_attr & TLB_W)) {
//        call_log_funct(Logstore::add_entry_in_buffer, 1, "VTLB GUEST_GDT tlb "
//            "val %llx vtlb_attr %lx guest_gdt %lx PE %llu", tlb->val, vtlb_attr, 
//            guest_gdt, Counter::nb_pe);
        Cow_elt::resolve_cow_fault(tlb, nullptr, guest_gdt, vtlb_hpa, vtlb_attr);
    }
        
}

void Vtlb::map_address(mword virt, Queue<Cow_field> *cow_fields) {
    Paddr vtlb_hpa;
    mword vtlb_attr;
    Vtlb *tlb = nullptr;
    if(virt && lookup(virt, vtlb_hpa, vtlb_attr, tlb) && 
            (vtlb_attr & TLB_P)) {
        uint64 prev_val = tlb->val;
        if(cow_fields){
            if(!(vtlb_attr & TLB_W) && Cow_field::is_cowed(cow_fields, virt))
                Cow_elt::resolve_cow_fault(tlb, nullptr, virt, vtlb_hpa, vtlb_attr);
        } else {
            tlb->val &= ~TLB_P;
        }
        call_log_funct(Logstore::add_entry_in_buffer, 0, "VTLB GUEST_IDT tlb "
            "val %llx:%llx vtlb_attr %lx guest_idt %lx PE %llu", prev_val, tlb->val, vtlb_attr, 
            virt, Counter::nb_pe);
    }
}
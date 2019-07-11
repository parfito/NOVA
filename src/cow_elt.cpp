/* 
 * File:   cow_elt.cpp
 * Author: Parfait Tokponnon <mahoukpego.tokponnon@uclouvain.be>
 * 
 * Created on 7 octobre 2018, 21:29
 */

#include "cow_elt.hpp"
#include "pd.hpp"
#include "stdio.hpp"
#include "hpt.hpp"
#include "string.hpp"
#include "pe.hpp"
#include "vmx.hpp"
#include "pe_stack.hpp"
#include "ec.hpp"
#include "lapic.hpp"
#include "pd.hpp"
#include "crc.hpp"

Slab_cache Cow_elt::cache(sizeof (Cow_elt), 32);
Queue<Cow_elt> Cow_elt::cow_elts;
size_t Cow_elt::number = 0;
size_t Cow_elt::current_ec_cow_elts_size = 0;

Cow_elt::Cow_elt(mword v, Paddr phys, mword a, Page_type t, mword f_addr) : type(t), page_addr(v), old_phys(phys),
attr(a), prev(nullptr), next(nullptr) {
    // TODO: Implement handling of cow fault in big pages
    unsigned short ord = (t == NORMAL) ? 1 : 11;
    linear_add = Buddy::allocator.alloc(ord, Pd::kern.quota, Buddy::NOFILL);
    new_phys[0] = Buddy::ptr_to_phys(linear_add);
    new_phys[1] = new_phys[0] + (1UL << ((ord - 1) + PAGE_BITS));
    m_fault_addr = f_addr;
    ec_rip = Ec::current->get_reg(18);
    ec_rcx = Ec::current->get_regsRCX();
    ec_rsp = Ec::current->get_reg(19);
    if (Ec::current->is_virutalcpu()) {
        Paddr hpa_rcx_rip;
        mword attrib;
        Ec::current->vtlb_lookup(ec_rsp, hpa_rcx_rip, attrib);
        char *rsp_ptr = reinterpret_cast<char*> (Hpt::remap_cow(Pd::kern.quota, hpa_rcx_rip)) +
                (ec_rsp & PAGE_MASK);
        // if *(rip_ptr as mword) overflows to the next page 
        if ((reinterpret_cast<mword> (rsp_ptr) & PAGE_MASK) + sizeof (mword) > PAGE_SIZE) {
            Hpt::remap_cow(Pd::kern.quota, (hpa_rcx_rip &= ~PAGE_MASK) + PAGE_SIZE,
                    PAGE_SIZE);
        }
        ec_rsp_content = *reinterpret_cast<mword*> (rsp_ptr + 0x10);
    }
    number++;
}

/**
 * Clones a cow_elt (orig) which points to the same physical frames that the orig uses 
 * @param orig
 */
Cow_elt::Cow_elt(const Cow_elt& orig) : type(orig.type), page_addr(orig.page_addr),
old_phys(orig.old_phys), attr(orig.attr), prev(nullptr), next(nullptr) {
    linear_add = orig.linear_add;
    new_phys[0] = orig.new_phys[0];
    new_phys[1] = orig.new_phys[1];
    number++;
}

Cow_elt::~Cow_elt() {
    Buddy::allocator.free(reinterpret_cast<mword> (linear_add), Pd::kern.quota);
    number--;
}

/**
 * Resolve page faults caused by hardening module.
 * @param tlb  : if came from Virtual machine, virtual page table entry pointer (address) used by the 
 *              host when VM runs
 * @param hpt  : if came from user space, page table entry pointer (address)
 * @param virt : page virtual address fault occurs at
 * @param phys : page physical address mapped at
 * @param attr : entry attribut
 */
void Cow_elt::resolve_cow_fault(Vtlb* tlb, Hpt *hpt, mword virt, Paddr phys, mword attr) {
    mword fault_addr = virt;
    phys &= ~PAGE_MASK;
    virt &= ~PAGE_MASK;
    Counter::cow_fault++;
    /* Do not try again to optimize by avoiding a new Cow_elt creation when phys is mapped elsewhere
     * if you don't have a good reason to. When phys is already mapped elsewhere, 
     * a new Cow_elt is necessary to save data relative to the current cow fault.
     */
    Cow_elt *ce = new (Pd::kern.quota) Cow_elt(virt, phys, attr, Cow_elt::NORMAL, fault_addr),
            *c = is_mapped_elsewhere(phys);
    mword a;
    if (tlb) {
        assert(!hpt);
        ce->vtlb = tlb;
        a = ce->attr | Vtlb::TLB_W;
        a &= ~Vtlb::TLB_COW;
    } else if (hpt) {
        assert(!tlb);
        ce->hpt = hpt;
        a = ce->attr | Hpt::HPT_W;
        a &= ~Hpt::HPT_COW;
    } else {
        Console::panic("Neither tlb, nor htp is specified");
    }

    // If this page fault occurs in a virtual address that points to an already mapped (and in-use) 
    // physical frame, Do not triplicate frame to the newly allocated frames; use the existing ones
    if (c) {
//        trace(COW_FAULT, "virt %lx Pe %u", virt, Counter::nb_pe);
        ce->new_phys[0] = c->new_phys[0];
        ce->new_phys[1] = c->new_phys[1];
        ce->v_is_mapped_elsewhere = c;
        ce->crc = c->crc;
        c->v_is_mapped_elsewhere = ce;
    } else { // Triplicate frames
        if (hpt) {
            copy_frames(ce->new_phys[0], ce->new_phys[1], reinterpret_cast<void*> (virt));
            ce->crc = Crc::compute(0, reinterpret_cast<void*>(virt), PAGE_SIZE);
        }
        if (tlb) { // virt is not mapped in the kernel page table
            void *phys_to_ptr = Hpt::remap_cow(Pd::kern.quota, phys, 2 * PAGE_SIZE);
            copy_frames(ce->new_phys[0], ce->new_phys[1], phys_to_ptr);
            ce->crc = Crc::compute(0, phys_to_ptr, PAGE_SIZE);
        }
    }
    // update page table entry with the newly allocated frame1
    if (tlb) {
        tlb->cow_update(ce->new_phys[0], a);
    }
    if (hpt) {
        hpt->cow_update(ce->new_phys[0], a, ce->page_addr);
    }
    // update the cow pages list
    cow_elts.enqueue(ce);
    //    Console::print("Cow error  v: %lx  phys: %lx attr %lx phys1: %lx  phys2: %lx", virt, phys, 
    //          ce->attr, ce->new_phys[0], ce->new_phys[1]);            
}

/**
 * Checks if the physical page was already in-use and listed in COW page list (cow_elts)
 * Called from resolve_cow_fault
 * @param phys
 * @return 
 */
Cow_elt* Cow_elt::is_mapped_elsewhere(Paddr phys) {
    Cow_elt *c = cow_elts.head(), *n = nullptr;
    while (c) {
        if (c->old_phys == phys) {//frame already mapped elsewhere
//            trace_no_newline(COW_FAULT, "Is already mapped in Cow_elts::cow_elts: "
//                    "c->old_phys == phys : virt %lx Phys:%lx new_phys[0]:%lx new_phys[1]:%lx",
//                    c->page_addr, c->old_phys, c->new_phys[0], c->new_phys[1]);
            assert(!c->v_is_mapped_elsewhere);
            return c;
        }
        n = c->next;
        c = (c == n || n == cow_elts.head()) ? nullptr : n;
    }
    return nullptr;
}

/**
 * Triplicate frames, copy frame0 content to frame1 and frame2
 * @param ce
 * @param virt
 */
void Cow_elt::copy_frames(Paddr phys1, Paddr phys2, void* virt) {
    void *ptr = Hpt::remap_cow(Pd::kern.quota, phys1);
    memcpy(ptr, virt, PAGE_SIZE);
    ptr = Hpt::remap_cow(Pd::kern.quota, phys2);
    memcpy(ptr, virt, PAGE_SIZE);
}

void Cow_elt::restore_vm_stack_state0() {
    assert(Ec::current->is_virutalcpu());
    Cow_elt *c = Ec::current->vm_kernel_stacks_head(), *head = c, *n = nullptr;    
    while (c) {
        c->vtlb->cow_update(c->new_phys[1], c->attr);
        n = c->next;
        c = (c == n || n == head) ? nullptr : n;
    }
}

/**
 * Restore state0 frames by updating page table entries with the allocated frame2
 */
void Cow_elt::restore_state0() {
    if(Ec::current->is_virutalcpu())
        restore_vm_stack_state0();
    Cow_elt *c = cow_elts.head(), *n = nullptr;

    mword a;
    while (c) {
        if (c->vtlb) {
            a = c->attr | Vtlb::TLB_W;
            a &= ~Vtlb::TLB_COW;
            c->vtlb->cow_update(c->new_phys[1], a);
            debug_started_trace(0, "Cow Restore  ce: %p  virt: %lx  phys2: %lx attr %lx",
                    c, c->page_addr, c->new_phys[1], a);
        }
        if (c->hpt) {
            a = c->attr | Hpt::HPT_W;
            a &= ~Hpt::HPT_COW;
            c->hpt->cow_update(c->new_phys[1], a, c->page_addr);
        }

        n = c->next;
        c = (c == n || n == cow_elts.head()) ? nullptr : n;
    }
}

bool Cow_elt::compare_vm_stack(){
    assert(Ec::current->is_virutalcpu());
    Cow_elt *c = Ec::current->vm_kernel_stacks_head(), *head = Ec::current->vm_kernel_stacks_head(), 
            *n = nullptr;    
    while(c) {
        mword *ptr1 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->new_phys[0])),
                *ptr2 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->new_phys[1],
                PAGE_SIZE));
        uint32 crc1 = Crc::compute(0, ptr1, PAGE_SIZE);
        uint32 crc2 = Crc::compute(0, ptr2, PAGE_SIZE);
        if (crc1 == crc2) {
            c->crc1 = crc1;
        } else {
            // if in production, uncomment this, for not to get too many unncessary Missmatch errors because 
            // just of error in vm stack            
            int missmatch_addr = 0;
            int diff = memcmp(reinterpret_cast<char*> (ptr1), reinterpret_cast<char*> (ptr2),
                    missmatch_addr, PAGE_SIZE);
            assert(diff);
            //                asm volatile ("" ::"m" (missmatch_addr)); // to avoid gdb "optimized out"            
            //                asm volatile ("" ::"m" (c)); // to avoid gdb "optimized out"     
            // because memcmp compare by grasp of 4 bytes
            mword index = (PAGE_SIZE - 4 * (missmatch_addr + 1)) / sizeof (mword);
            mword val1 = *(ptr1 + index);
            mword val2 = *(ptr2 + index);
            mword *ptr0 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->old_phys, 
                    2 * PAGE_SIZE));
            mword val0 = *(ptr0 + index);
            Pe::missmatch_addr = c->page_addr + index * sizeof (mword);
            Paddr hpa_guest_rip;
            mword attr;
            Ec::current->vtlb_lookup(c->ec_rip, hpa_guest_rip, attr);
            void *rip_ptr = reinterpret_cast<char*> (Hpt::remap_cow(Pd::kern.quota, hpa_guest_rip,
                    3 * PAGE_SIZE)) +
                    (c->ec_rip & PAGE_MASK);
            // if *(rip_ptr as mword) overflows to the next page 
            if ((reinterpret_cast<mword> (rip_ptr) & PAGE_MASK) + sizeof (mword) > PAGE_SIZE) {
                Hpt::remap_cow(Pd::kern.quota, (hpa_guest_rip &= ~PAGE_MASK) + PAGE_SIZE,
                        4 * PAGE_SIZE);
            }
            char instr_buff[MIN_STR_LENGTH];
            instruction_in_hex(*reinterpret_cast<mword*> (rip_ptr), instr_buff);

            Console::print("MISSMATCH IN VM STACK Pd: %s PE %lu virt %lx:%lx phys0:%lx phys1 %lx "
                    "phys2 %lx rip %lx:%s rcx %lx rsp %lx:%lx ptr1: %p ptr2: %p  val0: 0x%lx  val1:"
                    " 0x%lx val2 0x%lx, nb_cow_fault %u counter1 %llx counter2 %llx nb_pe %u "
                    "nb_vm_pe %u vm_size %lu", 
                    Pd::current->get_name(), Pe::get_number(), c->page_addr, index * sizeof (mword),
                    c->old_phys, c->new_phys[0], c->new_phys[1], c->ec_rip, instr_buff, c->ec_rcx, 
                    c->ec_rsp, c->ec_rsp_content, ptr1, ptr2, val0, val1, val2, Counter::cow_fault, 
                    Ec::counter1, Lapic::read_instCounter(), Counter::nb_pe, Counter::nb_vm_pe, Ec::current->vm_kernel_stacks_size());
            return true;
        }
        n = c->next;
        c = (c == n || n == head) ? nullptr : n;
    }
    return false;
}
/**
 * checks if frame1 and frame2 are equal
 * @return true if they don't match
 */
bool Cow_elt::compare() {
    if(Ec::current->is_virutalcpu() && compare_vm_stack()){
        return true;
    }
    Cow_elt *c = cow_elts.head(), *n = nullptr;
    while (c) {
        //        Console::print("Compare v: %p  phys: %p  ce: %p  phys1: %p  phys2: %p", 
        //        cow->page_addr_or_gpa, cow->old_phys, cow, cow->new_phys[0]->phys_addr, 
        //        cow->new_phys[1]->phys_addr);
        mword *ptr1 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->new_phys[0])),
                *ptr2 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->new_phys[1],
                PAGE_SIZE));
        uint32 crc1 = Crc::compute(0, ptr1, PAGE_SIZE);
        uint32 crc2 = Crc::compute(0, ptr2, PAGE_SIZE);
        if (crc1 == crc2) {
            c->crc1 = crc1;
        } else {
            // if in production, uncomment this, for not to get too many unncessary Missmatch errors because 
            // just of error in vm stack            
            int missmatch_addr = 0;
            int diff = memcmp(reinterpret_cast<char*> (ptr1), reinterpret_cast<char*> (ptr2),
                    missmatch_addr, PAGE_SIZE);
            assert(diff);
            //                asm volatile ("" ::"m" (missmatch_addr)); // to avoid gdb "optimized out"            
            //                asm volatile ("" ::"m" (c)); // to avoid gdb "optimized out"     
            // because memcmp compare by grasp of 4 bytes
            mword index = (PAGE_SIZE - 4 * (missmatch_addr + 1)) / sizeof (mword);
            if(Ec::current->is_virutalcpu()){
                // Cow fault due to instruction side effect in VM kernel stack
                *(ptr1 + index) = *(ptr2 + index);
                crc1 = Crc::compute(0, ptr1, PAGE_SIZE);
                if(crc1 == crc2){
                    commit_vm_stack_ce(c, crc1, ptr1);
                    Ec::current->add_vm_kernel_stacks(c);
                    return false;
                }
            }
            mword val1 = *(ptr1 + index);
            mword val2 = *(ptr2 + index);
            // if in production, comment this and return true, for not to get too many unncessary 
            // Missmatch errors           
            
            mword *ptr0 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->old_phys, 
                    2 * PAGE_SIZE));
            mword val0 = *(ptr0 + index);
            Pe::missmatch_addr = c->page_addr + index * sizeof (mword);

            Paddr hpa_guest_rip;
            mword attr;
            Ec::current->vtlb_lookup(c->ec_rip, hpa_guest_rip, attr);
            void *rip_ptr = reinterpret_cast<char*> (Hpt::remap_cow(Pd::kern.quota, hpa_guest_rip,
                    3 * PAGE_SIZE)) +
                    (c->ec_rip & PAGE_MASK);
            // if *(rip_ptr as mword) overflows to the next page 
            if ((reinterpret_cast<mword> (rip_ptr) & PAGE_MASK) + sizeof (mword) > PAGE_SIZE) {
                Hpt::remap_cow(Pd::kern.quota, (hpa_guest_rip &= ~PAGE_MASK) + PAGE_SIZE,
                        4 * PAGE_SIZE);
            }
            char instr_buff[MIN_STR_LENGTH];
            instruction_in_hex(*reinterpret_cast<mword*> (rip_ptr), instr_buff);

            Console::print("MISSMATCH Pd: %s PE %lu virt %lx:%lx phys0:%lx phys1 %lx phys2 %lx "
                    "rip %lx:%s rcx %lx rsp %lx:%lx ptr1: %p ptr2: %p  val0: 0x%lx  val1: 0x%lx "
                    "val2 0x%lx, nb_cow_fault %u counter1 %llx counter2 %llx Nb_pe %u nb_vm_pe %u "
                    "vm_size %lu", 
                    Pd::current->get_name(), Pe::get_number(), c->page_addr, index * sizeof (mword),
                    c->old_phys, c->new_phys[0], c->new_phys[1], c->ec_rip, instr_buff, c->ec_rcx, 
                    c->ec_rsp, c->ec_rsp_content, ptr1, ptr2, val0, val1, val2, Counter::cow_fault, 
                    Ec::counter1, Lapic::read_instCounter(), Counter::nb_pe, Counter::nb_vm_pe, Ec::current->vm_kernel_stacks_size());
            if (Pe::in_recover_from_stack_fault_mode) {
                // If already in recovering from stack fault, 
                // if in development, we got a real bug, print info, 
                // if in production, we got an SEU, just return true
                c = cow_elts.head(), n = nullptr;
                while (c) {
                    trace(0, "Cow v: %lx  phys: %lx phys1: %lx  phys2: %lx", c->page_addr, c->old_phys,
                            c->new_phys[0], c->new_phys[1]);
                    n = c->next;
                    c = (c == n || n == cow_elts.head()) ? nullptr : n;
                }
                Console::print_page(reinterpret_cast<void*> (ptr1));
                Console::print_page(reinterpret_cast<void*> (ptr2));
            }
            return true;
        }
        n = c->next;
        c = (c == n || n == cow_elts.head()) ? nullptr : n;
    }
    return false;
}

void Cow_elt::commit_vm_stack(){
    assert(Ec::current->is_virutalcpu());
    Cow_elt *c = Ec::current->vm_kernel_stacks_head(), *head = Ec::current->vm_kernel_stacks_head(), 
            *n = nullptr;    
    while(c) {
        Paddr old_phys = c->old_phys;
        if (c->crc != c->crc1) {
            void *ptr0 = Hpt::remap_cow(Pd::kern.quota, old_phys), 
                    *ptr1 = Hpt::remap_cow(Pd::kern.quota, c->new_phys[0], PAGE_SIZE);
            memcpy(ptr0, ptr1, PAGE_SIZE);
            c->crc = c->crc1;
        }
        c->vtlb->cow_update(old_phys, c->attr);
        n = c->next;
        c = (c == n || n == head) ? nullptr : n;
    }  
    if(Ec::current->vm_kernel_stacks_size() > 3){
        head = Ec::current->vm_kernel_stacks_head();
        Ec::current->vm_kernel_stacks_dequeue(head);
        Cow_elt::free(head);
    }
}

void Cow_elt::commit_vm_stack_ce(Cow_elt* c, uint32 crc1, mword* ptr1){
    c->attr |= Vtlb::TLB_W;
    c->attr &= ~Vtlb::TLB_COW;
    void *ptr0 = Hpt::remap_cow(Pd::kern.quota, c->old_phys);
    uint32 crc0 = Crc::compute(0, ptr0, PAGE_SIZE);
    if(crc0 != crc1){
        memcpy(ptr0, ptr1, PAGE_SIZE);
        c->crc = crc1;
    }
//    c->page_addr = c->ec_rcx = c->ec_rip = c->ec_rsp = c->ec_rsp_content = 0;
    assert(cow_elts.dequeue(c));
    c->vtlb->cow_update(c->old_phys, c->attr);
    Cow_elt *ce = c->v_is_mapped_elsewhere;
    if (ce) { // if ce->old_phys is used elsewhere
        assert(cow_elts.dequeue(ce));
        Ec::current->add_vm_kernel_stacks(ce);
        ce->vtlb->cow_update(ce->old_phys, ce->attr);
    }
    size_t index = 0;
    Pd::current->cow_elts.index_of(c, index);
    if (index < current_ec_cow_elts_size) { // if c comes from previous PE
        current_ec_cow_elts_size--;
    }
}
/**
 * Only called if everything went fine during comparison, 
 * We can now copy memories back to frame0, destroy cow_elts 
 */
void Cow_elt::commit() {
    if(Ec::current->is_virutalcpu())
        commit_vm_stack();
    Cow_elt *c = nullptr;
    assert(Pd::current->is_cow_elts_empty());
    size_t count = 0;
    while (cow_elts.dequeue(c = cow_elts.head())) {
        //        Console::print("c %p", c);
        asm volatile ("" ::"m" (c)); // to avoid gdb "optimized out"                        
        
        Paddr old_phys = c->old_phys;
        int diff = (c->crc != c->crc1);
        if (diff) {
            void *ptr0 = Hpt::remap_cow(Pd::kern.quota, old_phys), 
                    *ptr1 = Hpt::remap_cow(Pd::kern.quota, c->new_phys[0], PAGE_SIZE);
            memcpy(ptr0, ptr1, PAGE_SIZE);
            c->crc = c->crc1;
        }
//        size_t ce_index = 0;
        Cow_elt *ce = c->v_is_mapped_elsewhere;
        if (count < current_ec_cow_elts_size) { // if c comes from previous PE
            if (ce) { // if ce->old_phys is used elsewhere
                // if ce was also in previous PE
//                if (Pd::current->cow_elts.index_of(ce, ce_index) && ce_index + count < current_ec_cow_elts_size) {
//                    Pd::current->cow_elts.index_of(ce, ce_index) will always be false because Pd::current->cow_elts was empty;
//                    count++;
//                    if (Ec::keep_cow || diff)
//                        Counter::used_cows_in_old_cow_elts++;
//                }
                assert(cow_elts.dequeue(ce));
                if (Ec::keep_cow || diff) {
                    Counter::used_cows_in_old_cow_elts++;
                    Pd::current->cow_elts.enqueue(c);
                    Pd::current->cow_elts.enqueue(ce);
                } else {
                    destroy(c, Pd::kern.quota);
                    destroy(ce, Pd::kern.quota);
                }
                // update ce->virt page table entry with the allocated the old frame
                if (ce->vtlb) {
                    ce->vtlb->cow_update(old_phys, ce->attr);
                }
                if (ce->hpt) {
                    ce->hpt->cow_update(old_phys, ce->attr, ce->page_addr);
                }
            } else {
                if (Ec::keep_cow || diff) {
                    Pd::current->cow_elts.enqueue(c);
                } else {
                    destroy(c, Pd::kern.quota);
                }
            }
        } else {
            Pd::current->cow_elts.enqueue(c);
            if (ce) { // if ce->old_phys is used elsewhere
                assert(cow_elts.dequeue(ce));
                Pd::current->cow_elts.enqueue(ce);
                // update ce->virt page table entry with the allocated the old frame
                if (ce->vtlb) {
                    ce->vtlb->cow_update(old_phys, ce->attr);
                }
                if (ce->hpt) {
                    ce->hpt->cow_update(old_phys, ce->attr, ce->page_addr);
                }
            }
        }
        if (c->vtlb) {
            c->vtlb->cow_update(old_phys, c->attr);
        }
        if (c->hpt) {
            c->hpt->cow_update(old_phys, c->attr, c->page_addr);
        }
        //        trace(0, "count %lu MM %x c %lx %lx %lx %lx ce %lx  index %lu", count, missmatch_addr, 
        //                c->page_addr, c->old_phys, c->new_phys[0], c->new_phys[1], reinterpret_cast<mword>(
        //                ce ? ce->page_addr : 0), reinterpret_cast<mword>(ce ? ce_index + count : 0));
        //        Pe::add_pe_state(count, c->crc, c->page_addr, c->old_phys, c->new_phys[0], c->new_phys[1], 
        //                reinterpret_cast<mword>(ce ? ce->page_addr : 0), 
        //                reinterpret_cast<mword>(ce ? ce_index + count : 0));
        count++;
    }
    //    trace(0, "============================================ Ec %s ec_cow_elts_size %lu", 
    //            Ec::current->get_name(), current_ec_cow_elts_size);
    Pe::set_ss_val(current_ec_cow_elts_size);
    current_ec_cow_elts_size = 0;
    Ec::keep_cow = false;
    if (Pe::in_recover_from_stack_fault_mode) {
        Pe::in_recover_from_stack_fault_mode = false;
        debug_started_trace(0, "Rollback finished");
    }
}

void Cow_elt::restore_vm_stack_state1() {
    assert(Ec::current->is_virutalcpu());
    Cow_elt *c = Ec::current->vm_kernel_stacks_head(), *head = Ec::current->vm_kernel_stacks_head(), 
            *n = nullptr;    
    while (c) {
        c->vtlb->cow_update(c->new_phys[0], c->attr);
        n = c->next;
        c = (c == n || n == head) ? nullptr : n;
    }
}

/**
 * Restore state1's frames by updating page table entries with the allocated frame2, in order to 
 * make the first run catch up the second run
 */
void Cow_elt::restore_state1() {
    if(Ec::current->is_virutalcpu())
        restore_vm_stack_state1();
    Cow_elt *c = cow_elts.head(), *n = nullptr;
    mword a;
    while (c) {
        if (c->vtlb) {
            a = c->attr | Vtlb::TLB_W;
            a &= ~Vtlb::TLB_COW;
            c->vtlb->cow_update(c->new_phys[0], a);
        }
        if (c->hpt) {
            a = c->attr | Hpt::HPT_W;
            a &= ~Hpt::HPT_COW;
            c->hpt->cow_update(c->new_phys[0], a, c->page_addr);
        }
        n = c->next;
        c = (c == n || n == cow_elts.head()) ? nullptr : n;
    }
}

void Cow_elt::rollback_vm_stack() {
    assert(Ec::current->is_virutalcpu());
    Cow_elt *c = Ec::current->vm_kernel_stacks_head(), *head = Ec::current->vm_kernel_stacks_head(),
            *n = nullptr;    
    while (c) {
        void *phys_to_ptr = Hpt::remap_cow(Pd::kern.quota, c->old_phys, 2 * PAGE_SIZE);
        copy_frames(c->new_phys[0], c->new_phys[1], phys_to_ptr);
        c->vtlb->cow_update(c->new_phys[0], c->attr);
        n = c->next;
        c = (c == n || n == head) ? nullptr : n;
    }
}

/*
 * upadate hpt or vtlb with old_phys value and attr
 * called when we have to re-execute the entire double execution
 */
void Cow_elt::rollback() {
    if(Ec::current->is_virutalcpu())
        rollback_vm_stack();
    Cow_elt *c = cow_elts.head(), *n = nullptr;
    mword a;
    while (c) {
        void *phys_to_ptr = Hpt::remap_cow(Pd::kern.quota, c->old_phys, 2 * PAGE_SIZE);
        copy_frames(c->new_phys[0], c->new_phys[1], phys_to_ptr);
        if (c->vtlb) {
            a = c->attr | Vtlb::TLB_W;
            a &= ~Vtlb::TLB_COW;
            c->vtlb->cow_update(c->new_phys[0], a);
            //            trace(0, "rollback v: %lx  phys: %lx attr %lx ce: %p  phys1: %lx  
            //            phys2: %lx", c->page_addr, c->old_phys, ca, ce, ce->new_phys[0], ce->new_phys[1]);        
        }
        if (c->hpt) {
            a = c->attr | Hpt::HPT_W;
            a &= ~Hpt::HPT_COW;
            c->hpt->cow_update(c->new_phys[0], a, c->page_addr);
        }
        n = c->next;
        c = (c == n || n == cow_elts.head()) ? nullptr : n;
    }
}

/**
 * updating page table entries of previous COW with the allocated frame1
 * @param is_vcpu : true if VM, false ordinary process
 */
void Cow_elt::place_phys0() {
    assert(is_empty());
    Cow_elt *d = nullptr;
    while (Pd::current->cow_elts.dequeue(d = Pd::current->cow_elts.head())) {
        Paddr phys;
        mword attrib;
        size_t s = Pd::current->Space_mem::loc[Cpu::id].lookup(d->page_addr, phys, attrib);
        if (!s || phys != d->old_phys || attrib != d->attr) {
            Cow_elt *de = d->v_is_mapped_elsewhere;
            if (de) {
                Pd::current->cow_elts.dequeue(de);
                destroy(de, Pd::kern.quota);
            }
            destroy(d, Pd::kern.quota);
            continue;
        }
        void *ptr0 = Hpt::remap_cow(Pd::kern.quota, d->old_phys, 2 * PAGE_SIZE);
        uint32 crc0 = Crc::compute(0, ptr0, PAGE_SIZE);
        if (d->crc != crc0) {
            copy_frames(d->new_phys[0], d->new_phys[1], ptr0);
            d->crc = crc0;
        }
        if (d->hpt) {
            mword a = d->attr | Hpt::HPT_W;
            a &= ~Hpt::HPT_COW;
            d->hpt->cow_update(d->new_phys[0], a, d->page_addr);
        }
        if (d->vtlb) { // virt is not mapped in the kernel page table
            mword a = d->attr | Vtlb::TLB_W;
            a &= ~Vtlb::TLB_COW;
            d->vtlb->cow_update(d->new_phys[0], a);
        }
        cow_elts.enqueue(d);
        current_ec_cow_elts_size++;
        Cow_elt *de = d->v_is_mapped_elsewhere;
        if (de) {
            if (de->hpt) {
                mword a = de->attr | Hpt::HPT_W;
                a &= ~Hpt::HPT_COW;
                de->hpt->cow_update(de->new_phys[0], a, de->page_addr);
            }
            if (de->vtlb) { // virt is not mapped in the kernel page table
                mword a = de->attr | Vtlb::TLB_W;
                a &= ~Vtlb::TLB_COW;
                de->vtlb->cow_update(de->new_phys[0], a);
            }
            Pd::current->cow_elts.dequeue(de);
            cow_elts.enqueue(de);
            current_ec_cow_elts_size++;
        }
        //        trace(0, "Placing %lu d %lx %lx %lx %lx de %lx", current_ec_cow_elts_size, 
        //                d->page_addr, d->old_phys, d->new_phys[0], d->new_phys[1], reinterpret_cast<mword>(
        //                de ? de->page_addr : 0)); 
        Pe::add_pe_state(d->page_addr, d->old_phys, d->new_phys[0],
                d->new_phys[1], reinterpret_cast<mword> (de ? de->page_addr : 0));
    }
    
    if(Ec::current->is_virutalcpu()){
        Cow_elt *c = Ec::current->vm_kernel_stacks_head(), 
                *head = Ec::current->vm_kernel_stacks_head(), *n = nullptr;    
        while(c) {
            void *ptr0 = Hpt::remap_cow(Pd::kern.quota, c->old_phys);
            uint32 crc0 = Crc::compute(0, ptr0, PAGE_SIZE);
            if (c->crc != crc0) {
                copy_frames(c->new_phys[0], c->new_phys[1], ptr0);
                c->crc = crc0;
            }
            c->vtlb->cow_update(c->new_phys[0], c->attr);
            n = c->next;
            c = (c == n || n == head) ? nullptr : n;
        }
    }
}

bool Cow_elt::is_kernel_vm_modified(){
    if(!Ec::current->is_virutalcpu())
        return false;
    Cow_elt *c = Ec::current->vm_kernel_stacks_head(), *head = Ec::current->vm_kernel_stacks_head(), 
            *n = nullptr;    
    while(c) {
        void *ptr1 = Hpt::remap_cow(Pd::kern.quota, c->new_phys[0], PAGE_SIZE);
        uint32 crc1 = Crc::compute(0, ptr1, PAGE_SIZE);
        if (c->crc != crc1) {
            return true;
        }
        n = c->next;
        c = (c == n || n == head) ? nullptr : n;
    }
    return false;
}
/**
 * this function is supposed to be called after place_phys0. If v is found in 
 * Ec::current->cow_elts, v is supposed to have been cowed.
 * @param v
 * @return 
 */
bool Cow_elt::would_have_been_cowed_in_place_phys0(mword v) {
    Cow_elt *c = Pd::current->cow_elts.head(), *head = Pd::current->cow_elts.head(), *n = nullptr;
    while (c) {
        if (v == c->page_addr)
            return true;
        n = c->next;
        c = (c == n || n == head) ? nullptr : n;
    }
    return false;
}

void Cow_elt::free(Cow_elt* c){
    mword a = c->attr | Vtlb::TLB_COW;
    a &= ~Vtlb::TLB_W;
    c->vtlb->cow_update(c->old_phys, a);
    Cow_elt::destroy(c, Pd::kern.quota);    
}
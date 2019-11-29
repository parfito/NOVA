/* 
 * File:   cow_elt.cpp
 * Author: Parfait Tokponnon <mahoukpego.tokponnon@uclouvain.be>
 * 
 * Created on 7 octobre 2018, 21:29
 */

#include "cow_elt.hpp"
#include "stdio.hpp"
#include "hpt.hpp"
#include "string.hpp"
#include "log.hpp"
#include "vmx.hpp"
#include "pe_stack.hpp"
#include "ec.hpp"
#include "lapic.hpp"
#include "crc.hpp"
#include "pe.hpp"
#include "log_store.hpp"

Slab_cache Cow_elt::cache(sizeof (Cow_elt), 32);
Queue<Cow_elt> *Cow_elt::cow_elts;
size_t Cow_elt::number = 0;
size_t Cow_elt::current_ec_cow_elts_size = 0;

Cow_elt::Cow_elt(mword addr, Paddr phys, mword a, Hpt* h, Vtlb* v, Page_type t, mword f_addr) : 
type(t), page_addr(addr), attr(a), prev(nullptr), next(nullptr) {
    // TODO: Implement handling of cow fault in big pages
    assert((h && (v == nullptr)) || (v && (h == nullptr)));
    phys_addr[0] = phys;
    /* Do not try again to optimize by avoiding a new Cow_elt creation when phys is mapped elsewhere
     * if you don't have a good reason to. When phys is already mapped elsewhere, 
     * a new Cow_elt is necessary to save data relative to the current cow fault.
     */
    Cow_elt *c = is_mapped_elsewhere(phys); 
    if(c){
// This page fault occurs in a virtual address that points to an already mapped (and in-use) 
// physical frame, Do not triplicate frame to the newly allocated frames; use the existing ones
        Console::print("virt %lx Pe %llu", addr, Counter::nb_pe);
        linear_add = nullptr;
        phys_addr[1] = c->phys_addr[1];
        phys_addr[2] = c->phys_addr[2];
        crc = c->crc;    
        if (h) {
            pte.hpt = h;
        } else if (v) { // virt is not mapped in the kernel page table
            pte.is_hpt = false;
            pte.vtlb = v;
        } else {
            Console::panic("Neither tlb, nor htp is specified");
        }
        v_is_mapped_elsewhere = c;
        c->v_is_mapped_elsewhere = this;
    } else {
        unsigned short ord = (t == NORMAL) ? 1 : 11;
        linear_add = Buddy::allocator.alloc(ord, Pd::kern.quota, Buddy::NOFILL);
        phys_addr[1] = Buddy::ptr_to_phys(linear_add);
        phys_addr[2] = phys_addr[1] + (1UL << ((ord - 1) + PAGE_BITS));
        if (h) {
            pte.hpt = h;
        } else if (v) { // virt is not mapped in the kernel page table
            pte.is_hpt = false;
            pte.vtlb = v;
        } else {
            Console::panic("Neither tlb, nor htp is specified");
        }
        copy_frames(phys_addr[1], phys_addr[2], phys);
        crc = Crc::compute(0, reinterpret_cast<void*>(COW_ADDR), PAGE_SIZE); // phys should have been mapped on COW_ADDR by copy_frames()
    }
    // update page table entry with the newly allocated frame1
    update_pte(Pe::run_number == 0 ? PHYS1 : PHYS2, RW);
    number++;
    // For debugging purpose =====================================================
    m_fault_addr = f_addr;
    ec_rcx = Ec::current->get_reg(Ec::RCX);
    ec_rip = Ec::current->get_reg(Ec::RIP);
    ec_rsp = Ec::current->get_reg(Ec::RSP);
    if (Ec::current->is_virutalcpu()) {
        Paddr hpa_rcx_rip;
        mword attrib;
        Ec::current->vtlb_lookup(static_cast<uint64>(ec_rsp), hpa_rcx_rip, attrib);
        mword *rsp_ptr = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, 
                hpa_rcx_rip, 3, sizeof(mword)));
        assert(rsp_ptr);
        ec_rsp_content = *rsp_ptr + 0x10;
    }
    //=============================================================================
}

/**
 * Clones a cow_elt (orig) which points to the same physical frames that the orig uses 
 * @param orig
 */
Cow_elt::Cow_elt(const Cow_elt& orig) : type(orig.type), page_addr(orig.page_addr), attr(orig.attr), 
        prev(nullptr), next(nullptr) {
    linear_add = 0;
    phys_addr[0] = orig.phys_addr[0];
    phys_addr[1] = orig.phys_addr[1];
    phys_addr[2] = orig.phys_addr[2];
    pte = orig.pte;
}

Cow_elt::~Cow_elt() {
    Cow_elt *e = v_is_mapped_elsewhere;
    if (linear_add) {
        Buddy::allocator.free(reinterpret_cast<mword> (linear_add), Pd::kern.quota);
    } else if (e) {
        // Only destroy this information if obj is not the original
        e->v_is_mapped_elsewhere = nullptr;
    }
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

    Cow_elt *c = new Cow_elt(virt, phys, attr, hpt, tlb, Cow_elt::NORMAL, fault_addr);

    cow_elts->enqueue(c);
//    Console::print("Cow error v: %lx attr %lx phys0: %lx  phys1: %lx  phys2: %lx", virt, c->attr, 
//            c->phys_addr[0], c->phys_addr[1], c->phys_addr[2]);            
}

/**
 * Checks if the physical page was already in-use and listed in COW page list (cow_elts)
 * Called from resolve_cow_fault
 * @param phys
 * @return 
 */
Cow_elt* Cow_elt::is_mapped_elsewhere(Paddr phys) {
    Cow_elt *c = cow_elts->head(), *n = nullptr, *h = cow_elts->head();
    while (c) {
        if (c->phys_addr[0] == phys) {//frame already mapped elsewhere
            trace_no_newline(0, "Is already mapped virt %lx Phys:%lx new_phys[0]:%lx new_phys[1]:%lx ",
                    c->page_addr, c->phys_addr[0], c->phys_addr[1], c->phys_addr[2]);
            assert(!c->v_is_mapped_elsewhere);
            return c;
        }
        n = c->next;
        c = (n == h) ? nullptr : n;
    }
    return nullptr;
}

/**
 * Triplicate frames, copy frame0 content to frame1 and frame2
 * @param ce
 * @param virt
 */
void Cow_elt::copy_frames(Paddr phys1, Paddr phys2, Paddr phys0) {
    void *ptr0 = Hpt::remap_cow(Pd::kern.quota, phys0, 0),
            *ptr1 = Hpt::remap_cow(Pd::kern.quota, phys1, 1),
            *ptr2 = Hpt::remap_cow(Pd::kern.quota, phys2, 2);
    memcpy(ptr1, ptr0, PAGE_SIZE);
    memcpy(ptr2, ptr0, PAGE_SIZE);
}

/**
 * Restore state0 frames by updating page table entries with the allocated frame2
 */
void Cow_elt::restore_state0() {
    Cow_elt *c = cow_elts->head(), *n = nullptr, *h = c;
    while (c) {
        c->update_pte(PHYS2, RW);
        n = c->next;
        c = (n == h) ? nullptr : n;
    }
}

/**
 * checks if frame1 and frame2 are equal
 * @return true if they don't match
 */
bool Cow_elt::compare() {
    Cow_elt *c = cow_elts->head(), *n = nullptr, *h = c;
    while (c) {
//        Console::print("Compare v: %p  phys: %p  ce: %p  phys1: %p  phys2: %p", 
//        cow->page_addr_or_gpa, cow->phys_addr[0], cow, cow->new_phys[0]->phys_addr, 
//        cow->new_phys[1]->phys_addr);
        void *ptr1 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->phys_addr[1], 1)),
                *ptr2 = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, c->phys_addr[2], 2));
        uint32 crc1 = Crc::compute(0, ptr1, PAGE_SIZE);
        uint32 crc2 = Crc::compute(0, ptr2, PAGE_SIZE);
        if (crc1 == crc2) {
            c->crc1 = crc1;
        } else {
            // if in production, uncomment this, for not to get too many unncessary Missmatch errors because 
            // just of error in vm stack            
            size_t missmatch_addr = 0;
            int diff = memcmp(ptr1, ptr2, missmatch_addr, PAGE_SIZE);
            assert(diff);
                asm volatile ("" ::"m" (missmatch_addr)); // to avoid gdb "optimized out"            
                asm volatile ("" ::"m" (c)); // to avoid gdb "optimized out"     
            // because memcmp compare by grasp of 4 bytes
//            int ratio = sizeof(mword)/4; // sizeof(mword) == 4 ? 1 ; sizeof(mword) == 8 ? 2
            size_t index = missmatch_addr/sizeof(mword);
//            if(Ec::current->is_virutalcpu()){
//                // Cow fault due to instruction side effect in VM kernel stack
//                *(reinterpret_cast<mword*>(ptr1) + index) = *(reinterpret_cast<mword*>(ptr2) + index);
//                crc1 = Crc::compute(0, ptr1, PAGE_SIZE);
//                if(crc1 == crc2){
//                    c->crc1 = crc1;
//                    continue;
//                }
//            }
            mword val1 = *(reinterpret_cast<mword*>(ptr1) + index);
            mword val2 = *(reinterpret_cast<mword*>(ptr2) + index);
            // if in production, comment this and return true, for not to get too many unncessary 
            // Missmatch errors           
            
            void *ptr0 = Hpt::remap_cow(Pd::kern.quota, c->phys_addr[0], 0);
            mword val0 = *(reinterpret_cast<mword*>(ptr0) + index);
            Pe::missmatch_addr = c->page_addr + missmatch_addr;

            void *rip_ptr;
            if(Ec::current->is_virutalcpu()){
                Paddr hpa_guest_rip;
                mword attr;
                Ec::current->vtlb_lookup(c->ec_rip, hpa_guest_rip, attr);
                rip_ptr = reinterpret_cast<char*>(Hpt::remap_cow(Pd::kern.quota, 
                        hpa_guest_rip, 3, sizeof(mword)));                
            }else{
                rip_ptr = reinterpret_cast<char*>(Hpt::remap_cow(Pd::kern.quota, 
                    Pd::current->Space_mem::loc[Cpu::id], c->ec_rip, 3, sizeof(mword)));
                assert(rip_ptr);
            }
            
            char instr_buff[STR_MIN_LENGTH];
            instruction_in_hex(*reinterpret_cast<mword*> (rip_ptr), instr_buff);
            String *s = new String(2*STR_MAX_LENGTH);
            String::print(s->get_string(), "MISSMATCH Pd: %s PE %llu virt %lx: phys0:%lx phys1 %lx phys2 %lx "
                "rip %lx:%s rcx %lx rsp %lx:%lx MM %lx index %lu %lx val0: 0x%lx  val1: 0x%lx "
                "val2 0x%lx", Pd::current->get_name(), Counter::nb_pe, c->m_fault_addr, c->phys_addr[0], 
                c->phys_addr[1], c->phys_addr[2], c->ec_rip, instr_buff, c->ec_rcx, c->ec_rsp, 
                c->ec_rsp_content, Pe::missmatch_addr, index, reinterpret_cast<mword>(reinterpret_cast<mword*>(c->page_addr) + index), val0, val1, val2);
            Logstore::add_entry_in_buffer(s->get_string());
            trace(0, "%s", s->get_string());
            delete s;
                // if in development, we got a real bug, print info, 
                // if in production, we got an SEU, just return true
            c = cow_elts->head(), n = nullptr, h = c;
            while (c) {
                trace(0, "Cow v: %lx  phys: %lx phys1: %lx  phys2: %lx", c->page_addr, c->phys_addr[0],
                    c->phys_addr[1], c->phys_addr[2]);
                n = c->next;
                c = (n == h) ? nullptr : n;
            }
//            Console::print_page(ptr0);
//            Console::print_page(ptr1);
//            Console::print_page(ptr2);
            return true;
        }        
        n = c->next;
        c = (n == h) ? nullptr : n;
    }
    return false;
}

/**
 * Only called if everything went fine during comparison, 
 * We can now copy memories back to frame0, destroy cow_elts 
 */
void Cow_elt::commit() {
    Cow_elt *c = cow_elts->head(), *tail = cow_elts->tail(), *next = nullptr;
    size_t count = 0;
    while (c) {
        //        Console::print("c %p", c);
        asm volatile ("" ::"m" (c)); // to avoid gdb "optimized out"                        
        Cow_elt *ce = c->v_is_mapped_elsewhere;
        if (c->linear_add) { 
            int diff = (c->crc != c->crc1);
            if (diff) {
                void *ptr0 = Hpt::remap_cow(Pd::kern.quota, c->phys_addr[0], 0), 
                        *ptr1 = Hpt::remap_cow(Pd::kern.quota, c->phys_addr[1], 1);
                memcpy(ptr0, ptr1, PAGE_SIZE); 
                c->crc = c->crc1;
            }
            if (!c->age || (c->age && diff) || Ec::keep_cow) {
                c->age++;
            } else { 
                c->age = -1; // to be destroyed;
            }
        } else {
        // if ce->phys_addr[0] is used elsewhere. Becareful, cloned cow_elt also has null linear_addr
            assert(ce); // Mandatory
            c->age = ce->age;    
                }
        c->update_pte(PHYS0,c->pte.is_hpt?RW:RO);

//        char buff[STR_MAX_LENGTH];
//        String::print(buff, "COMMIT count %lu c %lx %lx %lx %lx ce %lx ", count, c->page_addr, 
//            c->phys_addr[0], c->phys_addr[1], c->phys_addr[2], reinterpret_cast<mword>(ce ? ce->page_addr : 0));
//        trace(0, "%s", buff);
        c->to_log("COMMIT");
        count++;
    
        next = c->next;
        c = (c == tail) ? nullptr : next;
    }
    cow_elts = nullptr;
//    trace(0, "cow_elts %p Pd_cow %p size %lu %lu", &cow_elts, &Pd::current->cow_elts, cow_elts->size(), 
//            Pd::current->cow_elts.size());
    current_ec_cow_elts_size = 0;
    Ec::keep_cow = false;
}

/**
 * Restore state1's frames by updating page table entries with the allocated frame2, in order to 
 * make the first run catch up the second run
 */
void Cow_elt::restore_state1() {
    Cow_elt *c = cow_elts->head(), *n = nullptr, *h = c;
    while (c) {
        c->update_pte(PHYS1, RW);
        n = c->next;
        c = (n == h) ? nullptr : n;
    }
}

/**
 * Restore state1's frames by updating page table entries with the allocated frame2, in order to 
 * make the first run catch up the second run
 */
void Cow_elt::restore_state2() {
    Cow_elt *c = cow_elts->head(), *n = nullptr, *h = c;
    while (c) {
        c->update_pte(PHYS2, RW);
        n = c->next;
        c = (n == h) ? nullptr : n;
    }
}

/*
 * upadate hpt or vtlb with phys_addr[0] value and attr
 * called when we have to re-execute the entire double execution
 */
void Cow_elt::rollback() {
    Cow_elt *c = cow_elts->head(), *n = nullptr, *h = c;
    while (c) {
        copy_frames(c->phys_addr[1], c->phys_addr[2], c->phys_addr[0]);
        c->update_pte(PHYS1, RW);
        n = c->next;
        c = (n == h) ? nullptr : n;
    }
}

/*
 * upadate hpt or vtlb with phys_addr[0] value and attr
 * called when we have to re-execute the entire double execution
 */
void Cow_elt::debug_rollback() {
    Cow_elt *c = nullptr;
    while (cow_elts->dequeue(c = cow_elts->head())) {
        free(c);
    }
}

/**
 * updating page table entries of previous COW with the allocated frame1
 * @param is_vcpu : true if VM, false ordinary process
 */
void Cow_elt::place_phys0() {
    cow_elts = &Pd::current->cow_elts;
    Cow_elt *d = cow_elts->head(), *tail = cow_elts->tail(), *next =nullptr;
//    bool is_ro = true;
    while(d) {
        next = d->next; // d may be dequeued and destroyed in this loop
        cow_elts->dequeue(d);
        free(d);
        d = (d == tail) ? nullptr : next;          
    }
//    trace(0, "Pd %s Ec %s cow_elts size %lu %lu PE %u", Pd::current->get_name(), Ec::current->get_name(), 
//            cow_elts->size(), Pd::current->cow_elts.size(), Counter::nb_pe);
}

void Cow_elt::free(Cow_elt* c){
    Paddr phys;
    mword attr;
    if(Pd::current->Space_mem::loc[Cpu::id].lookup(c->page_addr, phys, attr) && 
            phys == c->phys_addr[0]){
        c->update_pte(PHYS0, RO);
    }
//    c->to_log("free deleting 1");      
    delete c;    
}

void Cow_elt::update_pte(Physic phys_type, Right right){
    mword a = attr;
    Paddr phys = 0;
    switch(phys_type){
        case PHYS0:
            phys = phys_addr[0];
            break;
        case PHYS1:
            phys = phys_addr[1];
            break;
        case PHYS2:
            phys = phys_addr[2];
            break;
        default:
            Console::panic("Wrong phys type");
    }
    if(pte.is_hpt)  {
        switch(right) {
        case RO:
            a &= ~Hpt::HPT_W;
            a |= Hpt::HPT_COW;
            break;
        case RW:
            a |= Hpt::HPT_W;
            a &= ~Hpt::HPT_COW;
            break;
        }
        pte.hpt->cow_update(phys, a, page_addr); 
    } else {
        switch(right) {
        case RO:
            a &= ~Vtlb::TLB_W;
            a |= Vtlb::TLB_COW;
            break;
        case RW:
            a |= Vtlb::TLB_W;
            a &= ~Vtlb::TLB_COW;
            break;
        }
       pte.vtlb->cow_update(phys, a); 
    }      
}

ALWAYS_INLINE
static inline void* Cow_elt::operator new (size_t){return cache.alloc(Pd::kern.quota);}

ALWAYS_INLINE
static inline void Cow_elt::operator delete (void *ptr) {
    cache.free (ptr, Pd::kern.quota);
}

void Cow_elt::to_log(const char* reason){
    char buff[2*STR_MAX_LENGTH];
    String::print(buff, "%s d %lx %lx %lx %lx %d de %lx next %lx %s", reason, page_addr, 
        phys_addr[0], phys_addr[1], phys_addr[2], age, v_is_mapped_elsewhere ? 
        page_addr : 0, next ? next->page_addr:0, pte.is_hpt ? "Hpt" : "VTLB");
    Logstore::add_entry_in_buffer(buff);    
}

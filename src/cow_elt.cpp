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
const char* Cow_elt::pte[3] = {"HPT", "EPT", "VTLB"}; 

Cow_elt::Cow_elt(Pte_type ptet, mword addr, Paddr phys, mword a, Page_type t) : 
    pte_type(ptet), type(t), attr(a), prev(nullptr), next(nullptr) {
    // TODO: Implement handling of cow fault in big pages
    mword fault_addr = addr;
    phys &= ~PAGE_MASK;
    addr &= ~PAGE_MASK;
    Counter::cow_fault++;
    page_addr = addr;
    phys_addr[0] = phys;
    /* Do not try again to optimize by avoiding a new Cow_elt creation when phys is mapped elsewhere
     * if you don't have a good reason to. When phys is already mapped elsewhere, 
     * a new Cow_elt is necessary to save data relative to the current cow fault.
     */
    Cow_elt *c = is_mapped_elsewhere(phys, addr); 
    if(c){
// This page fault occurs in a virtual address that points to an already mapped (and in-use) 
// physical frame, Do not triplicate frame to the newly allocated frames; use the existing ones
        linear_add = nullptr;
        phys_addr[1] = c->phys_addr[1];
        phys_addr[2] = c->phys_addr[2];
        crc = c->crc;   
        v_is_mapped_elsewhere = c;
        c->v_is_mapped_elsewhere = this;
    } else {
        unsigned short ord = (t == NORMAL) ? 1 : 11;
        linear_add = Buddy::allocator.alloc(ord, Pd::kern.quota, Buddy::NOFILL);
        phys_addr[1] = Buddy::ptr_to_phys(linear_add);
        phys_addr[2] = phys_addr[1] + (1UL << ((ord - 1) + PAGE_BITS));
        copy_frames(phys_addr[1], phys_addr[2], phys);
        crc = Crc::compute(0, reinterpret_cast<void*>(COW_ADDR), PAGE_SIZE); // phys should have been mapped on COW_ADDR by copy_frames()
    }
    number++;
    cow_elts->enqueue(this);
    // For debugging purpose =====================================================
    m_fault_addr = fault_addr;
    ec_rip = Ec::current->get_reg(Ec::RIP);
    ec_rax = Ec::current->get_reg(Ec::RAX);
    ec_rsp = Ec::current->get_reg(Ec::RSP);
    Paddr hpa_rip;
    mword attrib;
    mword *rip_ptr; 
    if (Ec::current->lookup(static_cast<uint64>(ec_rip), hpa_rip, attrib)){
            rip_ptr = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, 
                hpa_rip, 3, sizeof(mword)));
            assert(rip_ptr);
            instruction_in_hex(*rip_ptr, ec_rip_content);
        ec_es = Ec::current->get_regsES();
        ec_ss = Ec::current->get_regsSS();
    } else {
        String::print(ec_rip_content, "VM RIP NOT MAPPED");
    }
     //=============================================================================
}

/**
 * Clones a cow_elt (orig) which points to the same physical frames that the orig uses 
 * @param orig
 */
Cow_elt::Cow_elt(const Cow_elt& orig) : pte_type(orig.pte_type), type(orig.type), 
    page_addr(orig.page_addr), attr(orig.attr), prev(nullptr), next(nullptr) {
    linear_add = 0;
    phys_addr[0] = orig.phys_addr[0];
    phys_addr[1] = orig.phys_addr[1];
    phys_addr[2] = orig.phys_addr[2];
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
void Cow_elt::resolve_cow_fault_hpt(Hpt *h, mword virt, Paddr phys, mword attr) {
    Cow_elt *c = new Cow_elt(HPT, virt, phys, attr, Cow_elt::NORMAL);
    c->hpt = h;
    // update page table entry with the newly allocated frame1
    c->update_pte(Pe::run_number == 0 ? PHYS1 : PHYS2, true);
//    Console::print("Cow error v: %lx attr %lx phys0: %lx  phys1: %lx  phys2: %lx", virt, c->attr, 
//            c->phys_addr[0], c->phys_addr[1], c->phys_addr[2]);            
}

void Cow_elt::resolve_cow_fault_ept(Ept *e, mword virt, Paddr phys, mword attr) {
    Cow_elt *c = new Cow_elt(EPT, virt, phys, attr, Cow_elt::NORMAL);
    c->ept = e;
    c->update_pte(Pe::run_number == 0 ? PHYS1 : PHYS2, true);
}

void Cow_elt::resolve_cow_fault_vtlb(Vtlb* tlb, mword virt, Paddr phys, mword attr) {
    Cow_elt *c = new Cow_elt(VTLB, virt, phys, attr, Cow_elt::NORMAL);
    c->vtlb = tlb;
    c->update_pte(Pe::run_number == 0 ? PHYS1 : PHYS2, true);
}
/**
 * Checks if the physical page was already in-use and listed in COW page list (cow_elts)
 * Called from resolve_cow_fault
 * @param phys
 * @return 
 */
Cow_elt* Cow_elt::is_mapped_elsewhere(Paddr phys, mword virt) {
    Cow_elt *c = cow_elts->head(), *n = nullptr, *h = cow_elts->head();
    while (c) {
        if (c->phys_addr[0] == phys) {//frame already mapped elsewhere
            mword ec_rip = Ec::current->get_reg(Ec::RIP), ec_rsp = Ec::current->get_reg(Ec::RSP), 
                ec_rax = Ec::current->get_reg(Ec::RAX), attrib, ec_ss = 0, ec_es = 0;
            Paddr hpa_rip;
            char buff[STR_MIN_LENGTH];
            if (Ec::current->lookup(static_cast<uint64>(ec_rip), hpa_rip, attrib)){
                mword *rip_ptr = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, 
                    hpa_rip, 3, sizeof(mword)));
                instruction_in_hex(*rip_ptr, buff);
                ec_ss = Vmcs::read(Vmcs::GUEST_SEL_SS);
                ec_es = Vmcs::read(Vmcs::GUEST_SEL_ES);
            } else {
                String::print(buff, "VM RIP NOT MAPPED");
            }
            call_log_funct_with_buffer(Logstore::add_entry_in_buffer, 1, "Phys de virt = %lx Is already "
                "mapped virt %lx Phys:%lx new_phys[0]:%lx new_phys[1]:%lx Rip0 %lx:%s Rsp0 %lx Rax0 %lx "
                "ES0 %lx SS0 %lx Rip %lx:%s Rsp %lx Rax %lx ES %lx SS %lx", 
                virt, c->page_addr, c->phys_addr[0], c->phys_addr[1], c->phys_addr[2], c->ec_rip, 
                c->ec_rip_content, c->ec_rsp, c->ec_rax, c->ec_es, c->ec_ss, ec_rip, buff, ec_rsp, 
                ec_rax, ec_es, ec_ss);
//            assert(!c->v_is_mapped_elsewhere);
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
        c->update_pte(PHYS2, true);
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
            size_t missmatch_addr = 0, index = 0;
            int diff = 0;           
            mword val1, val2;
            bool is_resume_flag_set = false;
            if(Ec::current->is_virutalcpu()){
                mword rf_flag;
                if(sizeof(mword) == 8)
                    rf_flag = 1ull << 48;
                else
                    rf_flag = Cpu::EFL_RF;
                
                int page1 = 0, page2 = 0;
                do {
                    missmatch_addr = 0;
                    diff = page_comp(ptr1, ptr2, missmatch_addr, PAGE_SIZE);
                    assert(diff);
                    asm volatile ("" ::"m" (missmatch_addr)); // to avoid gdb "optimized out"            
                    asm volatile ("" ::"m" (c)); // to avoid gdb "optimized out"     
                    // because memcmp compare by grasp of 4 bytes
                    // int ratio = sizeof(mword)/4; // sizeof(mword) == 4 ? 1 ; sizeof(mword) == 8 ? 2
                    index = missmatch_addr/sizeof(mword);
                    val1 = *(reinterpret_cast<mword*>(ptr1) + index);
                    val2 = *(reinterpret_cast<mword*>(ptr2) + index);
                    if((val1 ^ val2) == rf_flag) {
                        is_resume_flag_set = true;
                        if(val1 & rf_flag) { // bit 1 in page 1
                            *(reinterpret_cast<mword*>(ptr1) + index) = *(reinterpret_cast<mword*>(ptr2) + index);
                            crc1 = Crc::compute(0, ptr1, PAGE_SIZE);
                            page1 ++;
                        } else { // bit 1 in page 2
                            *(reinterpret_cast<mword*>(ptr2) + index) = *(reinterpret_cast<mword*>(ptr1) + index);
                            crc2 = Crc::compute(0, ptr2, PAGE_SIZE);
                            page2 ++;
                        }
                    } else {
                        is_resume_flag_set = false;
                        break;
                    }
                } while(crc1 != crc2);
                if(is_resume_flag_set) {
                    if(page1 && page2)
                        call_log_funct(Logstore::add_entry_in_buffer, 1, "3rd run matches "
                        "partialy run1 %d and run2 %d", page1, page2);
                    if(page1)
                        c->crc1 = crc1;
                    else 
                        c->crc1 = crc2;
                }
            }else{
                missmatch_addr = 0;
                diff = page_comp(ptr1, ptr2, missmatch_addr, PAGE_SIZE);
                assert(diff);
                asm volatile ("" ::"m" (missmatch_addr)); // to avoid gdb "optimized out"            
                asm volatile ("" ::"m" (c)); // to avoid gdb "optimized out"     
                // because memcmp compare by grasp of 4 bytes
                // int ratio = sizeof(mword)/4; // sizeof(mword) == 4 ? 1 ; sizeof(mword) == 8 ? 2
                index = missmatch_addr/sizeof(mword);
                val1 = *(reinterpret_cast<mword*>(ptr1) + index);
                val2 = *(reinterpret_cast<mword*>(ptr2) + index);
            } 
                
            // if in production, comment this and return true, for not to get too many unncessary 
            // Missmatch errors    
            void *ptr0 = Hpt::remap_cow(Pd::kern.quota, c->phys_addr[0], 0);
            mword val0 = *(reinterpret_cast<mword*>(ptr0) + index);
            Pe::missmatch_addr = c->page_addr + missmatch_addr;
            call_log_funct_with_buffer(Logstore::add_entry_in_buffer, 1, "MISSMATCH "
                "Pd: %s PE %llu virt %#lx: phys0:%#lx phys1 %#lx phys2 %#lx rip %#lx:%s "
                "rcx %#lx rsp %#lx:%#lx MM %#lx index %lu %#lx val0: %#lx  val1: %#lx "
                "val2 %#lx %s", Pd::current->get_name(), Counter::nb_pe, c->m_fault_addr, 
                c->phys_addr[0], c->phys_addr[1], c->phys_addr[2], c->ec_rip, 
                c->ec_rip_content, c->ec_rcx, c->ec_rsp, c->ec_rsp_content, Pe::missmatch_addr, 
                index, reinterpret_cast<mword>(reinterpret_cast<mword*>(c->page_addr) 
                + index), val0, val1, val2, is_resume_flag_set ? "Resume flag set": "Fatal");
            if(!is_resume_flag_set) {
                // if in development, we got a real bug, print info, 
                // if in production, we got an SEU, just return true
                    if(IN_PRODUCTION)
                        return true;
                c = cow_elts->head(), n = nullptr, h = c;
                while (c) {
                    trace(0, "Cow v: %lx  phys: %lx phys1: %lx  phys2: %lx", c->page_addr, c->phys_addr[0],
                        c->phys_addr[1], c->phys_addr[2]);
                    n = c->next;
                    c = (n == h) ? nullptr : n;
                }
                Console::print_page(ptr0);
                Console::print_page(ptr1);
                Console::print_page(ptr2);
                return true;
            }        
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
    Cow_elt *c = cow_elts->head(), *h = c, *next = nullptr;
    call_log_funct(Logstore::add_entry_in_buffer, 0, "Committing PE %llu", Counter::nb_pe);
    size_t count = 0;
    while (c) {
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
        c->update_pte(PHYS0, false);

        c->to_log("COMMIT");
        count++;
    
        next = c->next;
        c = (next == h) ? nullptr : next;
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
        c->update_pte(PHYS1, true);
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
        c->update_pte(PHYS2, true);
        n = c->next;
        c = (n == h) ? nullptr : n;
    }
}

/*
 * called when we have to re-execute the entire double execution with their 
 * cow faults
 */
void Cow_elt::rollback() {
    Cow_elt *c = nullptr;
    while (cow_elts->dequeue(c = cow_elts->head())) {
        free(c);
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
 * reset pages to their original frames
 */
void Cow_elt::free_current_pd_cowelts() {
    cow_elts = &Pd::current->cow_elts;
    Cow_elt *d = nullptr;
    while(cow_elts->dequeue(d = cow_elts->head())) {
        free(d);
    }
}

void Cow_elt::free(Cow_elt* c){
    Paddr phys;
    mword attr;
    if(Ec::current->lookup(c->page_addr, phys, attr) && (attr | Hpt::HPT_W)) { 
        if(phys == c->phys_addr[0]) {
            c->update_pte(PHYS0, false);            
        } else if(Ec::nb_try && 
            ((phys == c->phys_addr[1]) || phys == c->phys_addr[2])){
            c->update_pte(PHYS0, false);
        } else { // Someone changed dramatically the mapping
            trace(0, "cow %#lx %#lx %#lx %#lx has changed to %#lx", c->page_addr, 
                c->phys_addr[0], c->phys_addr[1], c->phys_addr[2], phys);
        }
        
    }
//    c->to_log("free deleting 1");      
    delete c;    
}

void Cow_elt::update_pte(Physic phys_type, bool rw){
    Paddr phys = phys_addr[phys_type];
    switch(pte_type) {
    case HPT:
        hpt->cow_update(phys | attr, rw, page_addr); 
        break;
    case EPT:
       ept->cow_update(phys | attr, rw);
       break;
    case VTLB:
        vtlb->cow_update(phys | attr, rw);
    }      
}

ALWAYS_INLINE
static inline void* Cow_elt::operator new (size_t){return cache.alloc(Pd::kern.quota);}

ALWAYS_INLINE
static inline void Cow_elt::operator delete (void *ptr) {
    cache.free (ptr, Pd::kern.quota);
}

void Cow_elt::to_log(const char* reason){
    call_log_funct_with_buffer(Logstore::add_entry_in_buffer, 0, "%s d %lx %lx %lx %lx %d de %lx next %lx %s", reason, page_addr, 
        phys_addr[0], phys_addr[1], phys_addr[2], age, v_is_mapped_elsewhere ? 
        v_is_mapped_elsewhere->page_addr : 0, next ? next->page_addr:0, pte[pte_type]);
}

void Cow_elt::abort() {
    cow_elts = &Pd::current->cow_elts;
    Cow_elt *d = nullptr;
    uint8 phys_from = Pe::run_number == 0 ? 1 : 2;
    int n= 0;
    while(cow_elts->dequeue(d = cow_elts->head())) {
        void *ptr = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, d->phys_addr[phys_from], phys_from));
        assert(Crc::compute(0, ptr, PAGE_SIZE) == d->crc);
        d->update_pte(PHYS0, false);
        delete d;    
        n++;
    }
    assert(n == 1);
}

bool Cow_elt::is_pe_empty() {
    cow_elts = &Pd::current->cow_elts;
    Cow_elt *d = nullptr;
    int n= 0;
    uint8 phys_from = Pe::run_number == 0 ? 1 : 2;
    while(cow_elts->dequeue(d = cow_elts->head())) {
        void *ptr = reinterpret_cast<mword*> (Hpt::remap_cow(Pd::kern.quota, d->phys_addr[phys_from], phys_from));
        if(Crc::compute(0, ptr, PAGE_SIZE) != d->crc)
            return false;
        if(n > 1)
            return false;
    }
    if(n == 1)
        return true;
    else
        return false;
}
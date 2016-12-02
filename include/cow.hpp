/* 
 * File:   cow.hpp
 * Author: parfait
 *
 * Created on 13 novembre 2015, 22:09
 */
#pragma once

#include "memory.hpp"
#include "types.hpp"
#include "buddy.hpp"
#include "pd.hpp"
#include "hip.hpp"

#ifndef COW_HPP
#define	COW_HPP

class Cow {
private:
    static Spinlock cow_lock;

public:
    static uint16 frame_index_max;
    static uint16 elt_index_max;
    static bool max_displayed;

    struct cow_frame {
        Paddr phys_addr;
        uint16 index;
        bool used = false;
    };
    static struct cow_frame cow_frames[NB_COW_FRAME];

    struct cow_elt {
        mword page_addr_or_gpa; // if VM, this will hold the gpa, else hold page addr
        mword gla;
        Paddr old_phys;
        mword attr;
        struct cow_frame* new_phys[2];
        bool used = false;
        bool cowed = false;
        struct cow_elt *next = nullptr;
    };
    static struct cow_elt cow_list[NB_COW_ELT];

    struct block {
        Paddr start;
        Paddr end;
        bool used = false;
        block *next = nullptr;
    };
    static struct block block_elts[NB_BLOCK_ELT];
    static struct block *ram_mem_list;

    enum Multiboot_Type {
        MULTIBOOT_MODULE = -2,
        MICROHYPERVISOR = -1,
        AVAILABLE_MEMORY = 1,
        RESERVED_MEMORY = 2,
        ACPI_RECLAIM_MEMORY = 3,
        ACPI_NVS_MEMORY = 4
    };

    Cow();
    //    Cow(const Cow& orig);
    virtual ~Cow();

    static void initialize() {
        // Allocate NB_COW_FRAME cow frames
        for (uint64 i = 0; i < NB_COW_FRAME; i++)
            cow_frames[i].phys_addr = Buddy::ptr_to_phys(Buddy::allocator.alloc(0, Pd::kern.quota, Buddy::FILL_0));

        // calculate the physical address space for the RAM
        Hip_mem *mem_desc = Hip::get_mem_desc();
        uint32 num_mem_desc = (Hip::get_length() - Hip::get_mem_offset()) / Hip::get_mem_size();
        for (uint32 i = 0; i < num_mem_desc; i++, mem_desc++) {
            if (mem_desc->type == AVAILABLE_MEMORY) {
                struct block *b = get_new_block_elt(), *tampon = ram_mem_list;
                b->start = align_up(static_cast<Paddr> (mem_desc->addr), PAGE_SIZE); // Core rounds the start to the upper page boundary
                b->end = align_dn(static_cast<Paddr> (mem_desc->addr + mem_desc->size), PAGE_SIZE); // Core truncate the size to the lower page boundary
                ram_mem_list = b;
                b->next = tampon;
            }
        }
        struct block *b = ram_mem_list;
        while (b != nullptr) {
            if (b->start == 0x0UL) {
                b->start = 0x1000UL; // Core : [0 - 1000[ is needed as I/O memory by the VESA driver, remove it from Ram space */
            }
            //                        Console::print("deb: %08lx  fin: %08lx", b->start, b->end);
            b = b->next;
        }
    }

    static struct block* get_new_block_elt() {
        for (uint16 i = 0; i < NB_BLOCK_ELT; i++) {
            if (!block_elts[i].used) {
                block_elts[i].used = true;
                return &block_elts[i];
            }
        }
        return nullptr; //Normally this should never happen cause we allocate NB_BLOCK_ELT = 10
    }

    /**
     * @param elt_index
     * @return 
     */
    static bool get_cow_list_elt(uint16 & elt_index);
    static bool get_new_cow_frame(uint16 & frame_index);
    static void free_cow_frame(struct cow_frame * frame_ptr);

    static void free_cow_elt(cow_elt * cow);

    static bool get_new_cow_frame(cow_frame** frame_ptr);

    static bool get_cow_list_elt(cow_elt** cow_ptr);
    static bool subtitute(Paddr phys, cow_elt* cow, mword addr);

};

#endif	/* COW_HPP */

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
    static void initialize();

};

#endif	/* COW_HPP */

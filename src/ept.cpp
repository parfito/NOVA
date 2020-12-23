/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ept.hpp"
#include "cow_elt.hpp"
#include "stdio.hpp"
#include "ec.hpp"

mword Ept::ept_type;

void Ept::cow_update(uint64 new_val, bool rw) {
    new_val = rw ? new_val | EPT_W : new_val & ~EPT_W;
    Ept o;
    do o = *this; while (o.val != new_val && !set (o.val, new_val));
    flush();    
 }

bool Ept::is_cow_fault(mword v){
    Paddr p; mword a; Ept *e = nullptr;
    size_t s = cow_walk(v, p, a, e);
    if(!s)
        return false;
    assert(e);
    Cow_elt::resolve_cow_fault_ept(e, v, p, a);
    call_log_funct(Logstore::add_entry_in_buffer, Ec::nb_try ? 1 : 0, "entry gla "
        "%#lx p %#lx new_p %#lx attr %#lx", v, p, e->addr(), e->attr());
    return true;
}

Paddr Ept::get_addr() {
    return addr();
}
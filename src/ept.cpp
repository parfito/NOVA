/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ept.hpp"
#include "cow_elt.hpp"
#include "stdio.hpp"

mword Ept::ept_type;

void Ept::cow_update(mword new_val, bool rw) {
    new_val = rw ? new_val | EPT_W : new_val & ~EPT_W;
    Ept o;
    do o = *this; while (o.val != new_val && !set (o.val, new_val));
    flush();    
}

bool Ept::is_cow_fault(mword v){
    Ept *e = cow_walk(v);
    if(!e)
        return false;
    Cow_elt::resolve_cow_fault_ept(e, v, e->addr(), e->attr());
    call_log_funct(Logstore::add_entry_in_buffer, 0, "entry gla %#lx hpa %#lx %#lx", v, e->addr(), e->attr());
    return true;
}

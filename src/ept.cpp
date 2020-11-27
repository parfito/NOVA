/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "ept.hpp"
mword Ept::ept_type;

bool Ept::cow_update(mword v){
    Ept o, *e = cow_walk(v);
    if(!e)
        return false;
    mword new_val = e->addr() | e->attr() | EPT_W;
    do o = *e; while (o.val != new_val && !e->set (o.val, new_val));
    flush();    
    return true;
}
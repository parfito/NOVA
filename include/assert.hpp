/*
 * Assertions
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

#pragma once

#include "console.hpp"

#define assert(X)   do {                                                                                    \
                        if (EXPECT_FALSE (!(X)))                                                            \
                            Console::panic ("Assertion \"%s\" failed at %s:%d:%s", #X, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
                    } while (0)

/**
* assert_value(X, "string %s int %d", val_string, val_int)
*/ 
#define assert_value(X, FMT, ...)   do {                                                                                    \
                        if (EXPECT_FALSE (!(X))) {                                                          \
                            trace(0, FMT, ##__VA_ARGS__);                                                      \
                            Console::panic ("Assertion \"%s\" failed at %s:%d:%s", #X, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
                        }                                                                                                                   \
                    } while (0)

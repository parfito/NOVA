/*
 * Configuration
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

#define CFG_VER         8

#define NUM_CPU         64
#define NUM_IRQ         16
#define NUM_EXC         32
#define NUM_VMI         256
#define NUM_GSI         128
#define NUM_LVT         6
#define NUM_MSI         1
#define NUM_IPI         3

#define SPN_SCH         0
#define SPN_HLP         1
#define SPN_RCU         2
#define SPN_VFI         4
#define SPN_VFL         5
#define SPN_LVT         7
#define SPN_IPI         (SPN_LVT + NUM_LVT)
#define SPN_GSI         (SPN_IPI + NUM_IPI)

#define DEBUG           1
#define MAX_INSTRUCTION 0x100000
#define STR_MAX_LENGTH  80
#define STR_MIN_LENGTH  20

#define DEBUG_CMD_SHIFT          0
#define DEBUG_CMD_KILL           1
#define DEBUG_CMD_LOG            2
#define DEBUG_CMD_BITS           2
#define DEBUG_CMD_MASK           ((1 << DEBUG_CMD_BITS) - 1)

#define DEBUG_SCOPE_SHIFT        DEBUG_CMD_BITS
#define DEBUG_SCOPE_EC           0
#define DEBUG_SCOPE_PD           1
#define DEBUG_SCOPE_SYSTEM       2
#define DEBUG_SCOPE_BITS         2
#define DEBUG_SCOPE_MASK         ((1 << DEBUG_SCOPE_BITS) - 1)

#define DEBUG_STATE_SHIFT        (DEBUG_CMD_BITS + DEBUG_SCOPE_BITS)
#define DEBUG_STATE_OFF          0
#define DEBUG_STATE_ON           1
#define DEBUG_STATE_BITS         1
#define DEBUG_STATE_MASK         ((1 << DEBUG_STATE_BITS) - 1)

#define IN_PRODUCTION            0
#define LOG_MAX                 10000
#define LOG_PERCENT_TO_BE_LEFT  10
#define LOG_ENTRY_MAX           20*LOG_MAX

#define ENTRY_OFFSET    PAGE_SIZE
#define BUFFER_ORDER    2
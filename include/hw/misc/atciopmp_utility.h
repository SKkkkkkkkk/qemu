/*
 *  Andes Input Output Physical Memory Protection
 *
 * Copyright (c) 2023-2024 Andes Tech. Corp.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef ATCIOPMP_UTILITY_H
#define ATCIOPMP_UTILITY_H

#include "qemu/typedefs.h"

typedef enum {
    IOPMP_AMATCH_OFF,  /* Null (off)                            */
    IOPMP_AMATCH_TOR,  /* Top of Range                          */
    IOPMP_AMATCH_NA4,  /* Naturally aligned four-byte region    */
    IOPMP_AMATCH_NAPOT /* Naturally aligned power-of-two region */
} iopmp_am_t;

typedef enum {
    IOPMP_NONE = 0,
    IOPMP_RO   = 1,
    IOPMP_WO   = 2,
    IOPMP_RW   = 3,
    IOPMP_XO   = 4,
    IOPMP_RX   = 5,
    IOPMP_WX   = 6,
    IOPMP_RWX  = 7,
} iopmp_permission;

typedef struct {
    uint64_t sa;
    uint64_t ea;
} iopmp_addr_t;

/* To verfiy the same transaction */
typedef struct iopmp_transaction_state {
    bool supported;
    bool running;
    hwaddr start_addr;
    hwaddr end_addr;
    bool error_pending;
} iopmp_transaction_state;

typedef struct Iopmp_StreamSink {
    Object parent;
} Iopmp_StreamSink;

#endif

/*
 *  Andes Input Output Physical Memory Protection, ATCIOPMP300
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

#ifndef ATCIOPMP300_H
#define ATCIOPMP300_H

#include "hw/sysbus.h"
#include "qemu/typedefs.h"
#include "memory.h"
#include "hw/stream.h"
#include "hw/misc/riscv_iopmp_transaction_info.h"
#include "hw/misc/atciopmp_utility.h"

#define TYPE_ATCIOPMP300 "atciopmp300"
OBJECT_DECLARE_SIMPLE_TYPE(Atciopmp300state, ATCIOPMP300)

#define IOPMP300_MAX_MD_NUM          31
#define IOPMP300_MAX_SID_NUM         33
#define IOPMP300_MAX_K_NUM           16
/* For rapid-k model MAX_ENTRY_NUM = MD * K */
#define IOPMP300_MAX_ENTRY_NUM       (IOPMP300_MAX_MD_NUM * IOPMP300_MAX_K_NUM)

typedef struct {
    uint32_t addr_reg;
    uint32_t addrh_reg;
    uint32_t cfg_reg;
} iopmp300_entry_t;

typedef struct {
    uint32_t srcmd_en[IOPMP300_MAX_SID_NUM];
    uint32_t mdcfg[IOPMP300_MAX_MD_NUM];
    iopmp300_entry_t entry[IOPMP300_MAX_ENTRY_NUM];
    uint32_t mdlck;
    uint32_t entrylck;
    uint32_t mdcfglck;
    uint32_t arrlck;
    uint32_t mdstall;
    uint32_t errreact;
    uint64_t err_reqaddr;
    uint32_t err_reqsid;
    uint32_t err_reqinfo;
} iopmp300_regs;

typedef struct Atciopmp300state {
    SysBusDevice parent_obj;
    iopmp_addr_t entry_addr[IOPMP300_MAX_ENTRY_NUM];
    iopmp_transaction_state transaction_state[IOPMP300_MAX_SID_NUM];
    QemuMutex iopmp_transaction_mutex;
    MemoryRegion mmio;
    IOMMUMemoryRegion iommu;
    iopmp300_regs regs;
    MemoryRegion *downstream;
    MemoryRegion blocked_r, blocked_w, blocked_x, blocked_rw, blocked_rx,
                 blocked_wx, blocked_rwx;
    uint32_t k;
    Iopmp_StreamSink transaction_info_sink;

    AddressSpace iopmp_sysbus_as;
    AddressSpace downstream_as;
    AddressSpace blocked_r_as, blocked_w_as, blocked_x_as, blocked_rw_as,
                 blocked_rx_as, blocked_wx_as, blocked_rwx_as;
    qemu_irq irq;
    bool enable;
    volatile bool sid_stall[IOPMP300_MAX_SID_NUM];
    bool is_stalled;
    uint64_t md_stall_stat;
    uint32_t prio_entry;

    uint32_t sid_num;
    uint32_t md_num;
    uint32_t entry_num;
} Atciopmp300state;

DeviceState *atciopmp300_create(hwaddr addr, qemu_irq irq);

void iopmp300_setup_system_memory(DeviceState *dev, const MemMapEntry *memmap,
                                  uint32_t mapentry_num);
#endif

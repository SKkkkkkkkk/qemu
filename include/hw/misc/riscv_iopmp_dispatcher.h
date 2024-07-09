/*
 * QEMU RISC-V IOPMP dispatcher
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

#ifndef RISCV_IOPMP_DISPATCHER_H
#define RISCV_IOPMP_DISPATCHER_H

#include "hw/sysbus.h"
#include "qemu/typedefs.h"
#include "memory.h"
#include "hw/stream.h"
#include "hw/misc/riscv_iopmp_transaction_info.h"
#include "exec/hwaddr.h"

#define TYPE_IOPMP_DISPATCHER "iopmp_dispatcher"
#define IOPMP_DISPATCHER(obj) OBJECT_CHECK(Iopmp_Dispatcher_State, (obj), TYPE_IOPMP_DISPATCHER)

/* Handle n->iommu_idx < memory_region_iommu_num_indexes */
#define IOPMP_DISPATCHER_SID_NUM 33

typedef struct Iopmp_Dispatcher_StreamSink {
    Object parent;
} Iopmp_Dispatcher_StreamSink;

typedef struct Iopmp_Dispatcher_State {
    SysBusDevice parent_obj;
    IOMMUMemoryRegion iommu;
    Iopmp_Dispatcher_StreamSink transaction_info_sink;

    AddressSpace dispatcher_as;
    AddressSpace **target_as;
    StreamSink **target_sink;
    MemMapEntry *target_map;
    uint32_t target_num;
} Iopmp_Dispatcher_State;

void iopmp_dispatcher_add_target(DeviceState *dev, AddressSpace *as,
    StreamSink *sink, uint64_t base, uint64_t size, int id);

#endif

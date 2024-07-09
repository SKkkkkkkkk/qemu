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

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "trace.h"
#include "exec/exec-all.h"
#include "exec/address-spaces.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "hw/misc/riscv_iopmp_dispatcher.h"
#include "memory.h"
#include "hw/irq.h"

#define TYPE_IOPMP_DISPATCHER_IOMMU_MEMORY_REGION \
    "iopmp-dispatcher-iommu-memory-region"
#define TYPE_IOPMP_DISPATCHER_TRANSACTION_INFO_SINK \
    "iopmp_dispatcher_transaction_info_sink"

DECLARE_INSTANCE_CHECKER(Iopmp_Dispatcher_StreamSink,
                         IOPMP_DISPATCHER_TRANSACTION_INFO_SINK,
                         TYPE_IOPMP_DISPATCHER_TRANSACTION_INFO_SINK)

static IOMMUTLBEntry iopmp_dispatcher_translate(IOMMUMemoryRegion *iommu,
    hwaddr addr, IOMMUAccessFlags flags, int iommu_idx)
{
    Iopmp_Dispatcher_State *s;

    IOMMUTLBEntry entry = {
        .target_as = &address_space_memory,
        .iova = addr,
        .translated_addr = addr,
        .addr_mask = (~(hwaddr)0),
        .perm = IOMMU_RW,
    };

    s = IOPMP_DISPATCHER(container_of(iommu, Iopmp_Dispatcher_State, iommu));

    for (int i = 0; i < s->target_num; i++) {
        if (s->target_map[i].base <= addr &&
            addr < s->target_map[i].base + s->target_map[i].size) {
                entry.target_as = s->target_as[i];
                return entry;
        }
    }
    return entry;
}

static void iopmp_dispatcher_realize(DeviceState *dev, Error **errp)
{
    Object *obj = OBJECT(dev);
    Iopmp_Dispatcher_State *s = IOPMP_DISPATCHER(dev);

    memory_region_init_iommu(&s->iommu, sizeof(s->iommu),
                             TYPE_IOPMP_DISPATCHER_IOMMU_MEMORY_REGION,
                             obj, "riscv-iopmp-sysbus-iommu", UINT64_MAX);
    address_space_init(&s->dispatcher_as, MEMORY_REGION(&s->iommu), "iommu");

    s->target_as = g_new(AddressSpace *, s->target_num);
    s->target_sink = g_new(StreamSink *, s->target_num);
    s->target_map = g_new(MemMapEntry, s->target_num);

    object_initialize_child(OBJECT(s), "iopmp_dispatchert_transaction_info",
                            &s->transaction_info_sink,
                            TYPE_IOPMP_DISPATCHER_TRANSACTION_INFO_SINK);
}

static Property iopmp_dispatcher_properties[] = {
    DEFINE_PROP_UINT32("target-num", Iopmp_Dispatcher_State, target_num, 1),
    DEFINE_PROP_END_OF_LIST(),
};

static void iopmp_dispatcher_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    device_class_set_props(dc, iopmp_dispatcher_properties);
    dc->realize = iopmp_dispatcher_realize;
}

static int iopmp_dispatcher_attrs_to_index(IOMMUMemoryRegion *iommu,
                                           MemTxAttrs attrs)
{
    return attrs.requester_id;
}

static int iopmp_dispatcher_num_indexes(IOMMUMemoryRegion *iommu)
{
    return IOPMP_DISPATCHER_SID_NUM;
}

static void iopmp_dispatcher_iommu_memory_region_class_init(ObjectClass *klass,
                                                            void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);

    imrc->translate = iopmp_dispatcher_translate;
    imrc->attrs_to_index = iopmp_dispatcher_attrs_to_index;
    imrc->num_indexes = iopmp_dispatcher_num_indexes;
}

static const TypeInfo iopmp_dispatcher_info = {
    .name = TYPE_IOPMP_DISPATCHER,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Iopmp_Dispatcher_State),
    .class_init = iopmp_dispatcher_class_init,
};

static const TypeInfo
iopmp_dispatcher_iommu_memory_region_info = {
    .name = TYPE_IOPMP_DISPATCHER_IOMMU_MEMORY_REGION,
    .parent = TYPE_IOMMU_MEMORY_REGION,
    .class_init = iopmp_dispatcher_iommu_memory_region_class_init,
};

static size_t
transaction_info_push(StreamSink *transaction_info_sink, unsigned char *buf,
                      size_t len, bool eop)
{
    uint64_t addr;
    Iopmp_Dispatcher_StreamSink *ss =
        IOPMP_DISPATCHER_TRANSACTION_INFO_SINK(transaction_info_sink);
    Iopmp_Dispatcher_State *s = IOPMP_DISPATCHER(container_of(ss,
        Iopmp_Dispatcher_State, transaction_info_sink));
    iopmp_transaction_info signal;
    memcpy(&signal, buf, len);
    addr = signal.start_addr;
    for (int i = 0; i < s->target_num; i++) {
        if (s->target_map[i].base <= addr &&
            addr < s->target_map[i].base + s->target_map[i].size) {
                return stream_push(s->target_sink[i], buf, len, eop);
        }
    }
    /* Always pass if target is not protected by IOPMP*/
    return 1;
}

static void iopmp_dispatcher_transaction_info_sink_class_init(
    ObjectClass *klass, void *data)
{
    StreamSinkClass *ssc = STREAM_SINK_CLASS(klass);
    ssc->push = transaction_info_push;
}

static const TypeInfo dispatcher_transaction_info_sink = {
    .name = TYPE_IOPMP_DISPATCHER_TRANSACTION_INFO_SINK,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(Iopmp_Dispatcher_StreamSink),
    .class_init = iopmp_dispatcher_transaction_info_sink_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_STREAM_SINK },
        { }
    },
};

static void
iopmp_dispatcher_register_types(void)
{
    type_register_static(&iopmp_dispatcher_info);
    type_register_static(&iopmp_dispatcher_iommu_memory_region_info);
    type_register_static(&dispatcher_transaction_info_sink);
}

type_init(iopmp_dispatcher_register_types);

void iopmp_dispatcher_add_target(DeviceState *dev, AddressSpace *as,
    StreamSink *sink, uint64_t base, uint64_t size, int id)
{
    Iopmp_Dispatcher_State *s = IOPMP_DISPATCHER(dev);
    s->target_map[id].base = base;
    s->target_map[id].size = size;
    s->target_as[id] = as;
    s->target_sink[id] = sink;
}

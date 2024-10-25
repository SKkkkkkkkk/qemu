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

#define TYPE_IOPMP_DISPATCHER_TRANSACTION_INFO_SINK \
    "iopmp_dispatcher_transaction_info_sink"

DECLARE_INSTANCE_CHECKER(Iopmp_Dispatcher_StreamSink,
                         IOPMP_DISPATCHER_TRANSACTION_INFO_SINK,
                         TYPE_IOPMP_DISPATCHER_TRANSACTION_INFO_SINK)
static void iopmp_dispatcher_realize(DeviceState *dev, Error **errp)
{
    Iopmp_Dispatcher_State *s = IOPMP_DISPATCHER(dev);

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


static const TypeInfo iopmp_dispatcher_info = {
    .name = TYPE_IOPMP_DISPATCHER,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Iopmp_Dispatcher_State),
    .class_init = iopmp_dispatcher_class_init,
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
    type_register_static(&dispatcher_transaction_info_sink);
}

type_init(iopmp_dispatcher_register_types);

void iopmp_dispatcher_add_target(DeviceState *dev, StreamSink *sink,
    uint64_t base, uint64_t size, int id)
{
    Iopmp_Dispatcher_State *s = IOPMP_DISPATCHER(dev);
    s->target_map[id].base = base;
    s->target_map[id].size = size;
    s->target_sink[id] = sink;
}

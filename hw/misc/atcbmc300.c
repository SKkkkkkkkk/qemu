/*
 * Andes ATCBMC300 Bus Matrix Controller
 *
 * Copyright (c) 2025 Andes Tech. Corp.
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
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "hw/sysbus.h"
#include "target/riscv/cpu.h"
#include "hw/qdev-properties.h"
#include "hw/misc/atcbmc300.h"

#define LOGGE(x...) qemu_log_mask(LOG_GUEST_ERROR, x)

#define TYPE_ANDES_ATCBMC300 "riscv.andes.atcbmc300"

OBJECT_DECLARE_SIMPLE_TYPE(AndesATCBMC300State, ANDES_ATCBMC300)

typedef struct AndesATCBMC300State {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    MemoryRegion mmio;

    /* ID and revision register */
    uint32_t IdRev;
} AndesATCBMC300State;

enum {
    REG_IDREV = 0x00,
};

/* ATCBMC300 ID and Revision Register (Offset 0x0) */
#define ATCBMC300_IDREV         0x0
#define ATCBMC300_ID            0x000030
#define ATCBMC300_REV_MAJOR     0x0
#define ATCBMC300_REV_MINOR     0x1

static uint64_t
andes_atcbmc300_read(void *opaque, hwaddr addr, unsigned size)
{
    AndesATCBMC300State *bmc300 = opaque;
    uint64_t rz = 0;

    switch (addr) {
    case REG_IDREV:
        rz = bmc300->IdRev;
        break;
    default:
        LOGGE("%s: Bad addr %x\n", __func__, (int)addr);
    }

    return rz;
}

static void
andes_atcbmc300_write(void *opaque, hwaddr addr, uint64_t value, unsigned size)
{
    LOGGE("%s: Bad addr %x (value %x)\n", __func__, (int)addr, (int)value);
}

static const MemoryRegionOps andes_atcbmc300_ops = {
    .read = andes_atcbmc300_read,
    .write = andes_atcbmc300_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8
    }
};

static Property andes_atcbmc300_properties[] = {
    DEFINE_PROP_UINT32("id-and-revision", AndesATCBMC300State, IdRev,
                       (ATCBMC300_ID << 8) |
                       ((ATCBMC300_REV_MAJOR & 0xF) << 4) |
                       ((ATCBMC300_REV_MINOR & 0xF))),
    DEFINE_PROP_END_OF_LIST(),
};

static void andes_atcbmc300_realize(DeviceState *dev, Error **errp)
{
    AndesATCBMC300State *bmc300 = ANDES_ATCBMC300(dev);
    memory_region_init_io(&bmc300->mmio, OBJECT(dev), &andes_atcbmc300_ops,
                          bmc300, TYPE_ANDES_ATCBMC300, 0x100000);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &bmc300->mmio);
}

static void andes_atcbmc300_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = andes_atcbmc300_realize;
    device_class_set_props(dc, andes_atcbmc300_properties);
}

static const TypeInfo andes_atcbmc300_info = {
    .name = TYPE_ANDES_ATCBMC300,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AndesATCBMC300State),
    .class_init = andes_atcbmc300_class_init,
};

static void andes_atcbmc300_register_types(void)
{
    type_register_static(&andes_atcbmc300_info);
}

type_init(andes_atcbmc300_register_types)

/*
 * Create ATCBMC300 device.
 */
DeviceState*
andes_atcbmc300_create(hwaddr addr, hwaddr size)
{
    DeviceState *dev = qdev_new(TYPE_ANDES_ATCBMC300);

    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);

    return dev;
}

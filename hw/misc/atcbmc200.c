/*
 * Andes ATCBMC200 Bus Matrix Controller
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
#include "hw/misc/atcbmc200.h"

#define LOGGE(x...) qemu_log_mask(LOG_GUEST_ERROR, x)

#define TYPE_ANDES_ATCBMC200 "riscv.andes.atcbmc200"

OBJECT_DECLARE_SIMPLE_TYPE(AndesATCBMC200State, ANDES_ATCBMC200)

typedef struct AndesATCBMC200State {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    MemoryRegion mmio;

    /* ID and revision register */
    uint32_t IdRev;
} AndesATCBMC200State;

enum {
    REG_IDREV = 0x00,
};

/* ATCBMC200 ID and Revision Register (Offset 0x0) */
#define ATCBMC200_IDREV         0x0
#define ATCBMC200_ID            0x000020
#define ATCBMC200_REV_MAJOR     0x0
#define ATCBMC200_REV_MINOR     0x1

static uint64_t
andes_atcbmc200_read(void *opaque, hwaddr addr, unsigned size)
{
    AndesATCBMC200State *bmc200 = opaque;
    uint64_t rz = 0;

    switch (addr) {
    case REG_IDREV:
        rz = bmc200->IdRev;
        break;
    default:
        LOGGE("%s: Bad addr %x\n", __func__, (int)addr);
    }

    return rz;
}

static void
andes_atcbmc200_write(void *opaque, hwaddr addr, uint64_t value, unsigned size)
{
    LOGGE("%s: Bad addr %x (value %x)\n", __func__, (int)addr, (int)value);
}

static const MemoryRegionOps andes_atcbmc200_ops = {
    .read = andes_atcbmc200_read,
    .write = andes_atcbmc200_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8
    }
};

static Property andes_atcbmc200_properties[] = {
    DEFINE_PROP_UINT32("id-and-revision", AndesATCBMC200State, IdRev,
                       (ATCBMC200_ID << 8) |
                       ((ATCBMC200_REV_MAJOR & 0xF) << 4) |
                       ((ATCBMC200_REV_MINOR & 0xF))),
    DEFINE_PROP_END_OF_LIST(),
};

static void andes_atcbmc200_realize(DeviceState *dev, Error **errp)
{
    AndesATCBMC200State *bmc200 = ANDES_ATCBMC200(dev);
    memory_region_init_io(&bmc200->mmio, OBJECT(dev), &andes_atcbmc200_ops,
                          bmc200, TYPE_ANDES_ATCBMC200, 0x100000);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &bmc200->mmio);
}

static void andes_atcbmc200_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = andes_atcbmc200_realize;
    device_class_set_props(dc, andes_atcbmc200_properties);
}

static const TypeInfo andes_atcbmc200_info = {
    .name = TYPE_ANDES_ATCBMC200,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AndesATCBMC200State),
    .class_init = andes_atcbmc200_class_init,
};

static void andes_atcbmc200_register_types(void)
{
    type_register_static(&andes_atcbmc200_info);
}

type_init(andes_atcbmc200_register_types)

/*
 * Create ATCBMC200 device.
 */
DeviceState*
andes_atcbmc200_create(hwaddr addr, hwaddr size)
{
    DeviceState *dev = qdev_new(TYPE_ANDES_ATCBMC200);

    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);

    return dev;
}

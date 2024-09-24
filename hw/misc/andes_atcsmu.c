/*
 * Andes ATCSMU (System Management Unit)
 *
 * Copyright (c) 2021 Andes Tech. Corp.
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
#include "qemu/log.h"
#include "hw/sysbus.h"
#include "sysemu/runstate.h"
#include "hw/qdev-properties.h"
#include "hw/misc/andes_atcsmu.h"
#include "target/riscv/cpu.h"

/* #define DEBUG_ATCSMU */
/* #define MORE_HOOK */

#define xLOG(x...)
#define yLOG(x...) qemu_log(x)
#define zLOG(x...) printf(x)

#define LOG(x...) xLOG(x)
#define LOGGE(x...) qemu_log_mask(LOG_GUEST_ERROR, x)

#ifdef DEBUG_ATCPIT100
#undef LOG
#define LOG(x...) yLOG(x)
#endif

static uint32_t
reset_vector_read(int hartid, bool data_hi)
{
    CPUState *cpu = qemu_get_cpu(hartid);
    if (cpu) {
        CPURISCVState *env = cpu_env(cpu);
        if (data_hi) {
            return env->resetvec = (env->resetvec >> 32) ;
        } else {
            return env->resetvec & (UINT32_MAX);
        }
    }
    return 0;
}


static void
reset_vector_write(int hartid, uint64_t value, bool data_hi)
{
    CPUState *cpu = qemu_get_cpu(hartid);
    if (cpu) {
        CPURISCVState *env = cpu_env(cpu);
        if (data_hi) {
            env->resetvec = (env->resetvec << 32 >> 32) |
                            ((value & UINT32_MAX) << 32);
        } else {
            env->resetvec = (env->resetvec >> 32 << 32) | (value & UINT32_MAX);
        }
    }
}

static uint64_t atcsmu100_pcs_read(AndesATCSMUState *smu, hwaddr addr,
                                   unsigned size)
{
    unsigned int idx, offset;

    if (addr & 0x3) {
        LOGGE("%s: Bad addr %x\n", __func__, (int)addr);
        return 0;
    }

    idx = (addr - ATCSMU_PCS0_CFG) / ATCSMU_PCS_STRIDE;
    offset = addr - (ATCSMU_PCS0_CFG + ATCSMU_PCS_STRIDE * idx);
    if (idx >= ATCSMU_NUM_PCS) {
        LOGGE("%s: PCS%d is not supported\n", __func__, (int)idx);
        return 0;
    }

    switch (offset) {
    case ATCSMU_PCS_OFFSET_CFG:
        return smu->pcs_regs[idx].pcs_cfg;
    case ATCSMU_PCS_OFFSET_SCRATCH:
        return smu->pcs_regs[idx].pcs_scratch;
    case ATCSMU_PCS_OFFSET_MISC:
        return smu->pcs_regs[idx].pcs_misc;
    case ATCSMU_PCS_OFFSET_MISC2:
        return smu->pcs_regs[idx].pcs_misc2;
    case ATCSMU_PCS_OFFSET_WE:
        return smu->pcs_regs[idx].pcs_we;
    case ATCSMU_PCS_OFFSET_CTL:
        return smu->pcs_regs[idx].pcs_ctl;
    case ATCSMU_PCS_OFFSET_STATUS:
        return smu->pcs_regs[idx].pcs_status;
    default:
        LOGGE("%s: Bad addr %x\n", __func__, (int)addr);
        break;
    }

    return 0;
}

static void atcsmu100_pcs_write(AndesATCSMUState *smu, hwaddr addr,
                                uint64_t value, unsigned size)
{
    unsigned int idx, offset;

    if (addr & 0x3) {
        LOGGE("%s: Bad addr %x\n", __func__, (int)addr);
        return;
    }

    idx = (addr - ATCSMU_PCS0_CFG) / ATCSMU_PCS_STRIDE;
    offset = addr - (ATCSMU_PCS0_CFG + ATCSMU_PCS_STRIDE * idx);
    if (idx >= ATCSMU_NUM_PCS) {
        LOGGE("%s: PCS%d is not supported\n", __func__, (int)idx);
        return;
    }

    switch (offset) {
    case ATCSMU_PCS_OFFSET_CFG:
        /* PCSm_CFG is read-only */
        break;
    case ATCSMU_PCS_OFFSET_SCRATCH:
        smu->pcs_regs[idx].pcs_scratch = value;
        break;
    case ATCSMU_PCS_OFFSET_MISC:
        LOGGE("%s: Writing PCS%d_MISC is not supported\n", __func__, (int)idx);
        break;
    case ATCSMU_PCS_OFFSET_MISC2:
        LOGGE("%s: Writing PCS%d_MISC2 is not supported\n", __func__, (int)idx);
        break;
    case ATCSMU_PCS_OFFSET_WE:
        LOGGE("%s: Writing PCS%d_WE is not supported\n", __func__, (int)idx);
        break;
    case ATCSMU_PCS_OFFSET_CTL:
        if (idx == 0) {
            switch (value) {
            case PCS_CTL_CMD_RESET: /* PCS0_CTL resets all power domain */
                for (int i = 0; i < ATCSMU_NUM_PCS; i++) {
                    smu->pcs_regs[i].pcs_status = 0x11;
                }
                qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
                break;
            }
        } else {
            LOGGE("%s: Writing PCS%d_CTL is not supported\n",
                  __func__, (int)idx);
        }
        break;
    case ATCSMU_PCS_OFFSET_STATUS:
        smu->pcs_regs[idx].pcs_status = value;
        break;
    default:
        LOGGE("%s: Bad addr %x\n", __func__, (int)addr);
        break;
    }
}

static uint64_t
andes_atcsmu_read(void *opaque, hwaddr addr, unsigned size)
{
    AndesATCSMUState *smu = ANDES_ATCSMU(opaque);
    unsigned int idx;
    switch (addr) {
    case ATCSMU_SYSTEMVER:
        return smu->systemver;
        break;
    case ATCSMU_BOARDVER:
        return smu->boardver;
        break;
    case ATCSMU_SYSTEMCFG:
        return smu->systemcfg;
        break;
    case ATCSMU_SMUVER:
        return smu->smuver;
        break;
    case ATCSMU_WRSR:
        return smu->wrsr;
        break;
    case ATCSMU_SCRATCH:
        return smu->scratch;
        break;
    case ATCSMU_HART0_RESET_VECTOR_LO ... ATCSMU_HART3_RESET_VECTOR_HI:
        if (addr < ATCSMU_HART0_RESET_VECTOR_HI) {
            idx = (addr - ATCSMU_HART0_RESET_VECTOR_LO) >> 2;
            return reset_vector_read(idx, 0);
        } else {
            idx = (addr - ATCSMU_HART0_RESET_VECTOR_HI) >> 2;
            return reset_vector_read(idx, 1);
        }
        break;
    case ATCSMU_HART4_RESET_VECTOR_LO ... ATCSMU_HART7_RESET_VECTOR_HI:
        if (addr < ATCSMU_HART4_RESET_VECTOR_HI) {
            idx = ((addr - ATCSMU_HART4_RESET_VECTOR_LO) >> 2) + 4;
            return reset_vector_read(idx, 0);
        } else {
            idx = ((addr - ATCSMU_HART4_RESET_VECTOR_HI) >> 2) + 4;
            return reset_vector_read(idx, 1);
        }
        break;
    default:
        if (addr >= ATCSMU_PCS0_CFG &&
            addr < (ATCSMU_PCS0_CFG + ATCSMU_PCS_STRIDE * ATCSMU_NUM_PCS)) {
            return atcsmu100_pcs_read(smu, addr, size);
        } else {
            LOGGE("%s: Bad addr %x\n", __func__, (int)addr);
        }
    }
    return 0;
}

static void
andes_atcsmu_write(void *opaque, hwaddr addr, uint64_t value, unsigned size)
{
    AndesATCSMUState *smu = ANDES_ATCSMU(opaque);
    unsigned int idx;
    switch (addr) {
    case ATCSMU_WRSR:
        smu->wrsr &= ~value;
        break;
    case ATCSMU_SCRATCH:
        smu->scratch = value;
        break;
    case ATCSMU_HART0_RESET_VECTOR_LO ... ATCSMU_HART3_RESET_VECTOR_HI:
        if (addr < ATCSMU_HART0_RESET_VECTOR_HI) {
            idx = (addr - ATCSMU_HART0_RESET_VECTOR_LO) >> 2;
            reset_vector_write(idx, value, 0);
        } else {
            idx = (addr - ATCSMU_HART0_RESET_VECTOR_HI) >> 2;
            reset_vector_write(idx, value, 1);
        }
        break;
    case ATCSMU_HART4_RESET_VECTOR_LO ... ATCSMU_HART7_RESET_VECTOR_HI:
        if (addr < ATCSMU_HART4_RESET_VECTOR_HI) {
            idx = ((addr - ATCSMU_HART4_RESET_VECTOR_LO) >> 2) + 4;
            reset_vector_write(idx, value, 0);
        } else {
            idx = ((addr - ATCSMU_HART4_RESET_VECTOR_HI) >> 2) + 4;
            reset_vector_write(idx, value, 1);
        }
        break;
    case ATCSMU_SMUCR:
        switch (value) {
        case SMUCMD_RESET:
            smu->wrsr |= 0x10;
            qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
            break;
        case SMUCMD_POWEROFF:
            qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
            break;
        }
        break;
    default:
        if (addr >= ATCSMU_PCS0_CFG &&
            addr < (ATCSMU_PCS0_CFG + ATCSMU_PCS_STRIDE * ATCSMU_NUM_PCS)) {
            atcsmu100_pcs_write(smu, addr, value, size);
        } else {
            LOGGE("%s: Bad addr %x (value %x)\n",
                  __func__, (int)addr, (int)value);
        }
    }
}

static const MemoryRegionOps andes_atcsmu_ops = {
    .read = andes_atcsmu_read,
    .write = andes_atcsmu_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4
    }
};

static Property andes_atcsmu_properties[] = {
    DEFINE_PROP_UINT32("smu-base-addr", AndesATCSMUState, smu_base_addr, 0),
    DEFINE_PROP_UINT32("smu-base-size", AndesATCSMUState, smu_base_size, 0),
    DEFINE_PROP_UINT32("systemver", AndesATCSMUState, systemver,
                       (SYSTEMVER_ID << 8) |
                       ((SYSTEMVER_MAJOR & 0xF) << 4) |
                       ((SYSTEMVER_MINOR & 0xF))),
    DEFINE_PROP_UINT32("boardver", AndesATCSMUState, boardver,
                       (BOARDVER_ID << 8) |
                       ((BOARDVER_MAJOR & 0xF) << 4) |
                       ((BOARDVER_MINOR & 0xF))),
    DEFINE_PROP_UINT32("systemcfg", AndesATCSMUState, systemcfg, 0),
    DEFINE_PROP_UINT32("smuver", AndesATCSMUState, smuver, SMUVER_SAMPLE),
    DEFINE_PROP_END_OF_LIST(),
};

static void andes_atcsmu_realize(DeviceState *dev, Error **errp)
{
    AndesATCSMUState *smu = ANDES_ATCSMU(dev);
    memory_region_init_io(&smu->mmio, OBJECT(dev), &andes_atcsmu_ops, smu,
        TYPE_ANDES_ATCSMU, smu->smu_base_size);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &smu->mmio);
}

static void andes_atcsmu_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = andes_atcsmu_realize;
    device_class_set_props(dc, andes_atcsmu_properties);
}

static void andes_atcsmu_instance_init(Object *obj)
{
    AndesATCSMUState *smu = ANDES_ATCSMU(obj);

    for (int i = 0; i < ATCSMU_NUM_PCS; i++) {
        smu->pcs_regs[i].pcs_cfg = 0xd;     /* Reset, Light Sleep, Deep Sleep */
        smu->pcs_regs[i].pcs_scratch = 0;
        smu->pcs_regs[i].pcs_misc = 0xf0000fff;
        smu->pcs_regs[i].pcs_misc2 = 0x00003807;
        smu->pcs_regs[i].pcs_we = 0xffffffff;
        smu->pcs_regs[i].pcs_ctl = 0;
        smu->pcs_regs[i].pcs_status = 0x1;  /* pd_type = Reset */
    }
}

static const TypeInfo andes_atcsmu_info = {
    .name = TYPE_ANDES_ATCSMU,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AndesATCSMUState),
    .instance_init = andes_atcsmu_instance_init,
    .class_init = andes_atcsmu_class_init,
};

static void andes_atcsmu_register_types(void)
{
    type_register_static(&andes_atcsmu_info);
}

type_init(andes_atcsmu_register_types)

/*
 * Create ATCSMU device.
 */
void
andes_atcsmu_create(AndesATCSMUState *dev, hwaddr addr, hwaddr size,
                    int num_harts)
{
    qdev_prop_set_uint32(DEVICE(dev), "smu-base-addr", addr);
    qdev_prop_set_uint32(DEVICE(dev), "smu-base-size", size);
    qdev_prop_set_uint32(DEVICE(dev), "systemcfg", num_harts & 0xFF);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);
}

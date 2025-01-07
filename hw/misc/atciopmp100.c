#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "trace.h"
#include "exec/exec-all.h"
#include "exec/address-spaces.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "hw/misc/atciopmp100.h"
#include "memory.h"
#include "hw/irq.h"
#include "hw/registerfields.h"
#include "trace.h"

#define TYPE_ATCIOPMP100 "atciopmp100"
#define TYPE_IOPMP100_IOMMU_MEMORY_REGION "iopmp100-iommu-memory-region"
OBJECT_DECLARE_SIMPLE_TYPE(Atciopmp100state, ATCIOPMP100)

/* Max number of non-secure sources */
#define ATCIOPMP100_MAX_NS_SOURCE      32
/* Port0 is reserved */
#define ATCIOPMP100_RESERVED_PORT_NUM  1
#define ATCIOPMP100_MAX_PORT_NUM       (31 + ATCIOPMP100_RESERVED_PORT_NUM)
/* Secure RRID is fixed */
#define ATCIOPMP100_SECURE_RRID        0

typedef struct {
    uint32_t CTRL;
    uint32_t PRTLCK;
    uint32_t SRCSPERM;
    uint32_t SRCNSPERM[ATCIOPMP100_MAX_NS_SOURCE];
} iopmp100_regs;

typedef struct Atciopmp100state {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
    IOMMUMemoryRegion iommu;
    iopmp100_regs regs;
    MemoryRegion *downstream;
    AddressSpace downstream_as;
    MemMapEntry map[ATCIOPMP100_MAX_PORT_NUM];
    MemoryRegion blocked_rwx;
    AddressSpace blocked_rwx_as;
    uint32_t port_num;

    /*
     * The hardware defined parameters, which could be modified by device
     * property
     */
    /*
     * Data value to be returned for all read accesses that violate the
     * security check
     */
    uint32_t err_rdata;
} Atciopmp100state;

REG32(IDREV, 0x00)
    FIELD(IDREV, REVMINOR, 0, 4)
    FIELD(IDREV, REVMAJOR , 4, 4)
    FIELD(IDREV, ID, 8, 24)
REG32(CTRL, 0x10)
    FIELD(CTRL, L, 0, 1)
    FIELD(CTRL, ERR_RESP, 5, 1)
    FIELD(CTRL, ENABLE, 31, 1)
REG32(PRTLCK, 0x14)
    FIELD(PRTLCK, L, 0, 1)
    FIELD(PRTLCK, PRTL, 1, 31)
REG32(SRCSPERM, 0x1C)
    FIELD(SRCSPERM, L, 0, 1)
    FIELD(SRCSPERM, SRCSPERM, 1, 31)
REG32(SRCNSPERM0, 0x80)
    FIELD(SRCNSPERM0, L, 0, 1)
    FIELD(SRCNSPERM0, PRTPERMP, 1, 31)

#define ATCIOPMP100_MAX_PORT         32
#define ATCIOPMP100_REVMINOR         0
#define ATCIOPMP100_REVMAJOR         0
#define ATCIOPMP100_ID               0x003010

static void iopmp_iommu_notify(Atciopmp100state *s)
{
    IOMMUTLBEvent event = {
        .entry = {
            .iova = 0,
            .translated_addr = 0,
            .addr_mask = -1ULL,
            .perm = IOMMU_NONE,
        },
        .type = IOMMU_NOTIFIER_UNMAP,
    };

    for (int i = 0; i < ATCIOPMP100_MAX_NS_SOURCE + 1; i++) {
        memory_region_notify_iommu(&s->iommu, i, event);
    }
}

static MemTxResult atciopmp100_read(void *opaque, hwaddr addr, uint64_t *data,
                                    unsigned size, MemTxAttrs attrs)
{
    Atciopmp100state *s = ATCIOPMP100(opaque);
    uint32_t rz = 0;
    uint32_t offset, idx;

    /* Internal checker: secure requestor can access ATCIOPMP100 register */
    if (attrs.requester_id != ATCIOPMP100_SECURE_RRID) {
        if (FIELD_EX32(s->regs.CTRL , CTRL, ERR_RESP)) {
            *data = s->err_rdata;
            return MEMTX_OK;
        }
        return MEMTX_ERROR;
    }

    switch (addr) {
    case A_IDREV:
        rz = FIELD_DP32(rz, IDREV, REVMINOR, ATCIOPMP100_REVMINOR);
        rz = FIELD_DP32(rz, IDREV, REVMAJOR, ATCIOPMP100_REVMAJOR);
        rz = FIELD_DP32(rz, IDREV, ID, ATCIOPMP100_ID);
        break;
    case A_CTRL:
        rz = s->regs.CTRL;
        break;
    case A_PRTLCK:
        rz = s->regs.PRTLCK;
        break;
    case A_SRCSPERM:
        rz = s->regs.SRCSPERM;
        break;
    default:
        if (addr >= A_SRCNSPERM0 &&
            addr < A_SRCNSPERM0 + 4 * ATCIOPMP100_MAX_NS_SOURCE) {
            offset = addr - A_SRCNSPERM0;
            idx = offset >> 2;
            rz = s->regs.SRCNSPERM[idx];
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad addr %x\n",
                          __func__, (int)addr);
        }
        break;
    }
    trace_atciopmp100_read(addr, rz);
    *data = rz;
    return MEMTX_OK;
}

static MemTxResult atciopmp100_write(void *opaque, hwaddr addr, uint64_t value,
                                     unsigned size, MemTxAttrs attrs)
{
    Atciopmp100state *s = ATCIOPMP100(opaque);
    uint32_t offset, idx;
    uint32_t value32 = value;

    trace_atciopmp100_write(addr, value32);

    /* Internal checker: secure requestor can access ATCIOPMP100 register */
    if (attrs.requester_id != ATCIOPMP100_SECURE_RRID) {
        if (FIELD_EX32(s->regs.CTRL , CTRL, ERR_RESP)) {
            return MEMTX_OK;
        }
        return MEMTX_ERROR;
    }

    switch (addr) {
    case A_IDREV:
        break;
    case A_CTRL:
        if (!FIELD_EX32(s->regs.CTRL, CTRL, L)) {
            s->regs.CTRL = FIELD_DP32(s->regs.CTRL, CTRL, L,
                                      FIELD_EX32(value32, CTRL, L));
            s->regs.CTRL = FIELD_DP32(s->regs.CTRL, CTRL, ERR_RESP,
                                      FIELD_EX32(value32, CTRL, ERR_RESP));
            if (FIELD_EX32(value32, CTRL, ENABLE)) {
                /* W1SS */
                s->regs.CTRL = FIELD_DP32(s->regs.CTRL, CTRL, ENABLE, 1);
                iopmp_iommu_notify(s);
            }
        }
        break;
    case A_PRTLCK:
        if (!FIELD_EX32(s->regs.PRTLCK, PRTLCK, L)) {
            /* W1S */
            s->regs.PRTLCK |= value32;
        }
        break;
    case A_SRCSPERM:
        if (!FIELD_EX32(s->regs.SRCSPERM, SRCSPERM, L)) {
            s->regs.SRCSPERM = value32;
        }
        iopmp_iommu_notify(s);
        break;
    default:
        if (addr >= A_SRCNSPERM0 &&
            addr < A_SRCNSPERM0 + 4 * ATCIOPMP100_MAX_NS_SOURCE) {
            offset = addr - A_SRCNSPERM0;
            idx = offset >> 2;
            if (!FIELD_EX32(s->regs.SRCNSPERM[idx], SRCNSPERM0, L)) {
                s->regs.SRCNSPERM[idx] =
                    ((s->regs.SRCNSPERM[idx] & s->regs.PRTLCK) |
                     (value32 & ~s->regs.PRTLCK));
                s->regs.SRCNSPERM[idx] =
                    FIELD_DP32(s->regs.SRCNSPERM[idx], SRCNSPERM0, L,
                               FIELD_EX32(value32, SRCNSPERM0, L));
                iopmp_iommu_notify(s);
            }
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad addr %x\n",
                          __func__, (int)addr);
        }
        break;
    }
    return MEMTX_OK;
}

static IOMMUTLBEntry atciopmp100_translate(IOMMUMemoryRegion *iommu,
                                           hwaddr addr,
                                           IOMMUAccessFlags flags,
                                           int iommu_idx)
{
    int rrid = iommu_idx;
    Atciopmp100state *s = ATCIOPMP100(container_of(iommu, Atciopmp100state,
                                                   iommu));
    IOMMUTLBEntry entry = {
        .target_as = &s->downstream_as,
        .iova = addr,
        .translated_addr = addr,
        .addr_mask = 0,
        .perm = IOMMU_RW,
    };
    if (!FIELD_EX32(s->regs.CTRL, CTRL, ENABLE)) {
        entry.addr_mask = TARGET_PAGE_SIZE - 1;
        return entry;
    }
    for (int i = ATCIOPMP100_RESERVED_PORT_NUM; i < s->port_num; i++) {
        if (addr >= s->map[i].base &&
            addr < s->map[i].base + s->map[i].size) {
            entry.addr_mask = s->map[i].size - 1;
            if ((rrid == ATCIOPMP100_SECURE_RRID &&
                 !(s->regs.SRCSPERM & (1 << i))) ||
                (!(s->regs.SRCNSPERM[rrid - 1] & (1 << i)))) {
                entry.target_as = &s->blocked_rwx_as;
            }
            return entry;
        }
    }
    return entry;
}

static void alias_memory_subregions_range(MemoryRegion *src_mr,
                                          MemoryRegion *dst_mr,
                                          const MemMapEntry *memmap,
                                          uint32_t map_entry_num)
{
    int32_t priority;
    hwaddr addr;
    MemoryRegion *alias, *subregion;
    QTAILQ_FOREACH(subregion, &src_mr->subregions, subregions_link) {
        addr = subregion->addr;
        for (int i = ATCIOPMP100_RESERVED_PORT_NUM; i < map_entry_num; i++) {
            if (addr >= memmap[i].base &&
                addr < memmap[i].base + memmap[i].size) {
                priority = subregion->priority;
                alias = g_malloc0(sizeof(MemoryRegion));
                memory_region_init_alias(alias, NULL, subregion->name,
                                         subregion, 0,
                                         memory_region_size(subregion));
                memory_region_add_subregion_overlap(dst_mr, addr, alias,
                                                    priority);
                break;
            }
        }
    }
}

void iopmp100_setup_system_memory_range(DeviceState *dev,
                                        const MemMapEntry *memmap,
                                        uint32_t map_entry_num)
{
    Atciopmp100state *s = ATCIOPMP100(dev);
    uint32_t i;
    MemoryRegion *iommu_alias;
    MemoryRegion *target_mr = get_system_memory();
    MemoryRegion *downstream = g_malloc0(sizeof(MemoryRegion));
    memory_region_init(downstream, NULL, "iopmp_downstream",
                       memory_region_size(target_mr));

    map_entry_num = MIN(ATCIOPMP100_MAX_PORT_NUM, map_entry_num);
    s->port_num = map_entry_num;
    /* Create a downstream which does not have iommu of iopmp */
    alias_memory_subregions_range(target_mr, downstream, memmap, map_entry_num);

    for (i = ATCIOPMP100_RESERVED_PORT_NUM; i < map_entry_num; i++) {
        /* Memory access to protected regions of target are through IOPMP */
        s->map[i].base = memmap[i].base;
        s->map[i].size = memmap[i].size;
        iommu_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(iommu_alias, NULL, "iommu_alias",
                                 MEMORY_REGION(&s->iommu), memmap[i].base,
                                 memmap[i].size);
        /* Higher prior IOMMU memory region will take overlap protect region */
        memory_region_add_subregion_overlap(target_mr, memmap[i].base,
                                            iommu_alias, 1);
    }
    s->downstream = downstream;
    address_space_init(&s->downstream_as, s->downstream,
                       "iopmp-downstream-as");
}

static const MemoryRegionOps atciopmp100_ops = {
    .read_with_attrs = atciopmp100_read,
    .write_with_attrs = atciopmp100_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 4}
};

static MemTxResult atciopmp100_block_read(void *opaque, hwaddr addr,
                                          uint64_t *pdata, unsigned size,
                                          MemTxAttrs attrs)
{
    Atciopmp100state *s = ATCIOPMP100(opaque);
    if (FIELD_EX32(s->regs.CTRL , CTRL, ERR_RESP)) {
        *pdata = s->err_rdata;
        return MEMTX_OK;
    }
    return MEMTX_ERROR;
}

static MemTxResult atciopmp100_block_write(void *opaque, hwaddr addr,
                                           uint64_t value, unsigned size,
                                           MemTxAttrs attrs)
{
    Atciopmp100state *s = ATCIOPMP100(opaque);
    if (FIELD_EX32(s->regs.CTRL , CTRL, ERR_RESP)) {
        return MEMTX_OK;
    }
    return MEMTX_ERROR;
}

static MemTxResult atciopmp100_block_fetch(void *opaque, hwaddr addr,
                                           uint64_t *pdata, unsigned size,
                                           MemTxAttrs attrs)
{
    Atciopmp100state *s = ATCIOPMP100(opaque);
    if (FIELD_EX32(s->regs.CTRL , CTRL, ERR_RESP)) {
        *pdata = s->err_rdata;
        return MEMTX_OK;
    }
    return MEMTX_ERROR;
}

static const MemoryRegionOps atciopmp100_block_rwx_ops = {
    .fetch_with_attrs = atciopmp100_block_fetch,
    .read_with_attrs = atciopmp100_block_read,
    .write_with_attrs = atciopmp100_block_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {.min_access_size = 1, .max_access_size = 8},
};

static void atciopmp100_realize(DeviceState *dev, Error **errp)
{
    Object *obj = OBJECT(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    Atciopmp100state *s = ATCIOPMP100(dev);
    uint64_t size;
    size = -1ULL;

    memory_region_init_io(&s->blocked_rwx, NULL, &atciopmp100_block_rwx_ops,
                          s, "iopmp-blocked-rwx", size);
    address_space_init(&s->blocked_rwx_as, &s->blocked_rwx,
                       "iopmp-blocked-rwx-as");

    memory_region_init_iommu(&s->iommu, sizeof(s->iommu),
                             TYPE_IOPMP100_IOMMU_MEMORY_REGION,
                             obj, "riscv-iopmp-sysbus-iommu", UINT64_MAX);
    memory_region_init_io(&s->mmio, obj, &atciopmp100_ops,
                          s, "iopmp-regs", 0x4000);
    sysbus_init_mmio(sbd, &s->mmio);
}

static void atciopmp100_reset(DeviceState *dev)
{
    Atciopmp100state *s = ATCIOPMP100(dev);
    memset(&s->regs, 0, sizeof(iopmp100_regs));
}

static int atciopmp100_attrs_to_index(IOMMUMemoryRegion *iommu,
                                      MemTxAttrs attrs)
{
    return attrs.requester_id;
}

static void atciopmp100_iommu_mr_class_init(ObjectClass *klass, void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);

    imrc->translate = atciopmp100_translate;
    imrc->attrs_to_index = atciopmp100_attrs_to_index;
}

static Property atciopmp100_property[] = {
    DEFINE_PROP_UINT32("err_rdata", Atciopmp100state, err_rdata, 0x0),
    DEFINE_PROP_END_OF_LIST(),
};

static void atciopmp100_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    device_class_set_props(dc, atciopmp100_property);
    dc->realize = atciopmp100_realize;
    device_class_set_legacy_reset(dc, atciopmp100_reset);
}

static const TypeInfo atciopmp100_info = {
    .name = TYPE_ATCIOPMP100,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Atciopmp100state),
    .class_init = atciopmp100_class_init,
};

static const TypeInfo atciopmp100_iommu_memory_region_info = {
    .name = TYPE_IOPMP100_IOMMU_MEMORY_REGION,
    .parent = TYPE_IOMMU_MEMORY_REGION,
    .class_init = atciopmp100_iommu_mr_class_init,
};

static void atciopmp100_register_types(void)
{
    type_register_static(&atciopmp100_info);
    type_register_static(&atciopmp100_iommu_memory_region_info);
}

DeviceState *atciopmp100_create(hwaddr addr)
{
    DeviceState *dev;
    SysBusDevice *s;

    dev = qdev_new("atciopmp100");
    s = SYS_BUS_DEVICE(dev);
    sysbus_realize_and_unref(s, &error_fatal);
    sysbus_mmio_map(s, 0, addr);
    return dev;
}

type_init(atciopmp100_register_types);

/*
 * Andes Input Output Physical Memory Protection, ATCIOPMP300
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
#include "hw/misc/atciopmp300.h"
#include "memory.h"
#include "hw/irq.h"
#include "hw/registerfields.h"
#include "trace.h"

#define TYPE_IOPMP_IOMMU_MEMORY_REGION "iopmp-iommu-memory-region"
#define TYPE_IOPMP_TRANSACTION_INFO_SINK "iopmp_transaction_info_sink"

DECLARE_INSTANCE_CHECKER(Iopmp_StreamSink, IOPMP_TRANSACTION_INFO_SINK,
                         TYPE_IOPMP_TRANSACTION_INFO_SINK)

#define MEMTX_IOPMP_STALL (1 << 3)

REG32(VERSION, 0x00)
    FIELD(VERSION, VENDOR, 0, 24)
    FIELD(VERSION, SPECVER , 24, 8)
REG32(IMP, 0x04)
    FIELD(IMP, IMPID, 0, 32)
REG32(HWCFG0, 0x08)
    FIELD(HWCFG0, MD_NUM, 0, 7)
    FIELD(HWCFG0, SID_NUM, 7, 9)
    FIELD(HWCFG0, ENTRY_NUM, 16, 15)
    FIELD(HWCFG0, ENABLE, 31, 1)
REG32(HWCFG1, 0x0C)
    FIELD(HWCFG1, TOR_EN, 0, 1)
    FIELD(HWCFG1, SPS_EN, 1, 1)
    FIELD(HWCFG1, USER_CFG_EN, 2, 1)
    FIELD(HWCFG1, PROG_PRIENT, 3, 1)
    FIELD(HWCFG1, MODEL, 4, 4)
    FIELD(HWCFG1, PRIO_ENTRY, 16, 15)
REG32(ENTRYOFFSET, 0x10)
    FIELD(ENTRYOFFSET, OFFSET, 0, 32)
REG32(ERRREACT, 0x18)
    FIELD(ERRREACT, L, 0, 1)
    FIELD(ERRREACT, IE, 1, 1)
    FIELD(ERRREACT, IP, 2, 1)
    FIELD(ERRREACT, IRE, 4, 1)
    FIELD(ERRREACT, RRE, 5, 3)
    FIELD(ERRREACT, IWE, 8, 1)
    FIELD(ERRREACT, RWE, 9, 3)
    FIELD(ERRREACT, PEE, 28, 1)
    FIELD(ERRREACT, RPE, 29, 3)
REG32(MDSTALL, 0x20)
    FIELD(MDSTALL, EXEMPT, 0, 1)
    FIELD(MDSTALL, MD, 1, 31)
REG32(MDSTALLH, 0x24)
    FIELD(MDSTALLH, MD, 0, 32)
REG32(SIDSCP, 0x28)
    FIELD(SIDSCP, SID, 0, 16)
    FIELD(SIDSCP, OP, 30, 2)
REG32(MDLCK, 0x40)
    FIELD(MDLCK, L, 0, 1)
    FIELD(MDLCK, MD, 1, 31)
REG32(MDLCKH, 0x44)
    FIELD(MDLCKH, MDH, 0, 32)
REG32(MDCFGLCK, 0x48)
    FIELD(MDCFGLCK, L, 0, 1)
    FIELD(MDCFGLCK, F, 1, 7)
REG32(ENTRYLCK, 0x4C)
    FIELD(ENTRYLCK, L, 0, 1)
    FIELD(ENTRYLCK, F, 1, 16)
REG32(ERR_REQADDR, 0x60)
    FIELD(ERR_REQADDR, ADDR, 0, 32)
REG32(ERR_REQADDRH, 0x64)
    FIELD(ERR_REQADDRH, ADDRH, 0, 32)
REG32(ERR_REQSID, 0x68)
    FIELD(ERR_REQSID, SID, 0, 32)
REG32(ERR_REQINFO, 0x6C)
    FIELD(ERR_REQINFO, NO_HIT, 0, 1)
    FIELD(ERR_REQINFO, PAR_HIT, 1, 1)
    FIELD(ERR_REQINFO, TYPE, 8, 3)
    FIELD(ERR_REQINFO, EID, 16, 16)
REG32(MDCFG0, 0x800)
    FIELD(MDCFG0, T, 0, 16)
REG32(SRCMD_EN0, 0x1000)
    FIELD(SRCMD_EN0, L, 0, 1)
    FIELD(SRCMD_EN0, MD, 1, 31)
REG32(SRCMD_ENH0, 0x1004)
    FIELD(SRCMD_ENH0, MDH, 0, 32)
REG32(SRCMD_R0, 0x1008)
    FIELD(SRCMD_R0, MD, 1, 31)
REG32(SRCMD_RH0, 0x100C)
    FIELD(SRCMD_RH0, MDH, 0, 32)
REG32(SRCMD_W0, 0x1010)
    FIELD(SRCMD_W0, MD, 1, 31)
REG32(SRCMD_WH0, 0x1014)
    FIELD(SRCMD_WH0, MDH, 0, 32)
REG32(ENTRY_ADDR0, 0x2000)
    FIELD(ENTRY_ADDR0, ADDR, 0, 32)
REG32(ENTRY_ADDRH0, 0x2004)
    FIELD(ENTRY_ADDRH0, ADDRH, 0, 32)
REG32(ENTRY_CFG0, 0x2008)
    FIELD(ENTRY_CFG0, R, 0, 1)
    FIELD(ENTRY_CFG0, W, 1, 1)
    FIELD(ENTRY_CFG0, X, 2, 1)
    FIELD(ENTRY_CFG0, A, 3, 2)
REG32(ENTRY_USER_CFG0, 0x200C)
    FIELD(ENTRY_USER_CFG0, IM, 0, 32)

/* Offsets to SRCMD_EN(i) */
#define SRCMD_EN_OFFSET  0x0
#define SRCMD_ENH_OFFSET 0x4
#define SRCMD_R_OFFSET   0x8
#define SRCMD_RH_OFFSET  0xC
#define SRCMD_W_OFFSET   0x10
#define SRCMD_WH_OFFSET  0x14

/* Offsets to ENTRY_ADDR(i) */
#define ENTRY_ADDR_OFFSET     0x0
#define ENTRY_ADDRH_OFFSET    0x4
#define ENTRY_CFG_OFFSET      0x8
#define ENTRY_USER_CFG_OFFSET 0xC

static void iopmp_iommu_notify(Atciopmp300state *s)
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

    for (int i = 0; i < s->sid_num; i++) {
        memory_region_notify_iommu(&s->iommu, i, event);
    }
}

static inline int get_transaction_type(IOMMUAccessFlags flags)
{
    if (flags == IOMMU_RO) {
        return ERR_REQINFO_TYPE_READ;
    }
    if (flags == IOMMU_WO) {
        return ERR_REQINFO_TYPE_WRITE;
    }
    qemu_log_mask(LOG_GUEST_ERROR, "%s: Unsupported IOMMUAccessFlags %d\n",
                  __func__, (int)flags);
    g_assert_not_reached();
}

static void iopmp_decode_napot(uint64_t a, uint64_t *sa,
                               uint64_t *ea)
{
    /*
     * aaaa...aaa0   8-byte NAPOT range
     * aaaa...aa01   16-byte NAPOT range
     * aaaa...a011   32-byte NAPOT range
     * ...
     * aa01...1111   2^XLEN-byte NAPOT range
     * a011...1111   2^(XLEN+1)-byte NAPOT range
     * 0111...1111   2^(XLEN+2)-byte NAPOT range
     * 1111...1111   Reserved
     */

    a = (a << 2) | 0x3;
    *sa = a & (a + 1);
    *ea = a | (a + 1);
}

static void iopmp_update_rule(Atciopmp300state *s, uint32_t entry_index)
{
    uint8_t this_cfg = s->regs.entry[entry_index].cfg_reg;
    uint64_t this_addr = s->regs.entry[entry_index].addr_reg |
                         ((uint64_t)s->regs.entry[entry_index].addrh_reg << 32);
    uint64_t prev_addr = 0u;
    uint64_t sa = 0u;
    uint64_t ea = 0u;

    if (entry_index >= 1u) {
        prev_addr = s->regs.entry[entry_index - 1].addr_reg |
                    ((uint64_t)s->regs.entry[entry_index - 1].addrh_reg << 32);
    }

    switch (FIELD_EX32(this_cfg, ENTRY_CFG0, A)) {
    case IOPMP_AMATCH_OFF:
        sa = 0u;
        ea = -1;
        break;

    case IOPMP_AMATCH_TOR:
        sa = (prev_addr) << 2; /* shift up from [xx:0] to [xx+2:2] */
        ea = ((this_addr) << 2) - 1u;
        if (sa > ea) {
            sa = ea = 0u;
        }
        break;

    case IOPMP_AMATCH_NA4:
        sa = this_addr << 2; /* shift up from [xx:0] to [xx+2:2] */
        ea = (sa + 4u) - 1u;
        break;

    case IOPMP_AMATCH_NAPOT:
        iopmp_decode_napot(this_addr, &sa, &ea);
        break;

    default:
        sa = 0u;
        ea = 0u;
        break;
    }

    s->entry_addr[entry_index].sa = sa;
    s->entry_addr[entry_index].ea = ea;
    iopmp_iommu_notify(s);
}

static void update_md_stall_state(Atciopmp300state *s)
{
    uint64_t mdstall = s->regs.mdstall | (uint64_t)s->regs.mdstallh << 32;

    if (FIELD_EX32(s->regs.mdstall, MDSTALL, EXEMPT)) {
        s->md_stall_stat = mdstall ^ (~0ULL);
    } else {
        s->md_stall_stat = mdstall;
    }
    /* Remove exempt bit */
    s->md_stall_stat >>= 1;
}

static void update_sid_stall(Atciopmp300state *s)
{
    uint64_t srcmd_en;

    update_md_stall_state(s);
    s->is_stalled = 0;
    for (int i = 0; i < s->sid_num; i++) {
        s->sid_stall[i] = 0;
        srcmd_en = ((uint64_t)s->regs.srcmd_en[i] |
                    ((uint64_t)s->regs.srcmd_enh[i] << 32)) >> 1;
        for (int j = 0; j < s->md_num; j++) {
            if (((srcmd_en >> j) & 0x1) && ((s->md_stall_stat >> j) & 0x1)) {
                s->sid_stall[i] = 1;
                s->is_stalled = 1;
            }
        }
    }
}

static inline IOMMUAccessFlags entry_cfg_iommu_access_flags(uint32_t cfg)
{
    /* X bit is not used in IOMMUAccessFlags */
    return cfg & IOMMU_RW;
}

static MemTxResult atciopmp300_read(void *opaque, hwaddr addr, uint64_t *data,
                                    unsigned size, MemTxAttrs attrs)
{
    Atciopmp300state *s = ATCIOPMP300(opaque);
    uint32_t rz = 0;
    uint32_t offset, idx;
    MemTxResult tx_result = MEMTX_OK;
    switch (addr) {
    case A_VERSION:
        rz = VENDER_ANDES << R_VERSION_VENDOR_SHIFT |
             SPECVER_1_0_0_DRAFT3 << R_VERSION_SPECVER_SHIFT;
        break;
    case A_IMP:
        rz = IMPID_ATCIOPMP300;
        break;
    case A_HWCFG0:
        rz = s->md_num << R_HWCFG0_MD_NUM_SHIFT  |
             s->sid_num << R_HWCFG0_SID_NUM_SHIFT |
             s->entry_num << R_HWCFG0_ENTRY_NUM_SHIFT |
             s->enable << R_HWCFG0_ENABLE_SHIFT;
        break;
    case A_HWCFG1:
        rz = s->model << R_HWCFG1_MODEL_SHIFT |
             CFG_TOR_EN << R_HWCFG1_TOR_EN_SHIFT |
             s->sps_en << R_HWCFG1_SPS_EN_SHIFT |
             CFG_USER_CFG_EN << R_HWCFG1_USER_CFG_EN_SHIFT  |
             s->prog_prient << R_HWCFG1_PROG_PRIENT_SHIFT |
             s->prio_entry << R_HWCFG1_PRIO_ENTRY_SHIFT;
        break;
    case A_ENTRYOFFSET:
        rz = A_ENTRY_ADDR0;
        break;
    case A_ERRREACT:
        rz = s->regs.errreact;
        break;
    case A_MDSTALL:
        rz = FIELD_EX32(s->regs.mdstall, MDSTALL, MD);
        rz |= s->is_stalled;
        break;
    case A_MDSTALLH:
        rz = s->regs.mdstallh;
        break;
    case A_SIDSCP:
        rz = s->regs.sidscp;
        break;
    case A_MDLCK:
        rz = s->regs.mdlck;
        break;
    case A_MDLCKH:
        if (s->md_num < 31) {
            tx_result = MEMTX_ERROR;
        }
        rz = s->regs.mdlckh;
        break;
    case A_MDCFGLCK:
        rz = s->regs.mdcfglck;
        break;
    case A_ENTRYLCK:
        rz = s->regs.entrylck;
        break;
    case A_ERR_REQADDR:
        rz = s->regs.err_reqaddr & UINT32_MAX;
        break;
    case A_ERR_REQADDRH:
        rz = s->regs.err_reqaddr >> 32;
        break;
    case A_ERR_REQSID:
        rz = s->regs.err_reqsid;
        break;
    case A_ERR_REQINFO:
        rz = s->regs.err_reqinfo;
        break;

    default:
        if (addr >= A_MDCFG0 &&
            addr < A_MDCFG0 + 4 * (s->md_num - 1)) {
            offset = addr - A_MDCFG0;
            idx = offset >> 2;
            if (idx == 0 && offset == 0) {
                rz = s->regs.mdcfg[idx];
            } else {
                /* Only MDCFG0 is implemented in rapid-k model */
                tx_result = MEMTX_ERROR;
                qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad addr %x\n",
                              __func__, (int)addr);
            }
        } else if (addr >= A_SRCMD_EN0 &&
                   addr < A_SRCMD_WH0 + 32 * (s->sid_num - 1)) {
            offset = addr - A_SRCMD_EN0;
            idx = offset >> 5;
            offset &= 0x1f;

            switch (offset) {
            case SRCMD_EN_OFFSET:
                rz = s->regs.srcmd_en[idx];
                break;
            case SRCMD_ENH_OFFSET:
                if (s->md_num < 31) {
                    tx_result = MEMTX_ERROR;
                }
                rz = s->regs.srcmd_enh[idx];
                break;
            case SRCMD_R_OFFSET:
                if (!s->sps_en) {
                    tx_result = MEMTX_ERROR;
                }
                rz = s->regs.srcmd_r[idx];
                break;
            case SRCMD_RH_OFFSET:
                if (!s->sps_en || s->md_num < 31) {
                    tx_result = MEMTX_ERROR;
                }
                rz = s->regs.srcmd_rh[idx];
                break;
            case SRCMD_W_OFFSET:
                if (!s->sps_en) {
                    tx_result = MEMTX_ERROR;
                }
                rz = s->regs.srcmd_w[idx];
                break;
            case SRCMD_WH_OFFSET:
                if (!s->sps_en || s->md_num < 31) {
                    tx_result = MEMTX_ERROR;
                }
                rz = s->regs.srcmd_wh[idx];
                break;
            default:
                tx_result = MEMTX_ERROR;
                qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad addr %x\n",
                              __func__, (int)addr);
            }
        } else if (addr >= A_ENTRY_ADDR0 &&
                   addr < A_ENTRY_USER_CFG0 + 16 * (s->entry_num - 1)) {
            offset = addr - A_ENTRY_ADDR0;
            idx = offset >> 4;
            offset &= 0xf;

            switch (offset) {
            case ENTRY_ADDR_OFFSET:
                rz = s->regs.entry[idx].addr_reg;
                break;
            case ENTRY_ADDRH_OFFSET:
                rz = s->regs.entry[idx].addrh_reg;
                break;
            case ENTRY_CFG_OFFSET:
                rz = s->regs.entry[idx].cfg_reg;
                break;
            case ENTRY_USER_CFG_OFFSET:
                /* Does not support user customized permission */
                if (!CFG_USER_CFG_EN) {
                    tx_result = MEMTX_ERROR;
                }
                rz = 0;
                break;
            default:
                tx_result = MEMTX_ERROR;
                qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad addr %x\n",
                              __func__, (int)addr);
                break;
            }
        } else {
            tx_result = MEMTX_ERROR;
            qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad addr %x\n",
                          __func__, (int)addr);
        }
        break;
    }
    *data = rz;
    trace_atciopmp300_read(addr, rz);
    return tx_result;
}

static MemTxResult atciopmp300_write(void *opaque, hwaddr addr, uint64_t value,
                                     unsigned size, MemTxAttrs attrs)
{
    Atciopmp300state *s = ATCIOPMP300(opaque);
    uint32_t sid, op, offset, idx;
    uint32_t value32 = value;
    MemTxResult tx_result = MEMTX_OK;

    trace_atciopmp300_write(addr, value32);
    switch (addr) {
    case A_VERSION: /* RO */
        break;
    case A_IMP: /* RO */
        break;
    case A_HWCFG0:
        if (FIELD_EX32(value32, HWCFG0, ENABLE)) {
            /* W1S */
            iopmp_iommu_notify(s);
            s->enable = 1;
        }
        break;
    case A_HWCFG1:
        if (s->prog_prient) {
            s->prio_entry = FIELD_EX32(value32, HWCFG1, PRIO_ENTRY);
        }
        if (!FIELD_EX32(value32, HWCFG1, PROG_PRIENT)) {
            /* W0 */
            s->prog_prient = 0;
        }
        break;
    case A_ERRREACT:
        if (!FIELD_EX32(s->regs.errreact, ERRREACT, L)) {
            s->regs.errreact = FIELD_DP32(s->regs.errreact, ERRREACT, L,
                                          FIELD_EX32(value32, ERRREACT, L));
            s->regs.errreact = FIELD_DP32(s->regs.errreact, ERRREACT, IE,
                                          FIELD_EX32(value32, ERRREACT, IE));
            s->regs.errreact = FIELD_DP32(s->regs.errreact, ERRREACT, IRE,
                                          FIELD_EX32(value32, ERRREACT, IRE));
            s->regs.errreact = FIELD_DP32(s->regs.errreact, ERRREACT, RRE,
                                          FIELD_EX32(value32, ERRREACT, RRE));
            s->regs.errreact = FIELD_DP32(s->regs.errreact, ERRREACT, IWE,
                                          FIELD_EX32(value32, ERRREACT, IWE));
            s->regs.errreact = FIELD_DP32(s->regs.errreact, ERRREACT, RWE,
                                          FIELD_EX32(value32, ERRREACT, RWE));
            s->regs.errreact = FIELD_DP32(s->regs.errreact, ERRREACT, PEE,
                                          FIELD_EX32(value32, ERRREACT, PEE));
            s->regs.errreact = FIELD_DP32(s->regs.errreact, ERRREACT, RPE,
                                          FIELD_EX32(value32, ERRREACT, RPE));
        }
        if (FIELD_EX32(value32, ERRREACT, IP)) {
            s->regs.errreact = FIELD_DP32(s->regs.errreact, ERRREACT, IP, 0);
            qemu_set_irq(s->irq, 0);
        }
        break;
    case A_MDSTALL:
        s->regs.mdstall = value32;
        /* sid_stall should be captured only when MDSTALL is written */
        update_sid_stall(s);
        break;
    case A_MDSTALLH:
        s->regs.mdstallh = value32;
        break;
    case A_SIDSCP:
        sid = FIELD_EX32(value32, SIDSCP, SID);
        op = FIELD_EX32(value32, SIDSCP, OP);
        if (sid < s->sid_num) {
            switch (op) {
            case SIDSCP_OP_QUERY:
                s->regs.sidscp = sid |
                                 ((2 - s->sid_stall[sid]) << R_SIDSCP_OP_SHIFT);
                break;
            case SIDSCP_OP_STALL:
                s->sid_stall[sid] = true;
                break;
            case SIDSCP_OP_NOTSTALL:
                s->sid_stall[sid] = false;
                break;
            default:
                break;
            }
        } else {
            s->regs.sidscp = sid | (0x3 << R_SIDSCP_OP_SHIFT);
        }
        break;
    case A_MDLCK:
        if (!FIELD_EX32(s->regs.mdlck, MDLCK, L)) {
            s->regs.mdlck = value32;
        }
        break;
    case A_MDLCKH:
        if (s->md_num < 31) {
            tx_result = MEMTX_ERROR;
        } else if (!FIELD_EX32(s->regs.mdlck, MDLCK, L)) {
            s->regs.mdlckh = value32;
        }
        break;
    case A_MDCFGLCK:
        if (!FIELD_EX32(s->regs.mdcfglck, MDCFGLCK, L)) {
            s->regs.mdcfglck = FIELD_DP32(s->regs.mdcfglck, MDCFGLCK, F,
                                          FIELD_EX32(value32, MDCFGLCK, F));
            s->regs.mdcfglck = FIELD_DP32(s->regs.mdcfglck, MDCFGLCK, L,
                                          FIELD_EX32(value32, MDCFGLCK, L));
        }
        break;
    case A_ENTRYLCK:
        if (!(FIELD_EX32(s->regs.entrylck, ENTRYLCK, L))) {
            s->regs.entrylck = FIELD_DP32(s->regs.entrylck, ENTRYLCK, F,
                                          FIELD_EX32(value32, ENTRYLCK, F));
            s->regs.entrylck = FIELD_DP32(s->regs.entrylck, ENTRYLCK, L,
                                          FIELD_EX32(value32, ENTRYLCK, L));
        }
    case A_ERR_REQADDR: /* RO */
        break;
    case A_ERR_REQADDRH: /* RO */
        break;
    case A_ERR_REQSID: /* RO */
        break;
    case A_ERR_REQINFO: /* RO */
        break;

    default:
        if (addr >= A_MDCFG0 &&
            addr < A_MDCFG0 + 4 * (s->md_num - 1)) {
            offset = addr - A_MDCFG0;
            idx = offset >> 2;
            /* RO in rapid-k model */
            if (idx > 0) {
                qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad addr %x\n",
                              __func__, (int)addr);
            }
        } else if (addr >= A_SRCMD_EN0 &&
                   addr < A_SRCMD_WH0 + 32 * (s->sid_num - 1)) {
            offset = addr - A_SRCMD_EN0;
            idx = offset >> 5;
            offset &= 0x1f;

            if (offset % 4) {
                qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad addr %x\n",
                              __func__, (int)addr);
            } else if (FIELD_EX32(s->regs.srcmd_en[idx], SRCMD_EN0, L) == 0) {

                switch (offset) {
                case SRCMD_EN_OFFSET:
                    s->regs.srcmd_en[idx] =
                        FIELD_DP32(s->regs.srcmd_en[idx], SRCMD_EN0, L,
                                   FIELD_EX32(value32, SRCMD_EN0, L));

                    /* MD field is protected by mdlck */
                    value32 = (value32 & ~s->regs.mdlck) |
                              (s->regs.srcmd_en[idx] & s->regs.mdlck);
                    s->regs.srcmd_en[idx] =
                        FIELD_DP32(s->regs.srcmd_en[idx], SRCMD_EN0, MD,
                                   FIELD_EX32(value32, SRCMD_EN0, MD));
                    break;
                case SRCMD_ENH_OFFSET:
                    if (s->md_num < 31) {
                        tx_result = MEMTX_ERROR;
                    } else {
                        value32 = (value32 & ~s->regs.mdlckh) |
                                  (s->regs.srcmd_enh[idx] & s->regs.mdlckh);
                        s->regs.srcmd_enh[idx] =
                            FIELD_DP32(s->regs.srcmd_enh[idx], SRCMD_ENH0, MDH,
                                       value32);
                    }
                    break;
                case SRCMD_R_OFFSET:
                    if (s->sps_en) {
                        value32 = (value32 & ~s->regs.mdlck) |
                                  (s->regs.srcmd_r[idx] & s->regs.mdlck);
                        s->regs.srcmd_r[idx] =
                            FIELD_DP32(s->regs.srcmd_r[idx], SRCMD_R0, MD,
                                       FIELD_EX32(value32, SRCMD_R0, MD));
                    } else {
                        tx_result = MEMTX_ERROR;
                    }
                    break;
                case SRCMD_RH_OFFSET:
                    if (s->sps_en && s->md_num >= 31) {
                        value32 = (value32 & ~s->regs.mdlckh) |
                                  (s->regs.srcmd_rh[idx] & s->regs.mdlckh);
                        s->regs.srcmd_rh[idx] =
                            FIELD_DP32(s->regs.srcmd_rh[idx], SRCMD_RH0,
                                       MDH, value32);
                    } else {
                        tx_result = MEMTX_ERROR;
                    }
                    break;
                case SRCMD_W_OFFSET:
                    if (s->sps_en) {
                        value32 = (value32 & ~s->regs.mdlck) |
                                  (s->regs.srcmd_w[idx] & s->regs.mdlck);
                        s->regs.srcmd_w[idx] =
                            FIELD_DP32(s->regs.srcmd_w[idx], SRCMD_W0, MD,
                                       FIELD_EX32(value32, SRCMD_W0, MD));
                    } else {
                        tx_result = MEMTX_ERROR;
                    }
                    break;
                case SRCMD_WH_OFFSET:
                    if (s->sps_en && s->md_num >= 31) {
                        value32 = (value32 & ~s->regs.mdlckh) |
                                  (s->regs.srcmd_wh[idx] & s->regs.mdlckh);
                        s->regs.srcmd_wh[idx] =
                            FIELD_DP32(s->regs.srcmd_wh[idx], SRCMD_WH0,
                                       MDH, value32);
                    } else {
                        tx_result = MEMTX_ERROR;
                    }
                default:
                    break;
                }
            }
        } else if (addr >= A_ENTRY_ADDR0 &&
                   addr < A_ENTRY_USER_CFG0 + 16 * (s->entry_num - 1)) {
            offset = addr - A_ENTRY_ADDR0;
            idx = offset >> 4;
            offset &= 0xf;

            /* index < ENTRYLCK_F is protected */
            if (idx >= FIELD_EX32(s->regs.entrylck, ENTRYLCK, F)) {
                switch (offset) {
                case ENTRY_ADDR_OFFSET:
                    s->regs.entry[idx].addr_reg = value32;
                    break;
                case ENTRY_ADDRH_OFFSET:
                    s->regs.entry[idx].addrh_reg = value32;
                    break;
                case ENTRY_CFG_OFFSET:
                    s->regs.entry[idx].cfg_reg = value32;
                    break;
                case ENTRY_USER_CFG_OFFSET:
                    /* Does not support user customized permission */
                    if (!CFG_USER_CFG_EN) {
                        tx_result = MEMTX_ERROR;
                    }
                    break;
                default:
                    tx_result = MEMTX_ERROR;
                    qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad addr %x\n",
                                  __func__, (int)addr);
                    break;
                }
                iopmp_update_rule(s, idx);
                if (idx + 1 < s->entry_num &&
                    FIELD_EX32(s->regs.entry[idx + 1].cfg_reg, ENTRY_CFG0, A) ==
                    IOPMP_AMATCH_TOR) {
                    iopmp_update_rule(s, idx + 1);
                }
            }
        } else {
            tx_result = MEMTX_ERROR;
            qemu_log_mask(LOG_GUEST_ERROR, "%s: Bad addr %x\n", __func__,
                          (int)addr);
        }
    }
    return tx_result;
}

/* Match entry in memory domain */
static int match_entry_md(Atciopmp300state *s, int md_idx, hwaddr start_addr,
                          hwaddr end_addr, int *entry_idx,
                          int *prior_entry_in_tlb)
{
    int entry_idx_s, entry_idx_e;
    int result = ENTRY_NO_HIT;
    int i = 0;
    hwaddr tlb_sa = start_addr & ~(TARGET_PAGE_SIZE - 1);
    hwaddr tlb_ea = tlb_sa + TARGET_PAGE_SIZE - 1;
    entry_idx_s = md_idx * s->regs.mdcfg[0];
    entry_idx_e = (md_idx + 1) * s->regs.mdcfg[0];

    if (entry_idx_s >= s->entry_num) {
        return result;
    }
    if (entry_idx_e > s->entry_num) {
        entry_idx_e = s->entry_num;
    }
    i = entry_idx_s;
    for (i = entry_idx_s; i < entry_idx_e; i++) {
        if (FIELD_EX32(s->regs.entry[i].cfg_reg, ENTRY_CFG0, A) ==
            IOPMP_AMATCH_OFF) {
            continue;
        }
        if (start_addr >= s->entry_addr[i].sa &&
            start_addr <= s->entry_addr[i].ea) {
            /* Check end address */
            if (end_addr >= s->entry_addr[i].sa &&
                end_addr <= s->entry_addr[i].ea) {
                *entry_idx = i;
                return ENTRY_HIT;
            } else if (i >= s->prio_entry) {
                /* Continue for non-prio_entry */
                continue;
            } else {
                *entry_idx = i;
                return ENTRY_PAR_HIT;
            }
        } else if (end_addr >= s->entry_addr[i].sa &&
                   end_addr <= s->entry_addr[i].ea) {
            /* Only end address matches the entry */
            if (i >= s->prio_entry) {
                continue;
            } else {
                *entry_idx = i;
                return ENTRY_PAR_HIT;
            }
        } else if (start_addr < s->entry_addr[i].sa &&
                   end_addr > s->entry_addr[i].ea) {
            if (i >= s->prio_entry) {
                continue;
            } else {
                *entry_idx = i;
                return ENTRY_PAR_HIT;
            }
        }
        if (prior_entry_in_tlb != NULL) {
            if ((s->entry_addr[i].sa >= tlb_sa &&
                 s->entry_addr[i].sa <= tlb_ea) ||
                (s->entry_addr[i].ea >= tlb_sa &&
                 s->entry_addr[i].ea <= tlb_ea)) {
                /*
                 * TLB should not use the cached result when the tlb contains
                 * higher priority entry
                 */
                *prior_entry_in_tlb = 1;
            }
        }
    }
    return result;
}

static int match_entry(Atciopmp300state *s, int sid, hwaddr start_addr,
                       hwaddr end_addr, int *match_md_idx, int *match_entry_idx,
                       int *prior_entry_in_tlb)
{
    int cur_result = ENTRY_NO_HIT;
    int result = ENTRY_NO_HIT;
    /* Remove lock bit */
    uint64_t srcmd_en = ((uint64_t)s->regs.srcmd_en[sid] |
                         ((uint64_t)s->regs.srcmd_enh[sid] << 32)) >> 1;

    for (int md_idx = 0; md_idx < s->md_num; md_idx++) {
        if (srcmd_en & (1ULL << md_idx)) {
            cur_result = match_entry_md(s, md_idx, start_addr, end_addr,
                                        match_entry_idx, prior_entry_in_tlb);
            if (cur_result == ENTRY_HIT || cur_result == ENTRY_PAR_HIT) {
                *match_md_idx = md_idx;
                return cur_result;
            }
        }
    }
    return result;
}

static void iopmp_error_reaction(Atciopmp300state *s, uint32_t id, hwaddr start,
                                 hwaddr end, uint32_t info)
{
    if (s->transaction_state[id].supported) {
        if (s->transaction_state[id].error_pending) {
            /* Skip if this transaction is already reacted*/
            return ;
        }
        s->transaction_state[id].error_pending = 1;
    }
    if (!FIELD_EX32(s->regs.errreact, ERRREACT, IP)) {
        s->regs.errreact = FIELD_DP32(s->regs.errreact, ERRREACT, IP, 1);
        s->regs.err_reqsid = id;
        /* addr[LEN+2:2] */
        s->regs.err_reqaddr = start >> 2;
        s->regs.err_reqinfo = info;

        if (FIELD_EX32(info, ERR_REQINFO, TYPE) == ERR_REQINFO_TYPE_READ
            && FIELD_EX32(s->regs.errreact, ERRREACT, IE) &&
            FIELD_EX32(s->regs.errreact, ERRREACT, IRE)) {
            qemu_set_irq(s->irq, 1);
        }
        if (FIELD_EX32(info, ERR_REQINFO, TYPE) == ERR_REQINFO_TYPE_WRITE &&
            FIELD_EX32(s->regs.errreact, ERRREACT, IE) &&
            FIELD_EX32(s->regs.errreact, ERRREACT, IWE)) {
            qemu_set_irq(s->irq, 1);
        }
    }
}

static IOMMUTLBEntry iopmp_translate(IOMMUMemoryRegion *iommu, hwaddr addr,
                                     IOMMUAccessFlags flags, int iommu_idx)
{
    int pci_id = 0;
    int sid = iommu_idx;
    Atciopmp300state *s;
    MemoryRegion *mr = MEMORY_REGION(iommu);
    hwaddr start_addr, end_addr;
    int entry_idx = -1;
    int md_idx = -1;
    int result, srcmd_rw;
    int prior_entry_in_tlb = 0;
    iopmp_permission iopmp_perm;

    IOMMUTLBEntry entry = {
        .target_as = NULL,
        .iova = addr,
        .translated_addr = addr,
        .addr_mask = 0,
        .perm = IOMMU_NONE,
    };

    /* Find IOPMP of iommu */
    if (strncmp(mr->name, "atciopmp300-sysbus-iommu", 24) != 0) {
        sscanf(mr->name, "atciopmp300-pci-iommu%d", &pci_id);
        iopmp_pci_addressspcace *pci_s = container_of(iommu,
                                                      iopmp_pci_addressspcace,
                                                      iommu);
        s = ATCIOPMP300(pci_s->iopmp);
        /* If device does not specify sid, use id from pci */
        if (sid == 0) {
            sid = pci_id;
        }
    } else {
        s = ATCIOPMP300(container_of(iommu, Atciopmp300state, iommu));
    }
    entry.target_as = &s->downstream_as;

    if (s->transaction_state[sid].supported) {
        /* get transaction_state if device supported */
        start_addr = s->transaction_state[sid].start_addr;
        end_addr = s->transaction_state[sid].end_addr;
        if (addr > end_addr || addr < start_addr ||
            !s->transaction_state[sid].running) {
            qemu_log_mask(LOG_GUEST_ERROR, "transaction_state error.");
        }
    } else {
        start_addr = addr;
        end_addr = addr;
    }

    if (!s->enable) {
        /* Bypass IOPMP */
        /*
         * prevnet plen_out = 0;
         * plen_out = MIN(*plen_out, (addr | iotlb.addr_mask) - addr + 1);
         */
        entry.addr_mask = TARGET_PAGE_SIZE - 1,
        entry.perm = IOMMU_RW;
        return entry;
    }

    if (s->sid_stall[sid]) {
        entry.target_as = &s->stall_io_as;
        entry.perm = IOMMU_RW;
        return entry;
    }

    result = match_entry(s, sid, start_addr, end_addr, &md_idx, &entry_idx,
                         &prior_entry_in_tlb);
    if (result == ENTRY_HIT) {
        entry.addr_mask = s->entry_addr[entry_idx].ea -
                          s->entry_addr[entry_idx].sa;
        if (prior_entry_in_tlb) {
            /*
             * Reduce the entry size to make TLB repeat iommu translate on
             * every access.
             */
            entry.addr_mask = 0;
        }
        iopmp_perm = s->regs.entry[entry_idx].cfg_reg & IOPMP_RWX;

        if (s->sps_en) {
            /* SPS extension does not affect x permission */
            if (md_idx < 31) {
                srcmd_rw = IOPMP_XO | ((s->regs.srcmd_r[sid] >>
                                        (md_idx + R_SRCMD_R0_MD_SHIFT)) & 0x1);
                srcmd_rw |= ((s->regs.srcmd_w[sid] >>
                             (md_idx + R_SRCMD_W0_MD_SHIFT)) & 0x1) << 1;
            } else {
                srcmd_rw = IOPMP_XO | ((s->regs.srcmd_rh[sid] >>
                                        (md_idx + R_SRCMD_R0_MD_SHIFT - 32))
                                       & 0x1);
                srcmd_rw |= ((s->regs.srcmd_wh[sid] >>
                             (md_idx + R_SRCMD_W0_MD_SHIFT - 32)) & 0x1) << 1;
            }
            iopmp_perm &= srcmd_rw;
        }
        if (flags) {
            if ((entry_cfg_iommu_access_flags(iopmp_perm) & flags) == 0) {
                entry.target_as = &s->blocked_rw_as;
                entry.perm = IOMMU_RW;
            } else {
                entry.perm = entry_cfg_iommu_access_flags(iopmp_perm);
            }
        } else {
            /* CPU access with IOMMU_NONE flag */
            if (iopmp_perm & IOPMP_XO) {
                if ((iopmp_perm & IOPMP_RW) == IOPMP_RW) {
                    entry.target_as = &s->downstream_as;
                } else if ((iopmp_perm & IOPMP_RW) == IOPMP_RO) {
                    entry.target_as = &s->blocked_w_as;
                } else if ((iopmp_perm & IOPMP_RW) == IOPMP_WO) {
                    entry.target_as = &s->blocked_r_as;
                } else {
                    entry.target_as = &s->blocked_rw_as;
                }
            } else {
                if ((iopmp_perm & IOPMP_RW) == IOPMP_RW) {
                    entry.target_as = &s->blocked_x_as;
                } else if ((iopmp_perm & IOPMP_RW) == IOPMP_RO) {
                    entry.target_as = &s->blocked_wx_as;
                } else if ((iopmp_perm & IOPMP_RW) == IOPMP_WO) {
                    entry.target_as = &s->blocked_rx_as;
                } else {
                    entry.target_as = &s->blocked_rwx_as;
                }
            }
            entry.perm = IOMMU_RW;
        }
    } else {
         /* CPU access with IOMMU_NONE flag no_hit or par_hit*/
        entry.target_as = &s->blocked_rwx_as;
        entry.perm = IOMMU_RW;
    }
    return entry;
}

static const MemoryRegionOps iopmp_ops = {
    .read_with_attrs = atciopmp300_read,
    .write_with_attrs = atciopmp300_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {.min_access_size = 4, .max_access_size = 4}
};

static MemTxResult iopmp_permssion_write(void *opaque, hwaddr addr,
                                         uint64_t value, unsigned size,
                                         MemTxAttrs attrs)
{
    Atciopmp300state *s = ATCIOPMP300(opaque);
    return address_space_write(&s->downstream_as, addr, attrs, &value, size);
}

static MemTxResult iopmp_permssion_read(void *opaque, hwaddr addr,
                                        uint64_t *pdata, unsigned size,
                                        MemTxAttrs attrs)
{
    Atciopmp300state *s = ATCIOPMP300(opaque);
    return address_space_read(&s->downstream_as, addr, attrs, pdata, size);
}

static MemTxResult iopmp_block_write(void *opaque, hwaddr addr, uint64_t value,
                                     unsigned size, MemTxAttrs attrs)
{
    Atciopmp300state *s = ATCIOPMP300(opaque);
    int md_idx, entry_idx;
    uint32_t error_info = 0;
    int sid = attrs.requester_id;
    int result;
    hwaddr start_addr, end_addr;
    /* Handle error reaction for CPU transaction */
    if (!FIELD_EX32(s->regs.errreact, ERRREACT, IP)) {
        if (s->transaction_state[sid].supported) {
            /* get transaction_state if device supported */
            start_addr = s->transaction_state[sid].start_addr;
            end_addr = s->transaction_state[sid].end_addr;
            if (addr > end_addr || addr < start_addr ||
                !s->transaction_state[sid].running) {
                qemu_log_mask(LOG_GUEST_ERROR, "transaction_state error.");
            }
        } else {
            start_addr = addr;
            end_addr = addr;
        }

        result = match_entry(s, sid, start_addr, end_addr, &md_idx, &entry_idx,
                             NULL);
        if (result == ENTRY_PAR_HIT) {
            error_info = FIELD_DP32(error_info, ERR_REQINFO, PAR_HIT, 1);
        } else if (result == ENTRY_NO_HIT) {
            error_info = FIELD_DP32(error_info, ERR_REQINFO, NO_HIT, 1);
            entry_idx = 0;
        }
        error_info = FIELD_DP32(error_info, ERR_REQINFO, EID, entry_idx);
        error_info = FIELD_DP32(error_info, ERR_REQINFO, TYPE,
                                ERR_REQINFO_TYPE_WRITE);
        iopmp_error_reaction(s, attrs.requester_id, start_addr, end_addr,
                             error_info);
    }

    switch (FIELD_EX32(s->regs.errreact, ERRREACT, RWE)) {
    case RWE_BUS_ERROR:
        return MEMTX_ERROR;
        break;
    case RWE_DECODE_ERROR:
        return MEMTX_DECODE_ERROR;
        break;
    case RWE_SUCCESS:
        return MEMTX_OK;
        break;
    default:
        break;
    }
    return MEMTX_OK;
}

static MemTxResult iopmp_block_read(void *opaque, hwaddr addr, uint64_t *pdata,
                                    unsigned size, MemTxAttrs attrs)
{
    Atciopmp300state *s = ATCIOPMP300(opaque);
    int md_idx, entry_idx;
    uint32_t error_info = 0;
    int sid = attrs.requester_id;
    int result;
    hwaddr start_addr, end_addr;

    /* Handle error reaction for CPU transaction */
    if (!FIELD_EX32(s->regs.errreact, ERRREACT, IP)) {
        if (s->transaction_state[sid].supported) {
            /* get transaction_state if device supported */
            start_addr = s->transaction_state[sid].start_addr;
            end_addr = s->transaction_state[sid].end_addr;
            if (addr > end_addr || addr < start_addr ||
                !s->transaction_state[sid].running) {
                qemu_log_mask(LOG_GUEST_ERROR, "transaction_state error.");
            }
        } else {
            start_addr = addr;
            end_addr = addr;
        }

        result = match_entry(s, sid, start_addr, end_addr, &md_idx, &entry_idx,
                             NULL);
        error_info = FIELD_DP32(error_info, ERR_REQINFO, EID, entry_idx);
        error_info = FIELD_DP32(error_info, ERR_REQINFO, TYPE,
                                ERR_REQINFO_TYPE_READ);
        if (result == ENTRY_PAR_HIT) {
            error_info = FIELD_DP32(error_info, ERR_REQINFO, PAR_HIT, 1);
        } else if (result == ENTRY_NO_HIT) {
            error_info = FIELD_DP32(error_info, ERR_REQINFO, NO_HIT, 1);
        }
        iopmp_error_reaction(s, attrs.requester_id, start_addr, end_addr,
                             error_info);
    }

    switch (FIELD_EX32(s->regs.errreact, ERRREACT, RRE)) {
    case RRE_BUS_ERROR:
        return MEMTX_ERROR;
        break;
    case RRE_DECODE_ERROR:
        return MEMTX_DECODE_ERROR;
        break;
    case RRE_SUCCESS_ZEROS:
        *pdata = 0;
        return MEMTX_OK;
        break;
    case RRE_SUCCESS_ONES:
        *pdata = UINT64_MAX;
        return MEMTX_OK;
        break;
    default:
        break;
    }
    return MEMTX_OK;
}

static MemTxResult iopmp_block_fetch(void *opaque, hwaddr addr, uint64_t *pdata,
                                     unsigned size, MemTxAttrs attrs)
{
    Atciopmp300state *s = ATCIOPMP300(opaque);
    int md_idx, entry_idx;
    uint32_t error_info = 0;
    int sid = attrs.requester_id;
    int result;
    hwaddr start_addr, end_addr;

    /* Handle error reaction for CPU transaction */
    if (!FIELD_EX32(s->regs.errreact, ERRREACT, IP)) {
        if (s->transaction_state[sid].supported) {
            /* get transaction_state if device supported */
            start_addr = s->transaction_state[sid].start_addr;
            end_addr = s->transaction_state[sid].end_addr;
            if (addr > end_addr || addr < start_addr ||
                !s->transaction_state[sid].running) {
                qemu_log_mask(LOG_GUEST_ERROR, "transaction_state error.");
            }
        } else {
            start_addr = addr;
            end_addr = addr;
        }
        result = match_entry(s, sid, addr, addr, &md_idx, &entry_idx, NULL);
        error_info = FIELD_DP32(error_info, ERR_REQINFO, EID, entry_idx);
        error_info = FIELD_DP32(error_info, ERR_REQINFO, TYPE,
                                ERR_REQINFO_TYPE_READ);
        if (result == ENTRY_PAR_HIT) {
            error_info = FIELD_DP32(error_info, ERR_REQINFO, PAR_HIT, 1);
        } else if (result == ENTRY_NO_HIT) {
            error_info = FIELD_DP32(error_info, ERR_REQINFO, NO_HIT, 1);
        }
        iopmp_error_reaction(s, attrs.requester_id, start_addr, end_addr,
                             error_info);
    }

    /*
     * Use the same reaction as read
     * (exec reaction is not specified in draft3)
     */
    switch (FIELD_EX32(s->regs.errreact, ERRREACT, RRE)) {
    case RRE_BUS_ERROR:
        return MEMTX_ERROR;
        break;
    case RRE_DECODE_ERROR:
        return MEMTX_DECODE_ERROR;
        break;
    case RRE_SUCCESS_ZEROS:
        *pdata = 0;
        return MEMTX_OK;
        break;
    case RRE_SUCCESS_ONES:
        *pdata = UINT64_MAX;
        return MEMTX_OK;
        break;
    default:
        break;
    }
    return MEMTX_OK;
}

static const MemoryRegionOps iopmp_block_rw_ops = {
    .fetch_with_attrs = iopmp_permssion_read,
    .read_with_attrs = iopmp_block_read,
    .write_with_attrs = iopmp_block_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {.min_access_size = 1, .max_access_size = 8},
};

static const MemoryRegionOps iopmp_block_w_ops = {
    .fetch_with_attrs = iopmp_permssion_read,
    .read_with_attrs = iopmp_permssion_read,
    .write_with_attrs = iopmp_block_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {.min_access_size = 1, .max_access_size = 8},
};

static const MemoryRegionOps iopmp_block_r_ops = {
    .fetch_with_attrs = iopmp_permssion_read,
    .read_with_attrs = iopmp_block_read,
    .write_with_attrs = iopmp_permssion_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {.min_access_size = 1, .max_access_size = 8},
};

static const MemoryRegionOps iopmp_block_rwx_ops = {
    .fetch_with_attrs = iopmp_block_fetch,
    .read_with_attrs = iopmp_block_read,
    .write_with_attrs = iopmp_block_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {.min_access_size = 1, .max_access_size = 8},
};

static const MemoryRegionOps iopmp_block_wx_ops = {
    .fetch_with_attrs = iopmp_block_fetch,
    .read_with_attrs = iopmp_permssion_read,
    .write_with_attrs = iopmp_block_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {.min_access_size = 1, .max_access_size = 8},
};

static const MemoryRegionOps iopmp_block_rx_ops = {
    .fetch_with_attrs = iopmp_block_fetch,
    .read_with_attrs = iopmp_block_read,
    .write_with_attrs = iopmp_permssion_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {.min_access_size = 1, .max_access_size = 8},
};

static const MemoryRegionOps iopmp_block_x_ops = {
    .fetch_with_attrs = iopmp_block_fetch,
    .read_with_attrs = iopmp_permssion_read,
    .write_with_attrs = iopmp_permssion_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {.min_access_size = 1, .max_access_size = 8},
};

static MemTxResult iopmp_handle_stall(Atciopmp300state *s, hwaddr addr,
                                      MemTxAttrs attrs)
{
    return MEMTX_IOPMP_STALL;
}

static MemTxResult iopmp_stall_write(void *opaque, hwaddr addr, uint64_t value,
                                     unsigned size, MemTxAttrs attrs)
{
    Atciopmp300state *s = ATCIOPMP300(opaque);

    return iopmp_handle_stall(s, addr, attrs);
}

static MemTxResult iopmp_stall_read(void *opaque, hwaddr addr, uint64_t *pdata,
                                    unsigned size, MemTxAttrs attrs)
{
    Atciopmp300state *s = ATCIOPMP300(opaque);

    *pdata = 0;
    return iopmp_handle_stall(s, addr, attrs);
}

static const MemoryRegionOps iopmp_stall_io_ops = {
    .read_with_attrs = iopmp_stall_read,
    .write_with_attrs = iopmp_stall_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {.min_access_size = 1, .max_access_size = 8},
};

static void iopmp_realize(DeviceState *dev, Error **errp)
{
    Object *obj = OBJECT(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    Atciopmp300state *s = ATCIOPMP300(dev);
    uint64_t size;

    s->downstream = get_system_memory();
    size = memory_region_size(s->downstream);
    qemu_mutex_init(&s->iopmp_transaction_mutex);
    s->prog_prient = CFG_PROG_PRIENT;
    s->sid_num = MIN(s->sid_num, IOPMP_MAX_SID_NUM);
    s->md_num = MIN(s->md_num, IOPMP_MAX_MD_NUM);
    s->entry_num = MIN(s->entry_num, IOPMP_MAX_ENTRY_NUM);
    s->k = MIN(s->k, IOPMP_MAX_K_NUM);

    if (!s->model_str || strcmp(s->model_str, "rapidk") == 0) {
        /* apply default model */
        s->model = IOPMP_MODEL_RAPIDK;
        s->regs.mdcfglck = FIELD_DP32(s->regs.mdcfglck, MDCFGLCK, F, s->md_num);
        s->regs.mdcfglck = FIELD_DP32(s->regs.mdcfglck, MDCFGLCK, L, 1);
        s->regs.mdcfg[0] = s->k;
    } else {
        error_setg(errp, "IOPMP model %s is not supported", s->model_str);
        error_append_hint(errp, "Valid value is rapidk.\n");
        return;
    }
    memory_region_init_iommu(&s->iommu, sizeof(s->iommu),
                             TYPE_IOPMP_IOMMU_MEMORY_REGION,
                             obj, "atciopmp300-sysbus-iommu", UINT64_MAX);
    address_space_init(&s->iopmp_sysbus_as, MEMORY_REGION(&s->iommu), "iommu");
    memory_region_init_io(&s->mmio, obj, &iopmp_ops,
                          s, "iopmp-regs", 0x4000);
    sysbus_init_mmio(sbd, &s->mmio);
    /*
     * Set blocked region owner to NULL to because we only want mmio have
     * reentrancy_guard (all mr which owner is the same device share the
     * mem_reentrancy_guard, mr->dev->mem_reentrancy_guard.engaged_in_io)
     */
    memory_region_init_io(&s->blocked_rw, NULL, &iopmp_block_rw_ops,
                          s, "iopmp-blocked-rw", size);
    memory_region_init_io(&s->blocked_w, NULL, &iopmp_block_w_ops,
                          s, "iopmp-blocked-w", size);
    memory_region_init_io(&s->blocked_r, NULL, &iopmp_block_r_ops,
                          s, "iopmp-blocked-r", size);

    memory_region_init_io(&s->blocked_rwx, NULL, &iopmp_block_rwx_ops,
                          s, "iopmp-blocked-rwx", size);
    memory_region_init_io(&s->blocked_wx, NULL, &iopmp_block_wx_ops,
                          s, "iopmp-blocked-wx", size);
    memory_region_init_io(&s->blocked_rx, NULL, &iopmp_block_rx_ops,
                          s, "iopmp-blocked-rx", size);
    memory_region_init_io(&s->blocked_x, NULL, &iopmp_block_x_ops,
                          s, "iopmp-blocked-x", size);

    address_space_init(&s->downstream_as, s->downstream,
                       "iopmp-downstream-as");
    address_space_init(&s->blocked_rw_as, &s->blocked_rw,
                       "iopmp-blocked-rw-as");
    address_space_init(&s->blocked_w_as, &s->blocked_w,
                       "iopmp-blocked-w-as");
    address_space_init(&s->blocked_r_as, &s->blocked_r,
                       "iopmp-blocked-r-as");

    address_space_init(&s->blocked_rwx_as, &s->blocked_rwx,
                       "iopmp-blocked-rwx-as");
    address_space_init(&s->blocked_wx_as, &s->blocked_wx,
                       "iopmp-blocked-wx-as");
    address_space_init(&s->blocked_rx_as, &s->blocked_rx,
                       "iopmp-blocked-rx-as");
    address_space_init(&s->blocked_x_as, &s->blocked_x,
                       "iopmp-blocked-x-as");

    memory_region_init_io(&s->stall_io, obj, &iopmp_stall_io_ops,
                          s, "iopmp-stall-io", size);
    address_space_init(&s->stall_io_as, &s->stall_io,
                       "iopmp-stall-io-as");

    object_initialize_child(OBJECT(s), "iopmp_transaction_info",
                            &s->transaction_info_sink,
                            TYPE_IOPMP_TRANSACTION_INFO_SINK);
}

static void iopmp_reset(DeviceState *dev)
{
    Atciopmp300state *s = ATCIOPMP300(dev);

    qemu_set_irq(s->irq, 0);
    memset(&s->regs, 0, sizeof(iopmp_regs));
    memset(&s->entry_addr, 0, IOPMP_MAX_ENTRY_NUM * sizeof(iopmp_addr_t));
    memset(&s->sid_stall, 0, s->sid_num * sizeof(bool));

    s->prog_prient = CFG_PROG_PRIENT;
    s->enable = 0;

    if (s->model == IOPMP_MODEL_RAPIDK) {
        s->regs.mdcfglck = FIELD_DP32(s->regs.mdcfglck, MDCFGLCK, F, s->md_num);
        s->regs.mdcfglck = FIELD_DP32(s->regs.mdcfglck, MDCFGLCK, L, 1);
        s->regs.mdcfg[0] = s->k;
    }
}

static int iopmp_attrs_to_index(IOMMUMemoryRegion *iommu, MemTxAttrs attrs)
{
    return attrs.requester_id;
}

static int iopmp_num_indexes(IOMMUMemoryRegion *iommu)
{
    Atciopmp300state *s = ATCIOPMP300(container_of(iommu, Atciopmp300state,
                                                   iommu));
    return s->sid_num;
}

static void iopmp_iommu_memory_region_class_init(ObjectClass *klass, void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);

    imrc->translate = iopmp_translate;
    imrc->attrs_to_index = iopmp_attrs_to_index;
    imrc->num_indexes = iopmp_num_indexes;
}

static Property iopmp_property[] = {
    DEFINE_PROP_STRING("model", Atciopmp300state, model_str),
    DEFINE_PROP_BOOL("sps_en", Atciopmp300state, sps_en, false),
    DEFINE_PROP_UINT32("k", Atciopmp300state, k, CFG_IOPMP_MODEL_K),
    DEFINE_PROP_UINT32("prio_entry", Atciopmp300state, prio_entry,
                       CFG_PRIO_ENTRY),
    DEFINE_PROP_UINT32("sid_num", Atciopmp300state, sid_num, IOPMP_SID_NUM),
    DEFINE_PROP_UINT32("md_num", Atciopmp300state, md_num, IOPMP_MD_NUM),
    DEFINE_PROP_UINT32("entry_num", Atciopmp300state, entry_num,
                       IOPMP_ENTRY_NUM),
    DEFINE_PROP_END_OF_LIST(),
};

static void atciopmp300_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    device_class_set_props(dc, iopmp_property);
    dc->realize = iopmp_realize;
    dc->reset = iopmp_reset;
}

static void atciopmp300_init(Object *obj)
{
    Atciopmp300state *s = ATCIOPMP300(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    sysbus_init_irq(sbd, &s->irq);
}

static const TypeInfo iopmp_info = {
    .name = TYPE_ATCIOPMP300,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Atciopmp300state),
    .instance_init = atciopmp300_init,
    .class_init = atciopmp300_class_init,
};

static const TypeInfo
iopmp_iommu_memory_region_info = {
    .name = TYPE_IOPMP_IOMMU_MEMORY_REGION,
    .parent = TYPE_IOMMU_MEMORY_REGION,
    .class_init = iopmp_iommu_memory_region_class_init,
};

static AddressSpace *atciopmp300_find_add_as(PCIBus *bus, void *opaque,
                                             int devfn)
{
    Atciopmp300state *s = opaque;
    uint32_t id = PCI_BUILD_BDF(pci_bus_num(bus), devfn) % s->sid_num;
    iopmp_pci_addressspcace *iopmp_pci = s->iopmp_pci[id];

    if (iopmp_pci == NULL) {
        g_autofree char *name = NULL;
        name = g_strdup_printf("atciopmp300-pci-iommu%d", id);
        iopmp_pci = g_new0(iopmp_pci_addressspcace, 1);
        iopmp_pci->iopmp = opaque;
        memory_region_init_iommu(&iopmp_pci->iommu,
                                 sizeof(iopmp_pci->iommu),
                                 TYPE_IOPMP_IOMMU_MEMORY_REGION,
                                 OBJECT(s), name, UINT64_MAX);
        address_space_init(&iopmp_pci->as,
                           MEMORY_REGION(&iopmp_pci->iommu), "iommu");
    }
    return &iopmp_pci->as;
}

static const PCIIOMMUOps iopmp_iommu_ops = {
    .get_address_space = atciopmp300_find_add_as,
};

void iopmp_setup_pci(DeviceState *iopmp_dev, PCIBus *bus)
{
    Atciopmp300state *s = ATCIOPMP300(iopmp_dev);
    pci_setup_iommu(bus, &iopmp_iommu_ops, s);
}


/*
 * Alias subregions from the source memory region to the destination memory
 * region
 */
static void alias_memory_subregions(MemoryRegion *src_mr, MemoryRegion *dst_mr,
                                    const MemMapEntry *memmap,
                                    uint32_t map_entry_num)
{
    int32_t priority;
    hwaddr addr;
    MemoryRegion *alias, *subregion;
    QTAILQ_FOREACH(subregion, &src_mr->subregions, subregions_link) {
        addr = subregion->addr;
        for (int i = 0; i < map_entry_num; i++) {
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

/*
 * Create downstream of system memory for IOPMP, and overlap memory region
 * specified in memmap with IOPMP translator. Make sure subregions are added to
 * system memory before call this function.
 */
void iopmp300_setup_system_memory(DeviceState *dev, const MemMapEntry *memmap,
                                  uint32_t map_entry_num)
{
    Atciopmp300state *s = ATCIOPMP300(dev);
    uint32_t i;
    MemoryRegion *iommu_alias;
    MemoryRegion *target_mr = get_system_memory();
    MemoryRegion *downstream = g_malloc0(sizeof(MemoryRegion));
    memory_region_init(downstream, NULL, "iopmp_downstream",
                       memory_region_size(target_mr));
    /* Create a downstream which does not have iommu of iopmp */
    alias_memory_subregions(target_mr, downstream, memmap, map_entry_num);

    for (i = 0; i < map_entry_num; i++) {
        /* Memory access to protected regions of target are through IOPMP */
        iommu_alias = g_new(MemoryRegion, 1);
        memory_region_init_alias(iommu_alias, NULL, "iommu_alias",
                                 MEMORY_REGION(&s->iommu), memmap[i].base,
                                 memmap[i].size);
        memory_region_add_subregion_overlap(target_mr, memmap[i].base,
                                            iommu_alias, 1);
    }
    s->downstream = downstream;
    address_space_init(&s->downstream_as, s->downstream,
                       "iopmp-downstream-as");
}

static size_t
transaction_info_push(StreamSink *transaction_info_sink, unsigned char *buf,
                      size_t len, bool eop)
{
    Iopmp_StreamSink *ss = IOPMP_TRANSACTION_INFO_SINK(transaction_info_sink);
    Atciopmp300state *s = ATCIOPMP300(container_of(ss, Atciopmp300state,
                                      transaction_info_sink));
    iopmp_transaction_info signal;
    uint32_t sid;

    memcpy(&signal, buf, len);
    sid = signal.sid;

    if (s->transaction_state[sid].running) {
        if (eop) {
            /* Finish the transaction */
            qemu_mutex_lock(&s->iopmp_transaction_mutex);
            s->transaction_state[sid].running = 0;
            qemu_mutex_unlock(&s->iopmp_transaction_mutex);
            return 1;
        } else {
            /* Transaction is already running */
            return 0;
        }
    } else if (len == sizeof(iopmp_transaction_info)) {
        /* Get the transaction info */
        s->transaction_state[sid].supported = 1;
        qemu_mutex_lock(&s->iopmp_transaction_mutex);
        s->transaction_state[sid].running = 1;
        qemu_mutex_unlock(&s->iopmp_transaction_mutex);

        s->transaction_state[sid].start_addr = signal.start_addr;
        s->transaction_state[sid].end_addr = signal.end_addr;
        s->transaction_state[sid].error_pending = 0;
        return 1;
    }
    return 0;
}

static void iopmp_transaction_info_sink_class_init(ObjectClass *klass,
                                                   void *data)
{
    StreamSinkClass *ssc = STREAM_SINK_CLASS(klass);
    ssc->push = transaction_info_push;
}

static const TypeInfo transaction_info_sink = {
    .name = TYPE_IOPMP_TRANSACTION_INFO_SINK,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(Iopmp_StreamSink),
    .class_init = iopmp_transaction_info_sink_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_STREAM_SINK },
        { }
    },
};

static void
atciopmp300_register_types(void)
{
    type_register_static(&iopmp_info);
    type_register_static(&iopmp_iommu_memory_region_info);
    type_register_static(&transaction_info_sink);
}

DeviceState *atciopmp300_create(hwaddr addr, qemu_irq irq)
{
    DeviceState *dev;
    SysBusDevice *s;

    dev = qdev_new("atciopmp300");
    s = SYS_BUS_DEVICE(dev);
    sysbus_realize_and_unref(s, &error_fatal);
    sysbus_mmio_map(s, 0, addr);
    sysbus_connect_irq(s, 0, irq);
    return dev;
}

type_init(atciopmp300_register_types);

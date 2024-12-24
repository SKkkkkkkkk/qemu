/*
 * RISC-V GDB Server Stub
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
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
#include "qemu/qemu-print.h"
#include "exec/gdbstub.h"
#include "gdbstub/helpers.h"
#include "cpu.h"
#include "andes_ace_helper.h"

struct TypeSize {
    const char *gdb_type;
    const char *id;
    int size;
    const char suffix;
};

static const struct TypeSize vec_lanes[] = {
    /* quads */
    { "uint128", "quads", 128, 'q' },
    /* 64 bit */
    { "uint64", "longs", 64, 'l' },
    /* 32 bit */
    { "uint32", "words", 32, 'w' },
    /* 16 bit */
    { "uint16", "shorts", 16, 's' },
    /*
     * TODO: currently there is no reliable way of telling
     * if the remote gdb actually understands ieee_half so
     * we don't expose it in the target description for now.
     * { "ieee_half", 16, 'h', 'f' },
     */
    /* bytes */
    { "uint8", "bytes", 8, 'b' },
};

int riscv_cpu_gdb_read_register(CPUState *cs, GByteArray *mem_buf, int n)
{
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(cs);
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    target_ulong tmp;

    if (n < 32) {
        tmp = env->gpr[n];
    } else if (n == 32) {
        tmp = env->pc;
    } else {
        return 0;
    }

    switch (mcc->misa_mxl_max) {
    case MXL_RV32:
        return gdb_get_reg32(mem_buf, tmp);
    case MXL_RV64:
    case MXL_RV128:
        return gdb_get_reg64(mem_buf, tmp);
    default:
        g_assert_not_reached();
    }
    return 0;
}

int riscv_cpu_gdb_write_register(CPUState *cs, uint8_t *mem_buf, int n)
{
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(cs);
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    int length = 0;
    target_ulong tmp;

    switch (mcc->misa_mxl_max) {
    case MXL_RV32:
        tmp = (int32_t)ldl_p(mem_buf);
        length = 4;
        break;
    case MXL_RV64:
    case MXL_RV128:
        if (env->xl < MXL_RV64) {
            tmp = (int32_t)ldq_p(mem_buf);
        } else {
            tmp = ldq_p(mem_buf);
        }
        length = 8;
        break;
    default:
        g_assert_not_reached();
    }
    if (n > 0 && n < 32) {
        env->gpr[n] = tmp;
    } else if (n == 32) {
        env->pc = tmp;
    }

    return length;
}

static int riscv_gdb_get_fpu(CPUState *cs, GByteArray *buf, int n)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;

    if (n < 32) {
        if (env->misa_ext & RVD) {
            return gdb_get_reg64(buf, env->fpr[n]);
        }
        if (env->misa_ext & RVF) {
            return gdb_get_reg32(buf, env->fpr[n]);
        }
    }
    return 0;
}

static int riscv_gdb_set_fpu(CPUState *cs, uint8_t *mem_buf, int n)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;

    if (n < 32) {
        env->fpr[n] = ldq_p(mem_buf); /* always 64-bit */
        return sizeof(uint64_t);
    }
    return 0;
}

static int riscv_gdb_get_vector(CPUState *cs, GByteArray *buf, int n)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    uint16_t vlenb = cpu->cfg.vlenb;
    if (n < 32) {
        int i;
        int cnt = 0;
        for (i = 0; i < vlenb; i += 8) {
            cnt += gdb_get_reg64(buf,
                                 env->vreg[(n * vlenb + i) / 8]);
        }
        return cnt;
    }

    return 0;
}

static int riscv_gdb_set_vector(CPUState *cs, uint8_t *mem_buf, int n)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    uint16_t vlenb = cpu->cfg.vlenb;
    if (n < 32) {
        int i;
        for (i = 0; i < vlenb; i += 8) {
            env->vreg[(n * vlenb + i) / 8] = ldq_p(mem_buf + i);
        }
        return vlenb;
    }

    return 0;
}

static int riscv_gdb_get_csr(CPUState *cs, GByteArray *buf, int n)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;

    if (n < CSR_TABLE_SIZE) {
        target_ulong val = 0;
        int result;

        result = riscv_csrrw_debug(env, n, &val, 0, 0);
        if (result == RISCV_EXCP_NONE) {
            return gdb_get_regl(buf, val);
        }
    }
    return 0;
}

static int riscv_gdb_set_csr(CPUState *cs, uint8_t *mem_buf, int n)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;

    if (n < CSR_TABLE_SIZE) {
        target_ulong val = ldtul_p(mem_buf);
        int result;

        result = riscv_csrrw_debug(env, n, NULL, val, -1);
        if (result == RISCV_EXCP_NONE) {
            return sizeof(target_ulong);
        }
    }
    return 0;
}

static int riscv_gdb_get_virtual(CPUState *cs, GByteArray *buf, int n)
{
    if (n == 0) {
#ifdef CONFIG_USER_ONLY
        return gdb_get_regl(buf, 0);
#else
        RISCVCPU *cpu = RISCV_CPU(cs);
        CPURISCVState *env = &cpu->env;

        return gdb_get_regl(buf, env->priv);
#endif
    }
    return 0;
}

static int riscv_gdb_set_virtual(CPUState *cs, uint8_t *mem_buf, int n)
{
    if (n == 0) {
#ifndef CONFIG_USER_ONLY
        RISCVCPU *cpu = RISCV_CPU(cs);
        CPURISCVState *env = &cpu->env;

        env->priv = ldtul_p(mem_buf) & 0x3;
        if (env->priv == PRV_RESERVED) {
            env->priv = PRV_S;
        }
#endif
        return sizeof(target_ulong);
    }
    return 0;
}

static GDBFeature *riscv_gen_dynamic_csr_feature(CPUState *cs, int base_reg)
{
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(cs);
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    GDBFeatureBuilder builder;
    riscv_csr_predicate_fn predicate;
    int bitsize = riscv_cpu_max_xlen(mcc);
    const char *name;
    int i;

#if !defined(CONFIG_USER_ONLY)
    env->debugger = true;
#endif

    /* Until gdb knows about 128-bit registers */
    if (bitsize > 64) {
        bitsize = 64;
    }

    gdb_feature_builder_init(&builder, &cpu->dyn_csr_feature,
                             "org.gnu.gdb.riscv.csr", "riscv-csr.xml",
                             base_reg);

    for (i = 0; i < CSR_TABLE_SIZE; i++) {
        if (env->priv_ver < csr_ops[i].min_priv_ver) {
            continue;
        }
        predicate = csr_ops[i].predicate;
        if (predicate && (predicate(env, i) == RISCV_EXCP_NONE)) {
            name = csr_ops[i].name;
            if (!name) {
                name = g_strdup_printf("csr%03x", i);
            }

            gdb_feature_builder_append_reg(&builder, name, bitsize, i,
                                           "int", NULL);
        }
    }

    gdb_feature_builder_end(&builder);

#if !defined(CONFIG_USER_ONLY)
    env->debugger = false;
#endif

    return &cpu->dyn_csr_feature;
}

static int andes_ace_get_reg(CPUState *cs, int reg_n)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    unsigned int ByteSize = 0;
    unsigned int reg_idx = 0;
    char *type_name = NULL;
    uint32_t curr_reg_no = 0;
    AceAcrInfo *acr_info_list = env->ace_acr_info_list;
    unsigned int grp_idx = 0;
    uint64_t *value;
    uint32_t value_len;

    if (acr_info_list == NULL) {
        return 0;
    }

    /* Get acr info by ACR register number */
    for (unsigned int i = 0; i < env->ace_acracm_reg_number; i++) {
        if ((acr_info_list->num + curr_reg_no) >= reg_n + 1) {
            reg_idx = reg_n - curr_reg_no;
            grp_idx = acr_info_list->idx;
            type_name = acr_info_list->name;
            unsigned int acr_width = acr_info_list->width;
            ByteSize =
                (acr_width % 8 == 0) ? acr_width / 8 : (acr_width / 8) + 1;
            break;
        }
        curr_reg_no += acr_info_list->num;
        acr_info_list++;
    }
    if (type_name == NULL) {
        qemu_printf("Cannot find gdb ACE register number %d\n", reg_n);
        return -1;
    }

    value = qemu_ace_agent_get_register(env, grp_idx, reg_idx, &value_len);
    env->ace_acr_value = (unsigned char *)value;
    return ByteSize;
}

static int andes_ace_set_reg(CPUState *cs, unsigned char *val, int reg_n)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    unsigned int ByteSize = 0;
    unsigned int reg_idx = 0;
    char *type_name = NULL;
    uint32_t curr_reg_no = 0;
    AceAcrInfo *acr_info_list = env->ace_acr_info_list;
    unsigned int grp_idx = 0;
    uint32_t value_len;

    if (acr_info_list == NULL) {
        return 0;
    }

    /* Get acr info by ACR register number */
    for (unsigned int i = 0; i < env->ace_acracm_reg_number; i++) {
        if ((acr_info_list->num + curr_reg_no) >= reg_n + 1) {
            reg_idx = reg_n - curr_reg_no;
            grp_idx = acr_info_list->idx;
            type_name = acr_info_list->name;
            unsigned int acr_width = acr_info_list->width;
            ByteSize =
                (acr_width % 8 == 0) ? acr_width / 8 : (acr_width / 8) + 1;
            break;
        }
        curr_reg_no += acr_info_list->num;
        acr_info_list++;
    }
    if (type_name == NULL) {
        qemu_printf("Cannot find acr reg no %d\n", reg_n);
        return -1;
    }

    /* value_len is stored as a 64-bit unsigned integer size */
    value_len = ByteSize >> 3 ? ByteSize >> 3 : 1;
    qemu_ace_agent_set_register(env, grp_idx, reg_idx,
                                (uint64_t *)val, value_len);

    return ByteSize;
}

static int riscv_gdb_get_ace(CPUState *cs, GByteArray *buf, int n)
{
    unsigned total_bytes = andes_ace_get_reg(cs, n);
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    if (total_bytes != -1) {
        g_byte_array_append(buf, env->ace_acr_value, total_bytes);
        return total_bytes;
    }
    return 0;
}

static int riscv_gdb_set_ace(CPUState *cs, uint8_t *mem_buf, int n)
{
    unsigned total_bytes = andes_ace_set_reg(cs, mem_buf, n);
    if (total_bytes != -1) {
        return total_bytes;
    }
    return 0;
}

static GDBFeature *riscv_gen_dynamic_ace_xml(CPUState *cs, int base_reg)
{
#if defined(CONFIG_USER_ONLY)
        return NULL;
#else
    RISCVCPU *cpu = RISCV_CPU(cs);
    GDBFeatureBuilder builder;
    CPURISCVState *env = &cpu->env;
    int num_regs = 0;
    AceAcrInfo *acr_info_list = env->ace_acr_info_list;

    if (acr_info_list == NULL) {
        return NULL;
    }

#if !defined(CONFIG_USER_ONLY)
    env->debugger = true;
#endif

    gdb_feature_builder_init(&builder, &cpu->dyn_ace_feature,
                             "org.gnu.gdb.riscv.ace", "riscv-ace.xml",
                             base_reg);

    for (unsigned int i = 0; i < env->ace_acracm_reg_number; i++) {
        unsigned int acr_number = acr_info_list->num;
        unsigned int acr_width = acr_info_list->width;
        char *acr_name = acr_info_list->name;
        unsigned int ByteSize =
            (acr_width % 8 == 0) ? acr_width / 8 : (acr_width / 8) + 1;

        gdb_feature_builder_append_tag(
            &builder, "<vector id=\"acr_%d_t\" type=\"uint8\" count=\"%d\"/>",
            ByteSize * 8, ByteSize);


        for (unsigned int idx = 0; idx < acr_number; idx++) {
            char acr_reg_name[2048];
            char acr_type[16];
            snprintf(acr_reg_name, sizeof(acr_reg_name),
                     "%s_%u", acr_name, idx);
            snprintf(acr_type, sizeof(acr_type),
                     "acr_%d_t", ByteSize * 8);
            gdb_feature_builder_append_reg(&builder, acr_reg_name, acr_width,
                                           num_regs++, acr_type, "ace");
        }
        acr_info_list++;
    }

    gdb_feature_builder_end(&builder);

#if !defined(CONFIG_USER_ONLY)
    env->debugger = false;
#endif

    return &cpu->dyn_ace_feature;
#endif
}

static GDBFeature *ricsv_gen_dynamic_vector_feature(CPUState *cs, int base_reg)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    int bitsize = cpu->cfg.vlenb << 3;
    GDBFeatureBuilder builder;
    int i;

    gdb_feature_builder_init(&builder, &cpu->dyn_vreg_feature,
                             "org.gnu.gdb.riscv.vector", "riscv-vector.xml",
                             base_reg);

    /* First define types and totals in a whole VL */
    for (i = 0; i < ARRAY_SIZE(vec_lanes); i++) {
        int count = bitsize / vec_lanes[i].size;
        gdb_feature_builder_append_tag(
            &builder, "<vector id=\"%s\" type=\"%s\" count=\"%d\"/>",
            vec_lanes[i].id, vec_lanes[i].gdb_type, count);
    }

    /* Define unions */
    gdb_feature_builder_append_tag(&builder, "<union id=\"riscv_vector\">");
    for (i = 0; i < ARRAY_SIZE(vec_lanes); i++) {
        gdb_feature_builder_append_tag(&builder,
                                       "<field name=\"%c\" type=\"%s\"/>",
                                       vec_lanes[i].suffix, vec_lanes[i].id);
    }
    gdb_feature_builder_append_tag(&builder, "</union>");

    /* Define vector registers */
    for (i = 0; i < 32; i++) {
        gdb_feature_builder_append_reg(&builder, g_strdup_printf("v%d", i),
                                       bitsize, i, "riscv_vector", "vector");
    }

    gdb_feature_builder_end(&builder);

    return &cpu->dyn_vreg_feature;
}

void riscv_cpu_register_gdb_regs_for_features(CPUState *cs)
{
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(cs);
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    if (env->misa_ext & RVD) {
        gdb_register_coprocessor(cs, riscv_gdb_get_fpu, riscv_gdb_set_fpu,
                                 gdb_find_static_feature("riscv-64bit-fpu.xml"),
                                 0);
    } else if (env->misa_ext & RVF) {
        gdb_register_coprocessor(cs, riscv_gdb_get_fpu, riscv_gdb_set_fpu,
                                 gdb_find_static_feature("riscv-32bit-fpu.xml"),
                                 0);
    }
    if (cpu->cfg.ext_zve32x) {
        gdb_register_coprocessor(cs, riscv_gdb_get_vector,
                                 riscv_gdb_set_vector,
                                 ricsv_gen_dynamic_vector_feature(cs, cs->gdb_num_regs),
                                 0);
    }
    switch (mcc->misa_mxl_max) {
    case MXL_RV32:
        gdb_register_coprocessor(cs, riscv_gdb_get_virtual,
                                 riscv_gdb_set_virtual,
                                 gdb_find_static_feature("riscv-32bit-virtual.xml"),
                                 0);
        break;
    case MXL_RV64:
    case MXL_RV128:
        gdb_register_coprocessor(cs, riscv_gdb_get_virtual,
                                 riscv_gdb_set_virtual,
                                 gdb_find_static_feature("riscv-64bit-virtual.xml"),
                                 0);
        break;
    default:
        g_assert_not_reached();
    }

    if (cpu->cfg.ext_zicsr) {
        gdb_register_coprocessor(cs, riscv_gdb_get_csr, riscv_gdb_set_csr,
                                 riscv_gen_dynamic_csr_feature(cs, cs->gdb_num_regs),
                                 0);
    }
    GDBFeature *feature = riscv_gen_dynamic_ace_xml(cs, cs->gdb_num_regs);
    if (feature && feature->num_regs != 0) {
        gdb_register_coprocessor(cs, riscv_gdb_get_ace, riscv_gdb_set_ace,
                                 feature,
                                 0);
    }
}

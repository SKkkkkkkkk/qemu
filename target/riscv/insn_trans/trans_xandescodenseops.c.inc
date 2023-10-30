/*
 * RISC-V translation routines for Andes CoDense
 *
 * Copyright (c) 2023 Andes Technology Corp.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "andes_cpu_bits.h"

#define ANDES_V5_GET_JAL_UIMM(inst) ((extract32(inst, 21, 10) << 1) \
                           | (extract32(inst, 20, 1) << 11) \
                           | (extract32(inst, 12, 8) << 12) \
                           | (extract32(inst, 31, 1) << 20))

extern const RISCVDecoder16 decoder16_table[];
extern const size_t decoder16_table_size;

static void decode_opc_andes(CPURISCVState *env,
                             DisasContext *ctx,
                             uint32_t opcode)
{
    /* Check for compressed insn */
    uint16_t opcode16 = opcode;
    if (extract16(opcode16, 0, 2) != 3) {
        if (!has_ext(ctx, RVC)) {
            gen_exception_illegal(ctx);
        } else {
            ctx->opcode = opcode16;

            for (size_t i = 0; i < decoder16_table_size; ++i) {
                if (decoder16_table[i].guard_func(ctx->cfg_ptr) &&
                    decoder16_table[i].riscv_cpu_decode_fn(ctx, opcode16)) {
                    return;
                }
            }
        }
    } else {
        ctx->opcode = opcode;
        for (size_t i = 0; i < decoder_table_size; ++i) {
            if (decoder_table[i].guard_func(ctx->cfg_ptr) &&
                decoder_table[i].riscv_cpu_decode_fn(ctx, opcode)) {
                return;
            }
        }
    }

    gen_exception_illegal(ctx);
}

static int andes_v5_gen_codense_exec_it(DisasContext *ctx,
                                        arg_execit *a)
{
    uint32_t insn;
    uint32_t imm_ex10 = a->imm_codense;
    CPURISCVState *env = cpu_env(ctx->cs);
    target_ulong uitb_val = 0;
    riscv_csrrw(env, CSR_UITB, &uitb_val, 0, 0);

    if (extract32(uitb_val, 0, 1)) { /* UTIB.HW == 1 */
        qemu_log_mask(LOG_GUEST_ERROR,
            "exec.it: UITB.HW == 1 is not supported by now!\n");
        gen_exception_illegal(ctx);
        uint32_t instruction_table[0];
        insn = instruction_table[imm_ex10 >> 2];
        return false;
    } else { /* UTIB.HW == 0 */
        target_ulong vaddr = (uitb_val & ~0x3) + (imm_ex10 << 2);
        insn = cpu_ldl_code(env, vaddr);
    }

    /*
     * Execute(insn)
     * do as the replaced instruction, even exceptions,
     * except ctx->pc_succ_insn value (2).
     */
    uint32_t op = MASK_OP_MAJOR(insn);
    if (op == OPC_RISC_JAL) {
        /* implement this by hack imm */
        /* Direct calculate rd and imm instead of decode_insn32_extract_j */
        int rd = GET_RD(insn);
        target_long imm = ANDES_V5_GET_JAL_UIMM(insn);
        target_ulong next_pc = (ctx->base.pc_next >> 21 << 21) | imm;
        imm = next_pc - ctx->base.pc_next;
        gen_jal(ctx, rd, imm);
    } else {
        /* JARL done as SPEC already */
        /* presume ctx->pc_succ_insn not changed in any ISA extension */
        decode_opc_andes(env, ctx, insn);
    }
    return true;
}

static bool trans_execit(DisasContext *ctx, arg_execit *a)
{
    andes_v5_gen_codense_exec_it(ctx, a);
    return true;
}

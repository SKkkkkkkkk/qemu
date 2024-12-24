/*
 * Andes ACE GDB stub
 *
 * Copyright (c) 2023 Andes Technology Corp.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _ANDES_ACE_GDB_H_
#define _ANDES_ACE_GDB_H_

#define NDS_QUERY_TARGET    "SID"
#define NDS_QUERY_ENDIAN    "LE"
#define NDS_QUERY_TARGET_CMD    "nds query target"
#define NDS_QUERY_ENDIAN_CMD    "nds query endian"
#define NDS_QUERY_CPUID_CMD     "nds query cpuid"
#define NDS_ACE_CMD             "nds ace "
#define NDS_VA_CMD              "nds va "
#define NDS_OTHER_CMD           "nds "

/* this function is coming from andes_ace_help */
int32_t qemu_ace_get_filename_for_gdb(unsigned char *, char *, CPUState *);

int gdb_handle_query_rcmd_andes_query(GArray *, void *);
#endif

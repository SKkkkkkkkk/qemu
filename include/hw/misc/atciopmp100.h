/*
 *  Andes Input Output Physical Memory Protection, ATCIOPMP100
 *
 * Copyright (c) 2023-2024 Andes Tech. Corp.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#ifndef ATCIOPMP100_H
#define ATCIOPMP100_H

DeviceState *atciopmp100_create(hwaddr addr);
void iopmp100_setup_system_memory_range(DeviceState *dev,
                                        const MemMapEntry *memmap,
                                        uint32_t map_entry_num);

#endif

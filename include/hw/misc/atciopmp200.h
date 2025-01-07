/*
 *  Andes Input Output Physical Memory Protection, ATCIOPMP200
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

#ifndef ATCIOPMP200_H
#define ATCIOPMP200_H

#include "hw/misc/atciopmp_utility.h"

DeviceState *atciopmp200_create(hwaddr addr, qemu_irq irq);
void iopmp200_setup_system_memory(DeviceState *dev, const MemMapEntry *memmap,
                                  uint32_t mapentry_num);
Iopmp_StreamSink *iopmp200_get_sink(DeviceState *dev);

#endif

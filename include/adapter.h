/*
 *
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __NEAR_ADAPTER_H
#define __NEAR_ADAPTER_H

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

typedef int (*near_recv)(uint8_t *resp, int length, void *data);
typedef int (*near_release)(int err, void *data);

int near_adapter_connect(uint32_t idx, uint32_t target_idx, uint8_t protocol);
int near_adapter_disconnect(uint32_t idx);
int near_adapter_send(uint32_t idx, uint8_t *buf, size_t length,
			near_recv rx_cb, void *data, near_release data_rel);

#endif

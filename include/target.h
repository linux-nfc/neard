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

#ifndef __NEAR_TARGET_H
#define __NEAR_TARGET_H

#include <stdint.h>

#include <glib.h>

#include <near/tag.h>

#define NFC_MAX_NFCID1_LEN 10

struct near_tag *near_target_add_tag(uint32_t adapter_idx, uint32_t target_idx,
					size_t data_length);
enum near_target_sub_type near_target_get_subtype(uint32_t adapter_idx,
				uint32_t target_idx);
uint8_t *near_target_get_nfcid(uint32_t adapter_idx, uint32_t target_idx,
				uint8_t *nfcid_len);

#endif

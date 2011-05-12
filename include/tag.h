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

#ifndef __NEAR_TAG_H
#define __NEAR_TAG_H

#include <stdint.h>

#include <glib.h>

#include <near/ndef.h>

#define NFC_HEADER_SIZE 1

#define	NEAR_TAG_NFC_TYPE1   0x1
#define	NEAR_TAG_NFC_TYPE2   0x2
#define	NEAR_TAG_NFC_TYPE3   0x4
#define	NEAR_TAG_NFC_TYPE4   0x8
#define	NEAR_TAG_NFC_DEP     0x10
#define	NEAR_TAG_NFC_UNKNOWN 0xff

struct near_tag_driver {
	uint16_t type;

	int (*read_tag)(uint32_t adapter_idx, uint32_t target_idx);
};

int near_tag_driver_register(struct near_tag_driver *driver);
void near_tag_driver_unregister(struct near_tag_driver *driver);

#endif

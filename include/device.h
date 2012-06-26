/*
 *
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#ifndef __NEAR_DEVICE_H
#define __NEAR_DEVICE_H

#include <stdint.h>

#include <glib.h>

struct near_device;

typedef void (*near_device_io_cb) (uint32_t adapter_idx, uint32_t target_idx,
								int status);

struct near_ndef_message;

#define NEAR_DEVICE_PRIORITY_LOW      -100
#define NEAR_DEVICE_PRIORITY_DEFAULT     0
#define NEAR_DEVICE_PRIORITY_HIGH      100

#define NEAR_DEVICE_SN_NPP       "com.android.npp"
#define NEAR_DEVICE_SN_SNEP      "urn:nfc:sn:snep"
#define NEAR_DEVICE_SN_HANDOVER  "urn:nfc:sn:handover"

struct near_device_driver {
	int priority;

	int (*listen)(uint32_t adapter_idx, near_device_io_cb cb);
	int (*push)(uint32_t adapter_idx, uint32_t target_idx,
					struct near_ndef_message *ndef,
					char *service_name,
					near_device_io_cb cb);
};

struct near_device *near_device_get_device(uint32_t adapter_idx,
						uint32_t target_idx);
int near_device_add_data(uint32_t adapter_idx, uint32_t target_idx,
			uint8_t *data, size_t data_length);
int near_device_add_records(struct near_device *device, GList *records,
				near_device_io_cb cb, int status);
int near_device_driver_register(struct near_device_driver *driver);
void near_device_driver_unregister(struct near_device_driver *driver);

#endif

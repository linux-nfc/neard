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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <glib.h>

#include <gdbus.h>

#include "near.h"

struct near_tag {
	uint32_t adapter_idx;
	uint32_t target_idx;
	uint16_t uid;

	uint16_t data_length;
	uint8_t *data;

	GList *ndef_list;
};

static GList *driver_list = NULL;

static void tag_initialize(struct near_tag *tag,
			uint32_t adapter_idx, uint32_t target_idx)
{
	tag->adapter_idx = adapter_idx;
	tag->target_idx = target_idx;

	return;
}

struct near_tag *__near_tag_new(uint32_t adapter_idx, uint32_t target_idx)
{
	struct near_tag *tag;

	tag = g_try_malloc0(sizeof(struct near_tag));
	if (tag == NULL)
		return NULL;

	tag_initialize(tag, adapter_idx, target_idx);

	return tag;
}

void __near_tag_free(struct near_tag *tag)
{
	g_free(tag->data);
	g_free(tag);
}

int near_tag_driver_register(struct near_tag_driver *driver)
{
	DBG("");

	if (driver->read_tag == NULL)
		return -EINVAL;

	driver_list = g_list_append(driver_list, driver);

	return 0;
}

void near_tag_driver_unregister(struct near_tag_driver *driver)
{
	DBG("");

	driver_list = g_list_remove(driver_list, driver);
}

int __near_tag_read(struct near_target *target)
{
	GList *list;
	uint16_t type;

	DBG("");

	type = __near_target_get_tag_type(target);
	if (type == NEAR_TAG_NFC_UNKNOWN)
		return -ENODEV;

	DBG("type 0x%x", type);

	for (list = driver_list; list; list = list->next) {
		struct near_tag_driver *driver = list->data;

		DBG("driver type 0x%x", driver->type);

		if (driver->type & type) {
			uint32_t adapter_idx, target_idx;		

			target_idx = __near_target_get_idx(target);
			adapter_idx = __near_target_get_adapter_idx(target);

			return driver->read_tag(adapter_idx, target_idx);
		}
	}

	return 0;
}

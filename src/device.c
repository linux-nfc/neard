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
#include <string.h>

#include <glib.h>

#include <gdbus.h>

#include "near.h"

struct near_device {
	char *path;

	uint32_t adapter_idx;
	uint32_t target_idx;

	uint8_t nfcid[NFC_MAX_NFCID1_LEN];
	uint8_t nfcid_len;

	size_t data_length;
	uint8_t *data;

	uint32_t n_records;
	GList *records;
};

static DBusConnection *connection = NULL;

static GHashTable *device_hash;

static void free_device(gpointer data)
{
}

int __near_device_init(void)
{
	DBG("");

	connection = near_dbus_get_connection();

	device_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, free_device);

	return 0;
}

void __near_device_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(device_hash);
	device_hash = NULL;
}

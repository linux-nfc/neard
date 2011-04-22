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

#include "near.h"

static GHashTable *adapter_hash;

struct near_adapter {
	char *path;

	char *name;
	guint32 idx;
	guint32 protocols;
};

static void free_adapter(gpointer data)
{
	struct near_adapter *adapter = data;

	g_free(adapter->name);
	g_free(adapter->path);
	g_free(adapter);
}

static void append_path(gpointer key, gpointer value, gpointer user_data)
{
	struct near_adapter *adapter = value;
	DBusMessageIter *iter = user_data;

	DBG("%s", adapter->path);

	if (adapter->path == NULL)
		return;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&adapter->path);

}

void __near_adapter_list(DBusMessageIter *iter, void *user_data)
{
	g_hash_table_foreach(adapter_hash, append_path, iter);
}

int __near_adapter_add(const char *name, guint32 idx, guint32 protocols)
{
	struct near_adapter *adapter;

	DBG("name %s idx %d", name, idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter != NULL)
		return -EEXIST;

	adapter = g_try_malloc0(sizeof(struct near_adapter));
	if (adapter == NULL)
		return -ENOMEM;

	adapter->name = g_strdup(name);
	if (adapter->name == NULL) {
		g_free(adapter);
		return -ENOMEM;
	}
	adapter->idx = idx;
	adapter->protocols = protocols;

	adapter->path = g_strdup_printf("%s/%d", NFC_PATH, idx);

	g_hash_table_insert(adapter_hash, GINT_TO_POINTER(idx), adapter);

	return 0;
}

void __near_adapter_remove(guint32 idx)
{
	g_hash_table_remove(adapter_hash, GINT_TO_POINTER(idx));
}

int __near_adapter_init(void)
{
	DBG("");

	adapter_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_adapter);

	return 0;
}

void __near_adapter_cleanup(void)
{
	g_hash_table_destroy(adapter_hash);
	adapter_hash = NULL;
}

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

static GSList *adapter_list = NULL;

struct near_adapter {
	char *path;

	char *name;
	guint32 idx;
	guint32 protocols;
};

static void append_path(gpointer value, gpointer user_data)
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
	g_slist_foreach(adapter_list, append_path, iter);
}

int __near_adapter_create(const char *name, guint32 idx, guint32 protocols)
{
	struct near_adapter *adapter;

	DBG("name %s idx %d", name, idx);

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

	adapter->path = g_strdup_printf("%s_%d", name, idx);

	adapter_list = g_slist_append(adapter_list, adapter);

	return 0;
}

int __near_adapter_init(void)
{
	DBG("");

	return 0;
}

void __near_adapter_cleanup(void)
{
	GSList *list;
	struct near_adapter *adapter;

	for (list = adapter_list; list; list = list->next) {
		adapter = list->data;

		g_free(adapter->name);
		g_free(adapter->path);
		g_free(adapter);
	}

	g_slist_free(adapter_list);
}

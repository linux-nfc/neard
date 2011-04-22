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

static DBusConnection *connection = NULL;

static GHashTable *adapter_hash;

struct near_adapter {
	char *path;

	char *name;
	guint32 idx;
	guint32 protocols;

	near_bool_t powered;
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

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_adapter *adapter = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	near_dbus_dict_open(&array, &dict);

	near_dbus_dict_append_basic(&dict, "Powered",
				    DBUS_TYPE_BOOLEAN, &adapter->powered);

	near_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("conn %p", conn);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable adapter_methods[] = {
	{ "GetProperties",     "",      "a{sv}", get_properties     },
	{ "SetProperty",       "sv",    "",      set_property       },
	{ },
};

static GDBusSignalTable adapter_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ "TargetFound",		"o"	},
	{ "TargetLost",			"o"	},
	{ }
};

struct near_adapter * __near_adapter_create(guint32 idx,
					const char *name, guint32 protocols)
{
	struct near_adapter *adapter;

	adapter = g_try_malloc0(sizeof(struct near_adapter));
	if (adapter == NULL)
		return NULL;

	adapter->name = g_strdup(name);
	if (adapter->name == NULL) {
		g_free(adapter);
		return NULL;
	}
	adapter->idx = idx;
	adapter->protocols = protocols;
	adapter->powered = TRUE;

	adapter->path = g_strdup_printf("%s/nfc%d", NFC_PATH, idx);

	return adapter;
}

void __near_adapter_destroy(struct near_adapter *adapter)
{
	DBG("");

	free_adapter(adapter);
}

const char *__near_adapter_get_path(struct near_adapter *adapter)
{
	return adapter->path;
}

struct near_adapter *__near_adapter_get(guint32 idx)
{
	return g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
}

int __near_adapter_add(struct near_adapter *adapter)
{
	guint32 idx = adapter->idx;

	DBG("%s", adapter->path);

	if (g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx)) != NULL)
		return -EEXIST;

	g_hash_table_insert(adapter_hash, GINT_TO_POINTER(idx), adapter);

	DBG("connection %p", connection);

	g_dbus_register_interface(connection, adapter->path,
					NFC_ADAPTER_INTERFACE,
					adapter_methods, adapter_signals,
							NULL, adapter, NULL);

	return 0;
}

void __near_adapter_remove(struct near_adapter *adapter)
{
	DBG("%s", adapter->path);

	g_dbus_unregister_interface(connection, adapter->path,
						NFC_ADAPTER_INTERFACE);

	g_hash_table_remove(adapter_hash, GINT_TO_POINTER(adapter->idx));
}

int __near_adapter_init(void)
{
	DBG("");

	connection = near_dbus_get_connection();

	adapter_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_adapter);

	return 0;
}

void __near_adapter_cleanup(void)
{
	g_hash_table_destroy(adapter_hash);
	adapter_hash = NULL;
}

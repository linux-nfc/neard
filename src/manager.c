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

static DBusConnection *connection;

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	near_dbus_dict_open(&array, &dict);

	near_dbus_dict_append_array(&dict, "Adapters",
			DBUS_TYPE_OBJECT_PATH, __near_adapter_list, NULL);

	near_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("conn %p", conn);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

int __near_manager_adapter_add(uint32_t idx, const char *name,
				uint32_t protocols, near_bool_t powered)
{
	struct near_adapter *adapter;
	const char *path;
	int err;

	DBG("idx %d", idx);

	adapter = __near_adapter_create(idx, name, protocols, powered);
	if (adapter == NULL)
		return -ENOMEM;

	path = __near_adapter_get_path(adapter);
	if (path == NULL) {
		__near_adapter_destroy(adapter);
		return -EINVAL;
	}

	err = __near_adapter_add(adapter);
	if (err < 0) {
		__near_adapter_destroy(adapter);
	} else {
		near_dbus_property_changed_array(NFC_MANAGER_PATH,
				NFC_MANAGER_INTERFACE, "Adapters",
				DBUS_TYPE_OBJECT_PATH, __near_adapter_list,
				NULL);

		g_dbus_emit_signal(connection, "/",
			NFC_MANAGER_INTERFACE, "AdapterAdded",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);
	}

	return err;
}

void __near_manager_adapter_remove(uint32_t idx)
{
	struct near_adapter *adapter;
	const char *path;

	DBG("idx %d", idx);

	adapter = __near_adapter_get(idx);
	if (adapter == NULL)
		return;

	path = __near_adapter_get_path(adapter);
	if (path == NULL)
		return;


	g_dbus_emit_signal(connection, "/",
			NFC_MANAGER_INTERFACE, "AdapterRemoved",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	__near_adapter_remove(adapter);

	near_dbus_property_changed_array(NFC_MANAGER_PATH,
				NFC_MANAGER_INTERFACE, "Adapters",
				DBUS_TYPE_OBJECT_PATH, __near_adapter_list,
				NULL);
}

static GDBusMethodTable manager_methods[] = {
	{ "GetProperties",     "",      "a{sv}", get_properties     },
	{ "SetProperty",       "sv",    "",      set_property       },
	{ },
};

static GDBusSignalTable manager_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ "AdapterAdded",		"o"	},
	{ "AdapterRemoved",		"o"	},
	{ }
};

int __near_manager_init(DBusConnection *conn)
{
	DBG("");

	connection = dbus_connection_ref(conn);

	DBG("connection %p", connection);

	g_dbus_register_interface(connection, NFC_MANAGER_PATH,
						NFC_MANAGER_INTERFACE,
						manager_methods,
						manager_signals, NULL, NULL, NULL);

	return __near_netlink_get_adapters();
}

void __near_manager_cleanup(void)
{
	DBG("");

	g_dbus_unregister_interface(connection, NFC_MANAGER_PATH,
						NFC_MANAGER_INTERFACE);

	dbus_connection_unref(connection);
}

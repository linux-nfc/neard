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

#include <glib.h>

#include <gdbus.h>

#include "near.h"

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

static DBusConnection *connection;

int __near_manager_init(DBusConnection *conn)
{
	DBG("");

	connection = dbus_connection_ref(conn);

	g_dbus_register_interface(connection, NFC_MANAGER_PATH,
						NFC_MANAGER_INTERFACE,
						manager_methods,
						manager_signals, NULL, NULL, NULL);

	return 0;
}

void __near_manager_cleanup(void)
{
	DBG("");

	g_dbus_unregister_interface(connection, NFC_MANAGER_PATH,
						NFC_MANAGER_INTERFACE);

	dbus_connection_unref(connection);
}

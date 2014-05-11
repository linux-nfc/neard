/*
 *
 *  seeld - Secure Element Manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <glib.h>

#include <gdbus.h>

#include "manager.h"
#include "seel.h"

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

	near_dbus_dict_append_array(&dict, "SecureElements",
			DBUS_TYPE_OBJECT_PATH, __seel_se_list, NULL);

	near_dbus_dict_close(&array, &dict);

	return reply;
}

int seel_manager_se_add(uint32_t se_idx, uint8_t ctrl_idx,
			uint8_t se_type, uint8_t ctrl_type)
{
	char *se_path;

	se_path = __seel_se_add(se_idx, ctrl_idx, se_type, ctrl_type);
	if (se_path ==  NULL)
		return -ENOMEM;

	DBG("Adding %s", se_path);

	g_dbus_emit_signal(connection, "/",
			SEEL_MANAGER_INTERFACE, "SecureElementAdded",
			DBUS_TYPE_OBJECT_PATH, &se_path,
			DBUS_TYPE_INVALID);

	return 0;
}

int seel_manager_se_remove(uint32_t se_idx, uint8_t ctrl_idx,
						uint8_t ctrl_type)
{
	struct seel_se *se;
	char *se_path;
	int err;

	se = __seel_se_get(se_idx, ctrl_idx, ctrl_type);
	if (se == NULL)
		return -ENODEV;

	se_path = g_strdup(__seel_se_get_path(se));
	if (se_path == NULL)
		return -EINVAL;

	err = __seel_se_remove(se_idx, ctrl_idx, ctrl_type);
	if (err < 0)
		return err;

	g_dbus_emit_signal(connection, "/",
			SEEL_MANAGER_INTERFACE, "SecureElementRemoved",
			DBUS_TYPE_OBJECT_PATH, &se_path,
			DBUS_TYPE_INVALID);

	g_free(se_path);

	return 0;
}

static const GDBusMethodTable manager_methods[] = {
	{ GDBUS_METHOD("GetProperties",
				NULL, GDBUS_ARGS({"properties", "a{sv}"}),
				get_properties) },
	{ },
};

static const GDBusSignalTable manager_signals[] = {
	{ GDBUS_SIGNAL("SecureElementAdded", GDBUS_ARGS({"se", "o" })) },
	{ GDBUS_SIGNAL("SecureElementRemoved", GDBUS_ARGS({"se", "o" })) },
	{ }
};

int __seel_manager_init(DBusConnection *conn)
{
	DBG("");

	connection = dbus_connection_ref(conn);

	DBG("connection %p", connection);

	g_dbus_register_interface(connection, SEEL_MANAGER_PATH,
						SEEL_MANAGER_INTERFACE,
						manager_methods,
						manager_signals,
						NULL, NULL, NULL);

	return 0;
}

void __seel_manager_cleanup(void)
{
	DBG("");

	g_dbus_unregister_interface(connection, SEEL_MANAGER_PATH,
						SEEL_MANAGER_INTERFACE);

	dbus_connection_unref(connection);
}


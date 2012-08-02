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

static DBusMessage *register_handover_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender, *path;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = __near_agent_handover_register(sender, path);
	if (err < 0)
		return __near_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *unregister_handover_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender, *path;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = __near_agent_handover_unregister(sender, path);
	if (err < 0)
		return __near_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *register_ndef_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	const char *sender, *path, *type;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __near_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &path);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &type);

	err = __near_agent_ndef_register(sender, path, type);
	if (err < 0)
		return __near_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *unregister_ndef_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	const char *sender, *path, *type;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __near_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &path);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &type);

	err = __near_agent_ndef_unregister(sender, path, type);
	if (err < 0)
		return __near_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable manager_methods[] = {
	{ GDBUS_METHOD("GetProperties",
				NULL, GDBUS_ARGS({"properties", "a{sv}"}),
				get_properties) },
	{ GDBUS_METHOD("SetProperty",
				GDBUS_ARGS({"name", "s"}, {"value", "v"}),
				NULL, set_property) },
	{ GDBUS_METHOD("RegisterHandoverAgent",
			GDBUS_ARGS({ "path", "o" }), NULL,
			register_handover_agent) },
	{ GDBUS_METHOD("UnregisterHandoverAgent",
			GDBUS_ARGS({ "path", "o" }), NULL,
			unregister_handover_agent) },
	{ GDBUS_METHOD("RegisterNDEFAgent",
			GDBUS_ARGS({"path", "o"}, {"type", "s"}),
		        NULL, register_ndef_agent) },
	{ GDBUS_METHOD("UnregisterNDEFAgent",
			GDBUS_ARGS({"path", "o"}, {"type", "s"}),
		        NULL, unregister_ndef_agent) },
	{ },
};

static const GDBusSignalTable manager_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
				GDBUS_ARGS({"name", "s"}, {"value", "v"})) },
	{ GDBUS_SIGNAL("AdapterAdded", GDBUS_ARGS({"adapter", "o" })) },
	{ GDBUS_SIGNAL("AdapterRemoved", GDBUS_ARGS({"adapter", "o" })) },
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

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <glib.h>

#include <gdbus.h>

#include "near.h"

#ifndef DBUS_TIMEOUT_USE_DEFAULT
#define DBUS_TIMEOUT_USE_DEFAULT (-1)
#endif

static DBusConnection *connection = NULL;
static GHashTable *ndef_app_hash;
static GHashTable *ho_agent_hash;

struct near_ndef_agent {
	char *sender;
	char *path;
	char *record_type;
	guint watch;
};

struct near_handover_agent {
	enum ho_agent_carrier carrier;
	guint watch;
	char *sender;
	char *path;
};

static void ndef_agent_free(gpointer data)
{
	struct near_ndef_agent *agent = data;

	DBG("");

	if (!agent || agent->watch == 0)
		return;

	g_dbus_remove_watch(connection, agent->watch);

	g_free(agent->sender);
	g_free(agent->path);
	g_free(agent);
}

static void ndef_agent_release(gpointer key, gpointer data, gpointer user_data)
{
	struct near_ndef_agent *agent = data;
	DBusMessage *message;

	if (!agent)
		return;

	DBG("%s %s", agent->sender, agent->path);

	message = dbus_message_new_method_call(agent->sender, agent->path,
					NFC_NDEF_AGENT_INTERFACE, "Release");
	if (!message)
		return;

	dbus_message_set_no_reply(message, TRUE);

	g_dbus_send_message(connection, message);
}

static void ndef_agent_disconnect(DBusConnection *conn, void *user_data)
{
	struct near_ndef_agent *agent = user_data;

	DBG("agent %s disconnected", agent->path);

	g_hash_table_remove(ndef_app_hash, agent->record_type);
}

static void append_ndef(DBusMessageIter *iter, void *user_data)
{
	GList *records = user_data;

	__near_ndef_append_records(iter, records);
}

static void ndef_agent_push_records(struct near_ndef_agent *agent,
					struct near_ndef_record *record,
							GList *records)
{
	DBusMessageIter iter, dict;
	DBusMessage *message;
	char *path;
	uint8_t *payload;
	size_t payload_len;

	DBG("");

	if (!agent->sender || !agent->path)
		return;

	DBG("Sending NDEF to %s %s", agent->path, agent->sender);

	message = dbus_message_new_method_call(agent->sender, agent->path,
					NFC_NDEF_AGENT_INTERFACE,
					"GetNDEF");
	if (!message)
		return;

	path = __near_ndef_record_get_path(record);
	payload = __near_ndef_record_get_payload(record, &payload_len);

	dbus_message_iter_init_append(message, &iter);

	near_dbus_dict_open(&iter, &dict);
	near_dbus_dict_append_basic(&dict, "Record",
					DBUS_TYPE_STRING, &path);
	near_dbus_dict_append_fixed_array(&dict, "Payload",
				DBUS_TYPE_BYTE, &payload, payload_len);
	near_dbus_dict_append_array(&dict, "NDEF",
				DBUS_TYPE_BYTE, append_ndef, records);
	near_dbus_dict_close(&iter, &dict);

	DBG("sending...");

	dbus_message_set_no_reply(message, TRUE);

	g_dbus_send_message(connection, message);
}

void __near_agent_ndef_parse_records(GList *records)
{
	GList *list;
	struct near_ndef_record *record;
	struct near_ndef_agent *agent;
	char *type;

	DBG("");

	for (list = records, agent = NULL; list; list = list->next) {
		record = list->data;
		type  = __near_ndef_record_get_type(record);

		if (!type)
			continue;

		DBG("Looking for type %s", type);

		agent = g_hash_table_lookup(ndef_app_hash, type);
		if (agent)
			ndef_agent_push_records(agent, record, records);
	}
}

static int ndef_register(const char *sender, const char *path,
						const char *record_type)
{
	struct near_ndef_agent *agent;

	DBG("%s registers path %s for %s", sender, path, record_type);

	if (g_hash_table_lookup(ndef_app_hash, record_type))
		return -EEXIST;

	agent = g_try_malloc0(sizeof(struct near_ndef_agent));
	if (!agent)
		return -ENOMEM;

	agent->sender = g_strdup(sender);
	agent->path = g_strdup(path);
	agent->record_type = g_strdup(record_type);

	if (!agent->sender || !agent->path ||
	    !agent->record_type) {
		g_free(agent);
		return -ENOMEM;
	}

	agent->watch = g_dbus_add_disconnect_watch(connection, sender,
							ndef_agent_disconnect,
							agent, NULL);
	g_hash_table_insert(ndef_app_hash, agent->record_type, agent);

	return 0;
}

static int ndef_unregister(const char *sender, const char *path,
						const char *record_type)
{
	struct near_ndef_agent *agent;

	DBG("sender %s path %s type %s", sender, path, record_type);

	agent = g_hash_table_lookup(ndef_app_hash, record_type);
	if (!agent)
		return -EINVAL;

	if (strcmp(agent->path, path) != 0 || strcmp(agent->sender, sender) != 0)
		return -EINVAL;

	g_hash_table_remove(ndef_app_hash, record_type);

	return 0;
}

static enum carrier_power_state string2cps(const char *state)
{
	if (strcasecmp(state, "active") == 0)
		return CPS_ACTIVE;

	if (strcasecmp(state, "inactive") == 0)
		return CPS_INACTIVE;

	if (strcasecmp(state, "activating") == 0)
		return CPS_ACTIVATING;

	return CPS_UNKNOWN;
}

static enum ho_agent_carrier string2carrier(const char *carrier)
{
	if (strcasecmp(carrier, NEAR_HANDOVER_AGENT_BLUETOOTH) == 0)
		return HO_AGENT_BT;

	if (strcasecmp(carrier, NEAR_HANDOVER_AGENT_WIFI) == 0)
		return HO_AGENT_WIFI;

	return HO_AGENT_UNKNOWN;
}

static struct carrier_data *parse_reply(DBusMessage *reply)
{
	DBusMessageIter args;
	DBusMessageIter data;
	struct carrier_data *c_data;

	c_data = g_try_new0(struct carrier_data, 1);
	if (!c_data)
		return NULL;

	c_data->state = CPS_UNKNOWN;

	dbus_message_iter_init(reply, &args);
	dbus_message_iter_recurse(&args, &data);

	while (dbus_message_iter_get_arg_type(&data) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value;
		DBusMessageIter entry;
		DBusMessageIter array;
		const char *key;
		int var;

		dbus_message_iter_recurse(&data, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);

		if (strcasecmp(key, "State") == 0) {
			const char *state;

			if (var != DBUS_TYPE_STRING)
				goto failed;

			dbus_message_iter_get_basic(&value, &state);

			c_data->state = string2cps(state);
			if (c_data->state == CPS_UNKNOWN)
				goto failed;
		} else if (strcasecmp(key, "EIR") == 0) {
			int size;
			void *oob_data;

			if (var != DBUS_TYPE_ARRAY)
				goto failed;

			dbus_message_iter_recurse(&value, &array);
			dbus_message_iter_get_fixed_array(&array, &oob_data,
									&size);

			if (size > UINT8_MAX || size < 8)
				goto failed;

			memcpy(c_data->data, oob_data, size);
			c_data->size = size;
			c_data->type = BT_MIME_V2_1;
		} else if (strcasecmp(key, "nokia.com:bt") == 0) {
			int size;
			void *oob_data;

			/* prefer EIR over nokia.com:bt */
			if (c_data->type == BT_MIME_V2_1)
				continue;

			dbus_message_iter_recurse(&value, &array);
			dbus_message_iter_get_fixed_array(&array, &oob_data,
									&size);

			if (size > UINT8_MAX || size < 8)
				goto failed;

			memcpy(c_data->data, oob_data, size);
			c_data->size = size;
			c_data->type = BT_MIME_V2_1;
		} else if (strcasecmp(key, "WSC") == 0) {
			int size;
			void *oob_data;

			if (var != DBUS_TYPE_ARRAY)
				goto failed;

			dbus_message_iter_recurse(&value, &array);
			dbus_message_iter_get_fixed_array(&array, &oob_data,
									&size);
			memcpy(c_data->data, oob_data, size);
			c_data->size = size;
			c_data->type = WIFI_WSC_MIME;
		}

		dbus_message_iter_next(&data);
	}

	/* State can be present only if EIR or nokia.com:bt is also present */
	if (c_data->state != CPS_UNKNOWN && c_data->size == 0)
		goto failed;

	return c_data;

failed:
	g_free(c_data);
	return NULL;
}

static const char *cps2string[] = {
	"inactive",
	"active",
	"activating",
};

static void prepare_data(DBusMessage *message, struct carrier_data *data)
{
	DBusMessageIter iter;
	DBusMessageIter dict;
	char *name = NULL;

	DBG("data %p", data);

	dbus_message_iter_init_append(message, &iter);

	near_dbus_dict_open(&iter, &dict);

	if (data) {
		void *pdata = data->data;

		switch (data->type) {
		case BT_MIME_V2_1:
			name = "EIR";
			break;

		case BT_MIME_V2_0:
			name = "nokia.com:bt";
			break;

		case WIFI_WSC_MIME:
			name = "WSC";
			break;
		}

		near_dbus_dict_append_fixed_array(&dict, name, DBUS_TYPE_BYTE,
							&pdata, data->size);

		if (data->state != CPS_UNKNOWN) {
			const char *state = cps2string[data->state];

			near_dbus_dict_append_basic(&dict, "State",
						DBUS_TYPE_STRING, &state);
		}
	}

	near_dbus_dict_close(&iter, &dict);
}

struct carrier_data *__near_agent_handover_request_data(
					enum ho_agent_carrier carrier,
					struct carrier_data *data)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusError error;
	struct carrier_data *data_reply;
	struct near_handover_agent *agent = NULL;

	agent = g_hash_table_lookup(ho_agent_hash,
				GINT_TO_POINTER(carrier));
	if (!agent)
		return NULL;

	message = dbus_message_new_method_call(agent->sender,
			agent->path, NFC_HANDOVER_AGENT_INTERFACE,
			"RequestOOB");
	if (!message)
		return NULL;

	prepare_data(message, data);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
					DBUS_TIMEOUT_USE_DEFAULT, &error);

	dbus_message_unref(message);

	if (!reply) {
		if (dbus_error_is_set(&error)) {
			near_error("RequestOOB failed: %s", error.message);
			dbus_error_free(&error);
		} else {
			near_error("RequestOOB failed");
		}
		return NULL;
	}

	data_reply = parse_reply(reply);

	dbus_message_unref(reply);

	DBG("OOB data %p", data_reply);

	return data_reply;
}

int __near_agent_handover_push_data(enum ho_agent_carrier carrier,
					struct carrier_data *data)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusError error;
	struct near_handover_agent *agent = NULL;

	agent = g_hash_table_lookup(ho_agent_hash, GINT_TO_POINTER(carrier));
	if (!agent)
		return -ESRCH;

	message = dbus_message_new_method_call(agent->sender,
			agent->path, NFC_HANDOVER_AGENT_INTERFACE,
			"PushOOB");
	if (!message)
		return -ENOMEM;

	prepare_data(message, data);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
					DBUS_TIMEOUT_USE_DEFAULT, &error);

	dbus_message_unref(message);

	if (reply) {
		dbus_message_unref(reply);
		return 0;
	}

	if (dbus_error_is_set(&error)) {
			near_error("PushOOB failed: %s", error.message);
			dbus_error_free(&error);
	} else {
		near_error("PushOOB failed");
	}

	return -EIO;
}

static void handover_agent_free(gpointer data)
{
	struct near_handover_agent *agent = data;

	if (!agent)
		return;

	g_free(agent->sender);
	agent->sender = NULL;

	g_free(agent->path);
	agent->path = NULL;

	if (agent->watch == 0)
		return;

	g_dbus_remove_watch(connection, agent->watch);
	agent->watch = 0;

	g_free(agent);
}

static void handover_agent_disconnect(DBusConnection *conn, void *data)
{
	struct near_handover_agent *agent = data;

	DBG("data %p", data);

	if (!agent)
		return;

	switch (agent->carrier) {
	case HO_AGENT_BT:
		/* start watching for legacy bluez */
		__near_bluetooth_legacy_start();
		break;

	case HO_AGENT_WIFI:
	case HO_AGENT_UNKNOWN:
		break;
	}

	handover_agent_free(agent);
}

static void handover_agent_release(gpointer key, gpointer data,
					gpointer user_data)
{
	struct near_handover_agent *agent = data;
	DBusMessage *message;

	if (!agent || agent->watch == 0)
		return;

	message = dbus_message_new_method_call(agent->sender, agent->path,
					"org.neard.HandoverAgent",
					"Release");
	if (message)
		g_dbus_send_message(connection, message);
}

static int create_handover_agent(const char *sender, const char *path,
					enum ho_agent_carrier carrier)
{
	struct near_handover_agent *agent;

	agent = g_try_malloc0(sizeof(struct near_handover_agent));
	if (!agent)
		return -ENOMEM;

	agent->sender = g_strdup(sender);
	agent->path = g_strdup(path);
	agent->carrier = carrier;
	agent->watch = g_dbus_add_disconnect_watch(connection, sender,
				 handover_agent_disconnect, agent, NULL);

	g_hash_table_insert(ho_agent_hash, GINT_TO_POINTER(carrier), agent);

	DBG("handover agent registered");

	switch (agent->carrier) {
	case HO_AGENT_BT:
		/* stop watching for legacy bluez */
		__near_bluetooth_legacy_stop();
		break;

	case HO_AGENT_WIFI:
	case HO_AGENT_UNKNOWN:
		break;
	}

	return 0;
}

static int handover_register(const char *sender, const char *path,
						const char *carrier)
{
	struct near_handover_agent *agent;
	enum ho_agent_carrier ho_carrier;

	DBG("sender %s path %s carrier %s", sender, path, carrier);

	ho_carrier = string2carrier(carrier);

	if (ho_carrier == HO_AGENT_UNKNOWN)
		return -EINVAL;

	agent = g_hash_table_lookup(ho_agent_hash, GINT_TO_POINTER(ho_carrier));
	if (agent)
		return -EEXIST;

	return create_handover_agent(sender, path, ho_carrier);
}

static int handover_unregister(const char *sender, const char *path,
						const char *carrier)
{
	struct near_handover_agent *agent;
	enum ho_agent_carrier ho_carrier;

	DBG("sender %s path %s carrier %s", sender, path, carrier);

	ho_carrier = string2carrier(carrier);
	agent = g_hash_table_lookup(ho_agent_hash, GINT_TO_POINTER(ho_carrier));
	if (!agent)
		return -ESRCH;

	if (strcmp(agent->path, path) != 0 ||
			strcmp(agent->sender, sender) != 0)
		return -ESRCH;

	g_hash_table_remove(ho_agent_hash, GINT_TO_POINTER(ho_carrier));

	return 0;
}

bool __near_agent_handover_registered(enum ho_agent_carrier carrier)
{
	struct near_handove_agent *agent = NULL;

	agent = g_hash_table_lookup(ho_agent_hash, GINT_TO_POINTER(carrier));

	return agent ? TRUE : FALSE;
}

static DBusMessage *register_handover_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	const char *sender, *path, *carrier;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	if (!dbus_message_iter_init(msg, &iter))
		return __near_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &path);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &carrier);

	err = handover_register(sender, path, carrier);
	if (err < 0)
		return __near_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *unregister_handover_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	const char *sender, *path, *carrier;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	if (!dbus_message_iter_init(msg, &iter))
		return __near_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &path);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &carrier);

	err = handover_unregister(sender, path, carrier);
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

	if (!dbus_message_iter_init(msg, &iter))
		return __near_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &path);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &type);

	err = ndef_register(sender, path, type);
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

	if (!dbus_message_iter_init(msg, &iter))
		return __near_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &path);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &type);

	err = ndef_unregister(sender, path, type);
	if (err < 0)
		return __near_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable manager_methods[] = {
	{ GDBUS_METHOD("RegisterHandoverAgent",
			GDBUS_ARGS({ "path", "o" }, { "type", "s"}),
			NULL, register_handover_agent) },
	{ GDBUS_METHOD("UnregisterHandoverAgent",
			GDBUS_ARGS({ "path", "o" }, { "type", "s"}),
			NULL, unregister_handover_agent) },
	{ GDBUS_METHOD("RegisterNDEFAgent",
			GDBUS_ARGS({"path", "o"}, {"type", "s"}),
			NULL, register_ndef_agent) },
	{ GDBUS_METHOD("UnregisterNDEFAgent",
			GDBUS_ARGS({"path", "o"}, {"type", "s"}),
			NULL, unregister_ndef_agent) },
	{ },
};

int __near_agent_init(void)
{
	DBG("");

	connection = near_dbus_get_connection();
	if (!connection)
		return -1;

	g_dbus_register_interface(connection, NFC_PATH,
						NFC_AGENT_MANAGER_INTERFACE,
						manager_methods,
						NULL, NULL, NULL, NULL);

	/*
	 * Legacy interface, for backward compatibility only.
	 * To be removed after 0.16.
	 */
	g_dbus_register_interface(connection, "/", "org.neard.Manager",
						manager_methods,
						NULL, NULL, NULL, NULL);


	ndef_app_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, ndef_agent_free);

	ho_agent_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
						NULL, handover_agent_free);

	return 0;
}

void __near_agent_cleanup(void)
{
	DBG("");

	g_hash_table_foreach(ndef_app_hash, ndef_agent_release, NULL);
	g_hash_table_destroy(ndef_app_hash);
	ndef_app_hash = NULL;

	g_hash_table_foreach(ho_agent_hash, handover_agent_release, NULL);
	g_hash_table_destroy(ho_agent_hash);
	ho_agent_hash = NULL;

	/*
	 * Legacy interface, for backward compatibility only.
	 * To be removed after 0.16.
	 */
	g_dbus_unregister_interface(connection, "/", "org.neard.Manager");

	g_dbus_unregister_interface(connection, NFC_PATH,
						NFC_AGENT_MANAGER_INTERFACE);


	dbus_connection_unref(connection);
}

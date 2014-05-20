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
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <gdbus.h>

#include "driver.h"
#include "seel.h"

struct seel_channel {
	char *path;

	struct seel_se *se;
	uint8_t channel;
	uint8_t *aid;
	size_t aid_len;
	bool basic;
};

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct seel_channel *channel = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	near_dbus_dict_open(&array, &dict);

	near_dbus_dict_append_basic(&dict, "Basic",
					DBUS_TYPE_BOOLEAN, &channel->basic);

	near_dbus_dict_append_fixed_array(&dict, "AID", DBUS_TYPE_BYTE,
						&channel->aid, channel->aid_len);

	near_dbus_dict_close(&array, &dict);

	return reply;
}

static void send_apdu_cb(void *context,
			uint8_t *apdu, size_t apdu_length,
			int err)
{
	DBusMessage *pending_msg = context;
	DBusConnection *conn;

	conn = near_dbus_get_connection();

	if (err) {
		DBusMessage *reply;

		reply = __near_error_failed(pending_msg, -err);

		g_dbus_send_message(conn, reply);
		dbus_message_unref(pending_msg);

		return;
	}

	g_dbus_send_reply(conn, pending_msg,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
				&apdu, apdu_length,
				DBUS_TYPE_INVALID);

	dbus_message_unref(pending_msg);

	DBG("");
}

static DBusMessage *send_apdu(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct seel_channel *channel = data;
	DBusMessage *pending_msg;
	struct seel_apdu *send_apdu;
	uint8_t *apdu, *app_hash;
	const GSList *app_hashes, *list;
	size_t apdu_len;
	const char *sender;
	int err;

	DBG("conn %p", conn);

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
					&apdu, &apdu_len, DBUS_TYPE_INVALID))
		return __near_error_invalid_arguments(msg);

	sender = dbus_message_get_sender(msg);
	app_hashes = __seel_se_get_hashes(channel->se, sender);

	for (list = app_hashes; list; list = list->next) {
		app_hash = list->data;

		if (__seel_ace_apdu_allowed(channel, app_hash, apdu, apdu_len))
			goto send_data;
	}

	near_error("*** APDU not allowed ***");
	return __near_error_permission_denied(msg);

send_data:
	pending_msg = dbus_message_ref(msg);

	send_apdu = __seel_apdu_build(apdu, apdu_len, channel->channel);
	if (!send_apdu) {
		dbus_message_unref(pending_msg);
		return __near_error_out_of_memory(msg);
	}

	err = __seel_se_queue_io(channel->se, send_apdu,
					send_apdu_cb, pending_msg);
	if (err < 0) {
		near_error("send apdu error %d", err);
		return NULL;
	}

	return NULL;
}

static const GDBusMethodTable channel_methods[] = {
	{ GDBUS_METHOD("GetProperties",
				NULL, GDBUS_ARGS({"properties", "a{sv}"}),
				get_properties) },
	{ GDBUS_ASYNC_METHOD("SendAPDU",
				GDBUS_ARGS({"apdu", "ay"}),
				GDBUS_ARGS({"resp", "ay"}),
				send_apdu) },
	{ },
};

static const GDBusSignalTable channel_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
				GDBUS_ARGS({"name", "s"}, {"value", "v"})) },
	{ }
};

struct seel_channel *__seel_channel_add(struct seel_se *se, uint8_t chn,
				uint8_t *aid, size_t aid_len, bool basic)
{
	struct seel_channel *channel;
	const char *se_path;
	char *path;
	DBusConnection *conn;

	DBG("");

	conn = near_dbus_get_connection();

	se_path = __seel_se_get_path(se);
	if (!se_path)
		return NULL;

	path = g_try_malloc0(strlen(se_path) + 16);
	if (!path)
		return NULL;

	g_snprintf(path, strlen(se_path) + 16, "%s/channel%d", se_path, chn);

	DBG("%s", path);

	channel = g_try_malloc0(sizeof(struct seel_channel));
	if (!channel) {
		g_free(path);
		return NULL;
	}

	if (aid && aid_len) {
	    channel->aid = g_try_malloc0(aid_len);
	    if (!channel->aid) {
		    g_free(path);
		    g_free(channel);
		    return NULL;
	    }

	    memcpy(channel->aid, aid, aid_len);
	}

	channel->aid_len = aid_len;
	channel->se = se;
	channel->path = path;
	channel->basic = basic;
	channel->channel = chn;

	g_dbus_register_interface(conn, channel->path,
					SEEL_CHANNEL_INTERFACE,
					channel_methods, channel_signals,
					NULL, channel, NULL);

	return channel;
}

void __seel_channel_remove(struct seel_channel *channel)
{
	DBusConnection *conn;

	DBG("");

	conn = near_dbus_get_connection();

	g_dbus_unregister_interface(conn, channel->path,
						SEEL_CHANNEL_INTERFACE);

	g_free(channel->path);
	g_free(channel->aid);
	g_free(channel);
}

char *__seel_channel_get_path(struct seel_channel *channel)
{
	return channel->path;
}

uint8_t __seel_channel_get_channel(struct seel_channel *channel)
{
	return channel->channel;
}

uint8_t *__seel_channel_get_aid(struct seel_channel *channel, size_t *aid_len)
{
	if (!channel->aid || !channel->aid_len)
		return NULL;

	*aid_len = channel->aid_len;

	return channel->aid;
}

struct seel_se *__seel_channel_get_se(struct seel_channel *channel)
{
	return channel->se;
}

bool __seel_channel_is_basic(struct seel_channel *channel)
{
	return channel->basic;
}

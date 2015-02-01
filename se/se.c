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
#include "driver.h"

#include "seel.h"

static DBusConnection *connection;

static GHashTable *se_hash;

struct seel_se {
	char *path;

	uint8_t ctrl_idx;
	uint8_t se_idx;

	enum seel_se_type se_type;
	enum seel_controller_type ctrl_type;

	struct seel_ctrl_driver *ctrl_driver;
	struct seel_io_driver *io_driver;
	struct seel_cert_driver *cert_driver;

	bool ioreq_pending;
	GList *ioreq_list;

	struct seel_channel *basic_channel;
	GHashTable *channel_hash;

	bool enabled;
};

struct seel_se_ioreq {
	struct seel_se *se;
	struct seel_apdu *apdu;
	void *context;
	transceive_cb_t cb;
};

static int send_io(struct seel_se *se);

static void se_free(gpointer data)
{
	struct seel_se *se = data;

	g_free(se->path);
}

static void se_channel_free(gpointer data)
{
	struct seel_channel *channel = data;

	__seel_channel_remove(channel);
}

static void append_path(gpointer key, gpointer value, gpointer user_data)
{
	struct seel_se *se = value;
	DBusMessageIter *iter = user_data;

	DBG("%s", se->path);

	if (se->path == NULL)
		return;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&se->path);
}

void __seel_se_list(DBusMessageIter *iter, void *user_data)
{
	g_hash_table_foreach(se_hash, append_path, iter);
}

static gboolean send_io_bh(gpointer user_data)
{
	struct seel_se *se = user_data;

	send_io(se);

	return FALSE;
}

static void io_cb(void *context,
			uint8_t *apdu, size_t apdu_length, int err)
{
	struct seel_se_ioreq *req = context;
	struct seel_se *se = req->se;

	DBG("%zd %d", apdu_length, err);

	/* Check response status */
	if (!err)
		err = __seel_apdu_resp_status(apdu, apdu_length);

	if (req->cb)
		req->cb(req->context, apdu, apdu_length, err);

	__seel_apdu_free(req->apdu);
	g_free(req);

	se->ioreq_pending = false;

	/*
	 * Process the next request after the callback is
	 * completely done, otherwise we may hit callback
	 * reentrance issue whenever the callback queues
	 * some request as well.
	 */
	g_idle_add(send_io_bh, se);
}

static int send_io(struct seel_se *se)
{
	GList *first;
	struct seel_se_ioreq *req;

	DBG("");

	se->ioreq_pending = true;

	first = g_list_first(se->ioreq_list);
	if (first == NULL) {
		DBG("No more pending requests");
		se->ioreq_pending = false;
		return -EIO;
	}

	req = first->data;

	se->ioreq_list = g_list_remove(se->ioreq_list, req);

	__seel_apdu_dump(__seel_apdu_data(req->apdu),
				__seel_apdu_length(req->apdu));

	if (se->io_driver && se->io_driver->transceive)
		return se->io_driver->transceive(se->ctrl_idx, se->se_idx,
						__seel_apdu_data(req->apdu),
						__seel_apdu_length(req->apdu),
						io_cb, req);

	return -EIO;
}

int __seel_se_queue_io(struct seel_se *se, struct seel_apdu *apdu,
					transceive_cb_t cb, void *context)
{
	struct seel_se_ioreq *req;

	DBG("Pending req %d", se->ioreq_pending);

	req = g_try_malloc0(sizeof(struct seel_se_ioreq));
	if (req == NULL) {
		cb(context, NULL, 0, -ENOMEM);
		__seel_apdu_free(apdu);
		return -ENOMEM;
	}

	req->se = se;
	req->apdu = apdu;
	req->context = context;
	req->cb = cb;

	se->ioreq_list = g_list_append(se->ioreq_list, req);

	if (se->ioreq_pending == true)
		return 0;

	return send_io(se);
}

static char *ctrl_to_string(enum seel_controller_type ctrl_type)
{
	switch (ctrl_type) {
	case SEEL_CONTROLLER_NFC:
		return "nfc";
	case SEEL_CONTROLLER_MODEM:
		return "modem";
	case SEEL_CONTROLLER_ASSD:
		return "assd";
	case SEEL_CONTROLLER_PCSC:
		return "pcsc";
	case SEEL_CONTROLLER_UNKNOWN:
		return NULL;
	}

	return NULL;
}

static char *se_to_string(enum seel_se_type se_type)
{
	switch (se_type) {
	case SEEL_SE_NFC:
		return "eSE";
	case SEEL_SE_ASSD:
		return "sdio";
	case SEEL_SE_PCSC:
		return "pcsc";
	case SEEL_SE_UICC:
		return "uicc";
	case SEEL_SE_UNKNOWN:
		return NULL;
	}

	return NULL;
}

static char *se_path(uint32_t se_idx, uint8_t ctrl_idx,
			uint8_t se_type, uint8_t ctrl_type)
{
	char *ctrl, *type;

	ctrl = ctrl_to_string(ctrl_type);
	if (ctrl == NULL)
		return NULL;

	type = se_to_string(se_type);
	if (type == NULL)
		return NULL;

	return g_strdup_printf("%s/se/%s%d_%s_se%d", SEEL_PATH,
					ctrl, ctrl_idx, type, se_idx);
}

struct seel_se *__seel_se_get(uint32_t se_idx, uint8_t ctrl_idx,
						uint8_t ctrl_type)
{
	struct seel_se *se;
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, se_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		se = value;

		if (se->ctrl_idx == ctrl_idx &&
				se->se_idx == se_idx &&
				se->ctrl_type == ctrl_type)
			return se;
	}

	return NULL;
}

const char *__seel_se_get_path(struct seel_se *se)
{
	return se->path;
}

const GSList *__seel_se_get_hashes(struct seel_se *se, const char *owner)
{
	pid_t pid;

	if (se->cert_driver == NULL)
		return NULL;

//	pid = g_dbus_get_pid_sync(connection, owner);
	pid = 0;

	DBG("app pid %d", pid);

	if (pid < 0)
		return NULL;

	return se->cert_driver->get_hashes(pid);
}

static int se_toggle(struct seel_se *se, bool enable)
{
	DBG("");

	if (se->ctrl_driver == NULL) {
		near_error("No controller driver");
		return -EOPNOTSUPP;
	}

	if (enable)
		return se->ctrl_driver->enable_se(se->ctrl_idx, se->se_idx);
	else
		return se->ctrl_driver->disable_se(se->ctrl_idx, se->se_idx);
}

static void append_channel_path(gpointer key, gpointer value,
						gpointer user_data)
{
	struct seel_channel *channel = value;
	DBusMessageIter *iter = user_data;
	const char *channel_path;

	channel_path = __seel_channel_get_path(channel);
	if (!channel_path)
		return;

	DBG("%s", channel_path);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&channel_path);
}

static void append_channels(DBusMessageIter *iter, void *user_data)
{
	struct seel_se *se = user_data;
	const char *basic_channel_path;

	DBG("");

	basic_channel_path = __seel_channel_get_path(se->basic_channel);
	if (!basic_channel_path)
		return;

	DBG("%s", basic_channel_path);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&basic_channel_path);

	g_hash_table_foreach(se->channel_hash, append_channel_path, iter);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct seel_se *se = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	char *se_type = se_to_string(se->se_type);

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	near_dbus_dict_open(&array, &dict);

	near_dbus_dict_append_basic(&dict, "Enabled",
					DBUS_TYPE_BOOLEAN, &se->enabled);

	near_dbus_dict_append_basic(&dict, "Type",
					DBUS_TYPE_STRING, &se_type);

	near_dbus_dict_append_array(&dict, "Channels",
				DBUS_TYPE_OBJECT_PATH, append_channels, se);

	near_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct seel_se *se = data;
	DBusMessageIter iter, value;
	const char *name;
	int type, err;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __near_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "Enabled") == TRUE) {
		bool enabled;

		if (type != DBUS_TYPE_BOOLEAN)
			return __near_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &enabled);

		err = se_toggle(se, enabled);
		if (err < 0) {
			if (err == -EALREADY) {
				if (se->enabled != enabled)
					goto ignore_err;

				if (enabled)
					return __near_error_already_enabled(msg);
				else
					return __near_error_already_disabled(msg);
			}

			return __near_error_failed(msg, -err);
		}

ignore_err:
		se->enabled = enabled;

		if (enabled)
			g_idle_add(__seel_ace_add, se);
	} else {
		return __near_error_invalid_property(msg);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

struct open_channel_context {
	DBusMessage *msg;
	struct seel_se *se;
	unsigned char *aid;
	int aid_len;
	uint8_t channel;
};

static void open_channel_error(struct open_channel_context *ctx, int err)
{
	DBusMessage *reply;
	DBusConnection *conn;

	near_error("error %d", err);

	conn = near_dbus_get_connection();

	reply = __near_error_failed(ctx->msg, -err);
	if (reply != NULL)
		g_dbus_send_message(conn, reply);

	dbus_message_unref(ctx->msg);
	ctx->msg = NULL;
	g_free(ctx);
}

static void select_aid_cb(void *context,
			uint8_t *apdu, size_t apdu_length,
			int err)
{
	struct open_channel_context *ctx = context;
	struct seel_apdu *close_channel;
	struct seel_channel *channel;
	char *path;
	DBusConnection *conn;
	int ret;

	conn = near_dbus_get_connection();

	if (err != 0) {
		/*
		 * err != 0 means SW != 9000.
		 * In this case, we need to clean the previously
		 * allocated logical channel.
		 */
		close_channel = __seel_apdu_close_logical_channel(ctx->channel);
		if (!close_channel)
			goto err;

		ret = __seel_se_queue_io(ctx->se, close_channel, NULL, ctx);
		if (ret < 0) {
			near_error("close channel error %d", ret);
			err = ret;
		}

		goto err;
	}

	channel = __seel_channel_add(ctx->se, ctx->channel,
					ctx->aid, ctx->aid_len, false);
	if (!channel) {
		err = -ENOMEM;
		goto err;
	}

	path = __seel_channel_get_path(channel);
	g_hash_table_replace(ctx->se->channel_hash, path, channel);

	g_dbus_send_reply(conn, ctx->msg,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID);

	dbus_message_unref(ctx->msg);
	ctx->msg = NULL;
	g_free(ctx);
	return;

err:
	return open_channel_error(ctx, err);
}

static void open_channel_cb(void *context,
			uint8_t *apdu, size_t apdu_length,
			int err)
{
	struct open_channel_context *ctx = context;
	struct seel_apdu *select_aid;

	DBG("");

	if (err || !apdu)
		return open_channel_error(ctx, err);

	/* Check response status */
	err = __seel_apdu_resp_status(apdu, apdu_length);
	if (err) {
		DBG("err %d", err);
		return open_channel_error(ctx, err);
	}

	ctx->channel = apdu[0];

	DBG("Channel %d", ctx->channel);

	select_aid = __seel_apdu_select_aid(ctx->channel,
						ctx->aid, ctx->aid_len);

	/* Send the AID selection APDU */
	err = __seel_se_queue_io(ctx->se, select_aid, select_aid_cb, ctx);
	if (err < 0) {
		near_error("AID err %d", err);
		return;
	}

	return;
}

static DBusMessage *open_channel(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct seel_se *se = data;
	unsigned char *aid;
	int aid_len, err;
	struct open_channel_context *ctx;
	struct seel_apdu *open_channel;

	DBG("");

	if (se->enabled == false)
		return __near_error_failed(msg, ENODEV);

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
					&aid, &aid_len, DBUS_TYPE_INVALID))
		return __near_error_invalid_arguments(msg);

	ctx = g_try_malloc0(sizeof(struct open_channel_context));
	if (ctx == NULL)
		return __near_error_failed(msg, ENOMEM);

	open_channel = __seel_apdu_open_logical_channel();
	if (open_channel == NULL) {
		g_free(ctx);
		return __near_error_failed(msg, ENOMEM);
	}

	ctx->msg = dbus_message_ref(msg);
	ctx->se = se;
	ctx->aid = aid;
	ctx->aid_len = aid_len;

	err = __seel_se_queue_io(se, open_channel, open_channel_cb, ctx);
	if (err < 0) {
		near_error("open channel error %d", err);
		return NULL;
	}

	return NULL;
}

struct close_channel_context {
	DBusMessage *msg;
	struct seel_se *se;
	struct seel_channel *channel;
	uint8_t chn;
};

static void close_channel_error(struct close_channel_context *ctx, int err)
{
	DBusMessage *reply;
	DBusConnection *conn;

	near_error("error %d", err);

	conn = near_dbus_get_connection();

	reply = __near_error_failed(ctx->msg, -err);
	if (reply != NULL)
		g_dbus_send_message(conn, reply);

	dbus_message_unref(ctx->msg);
	ctx->msg = NULL;
	g_free(ctx);
}

static void close_channel_cb(void *context, uint8_t *apdu, size_t apdu_length,
									int err)
{
	struct close_channel_context *ctx = context;
	char *channel_path;
	DBusConnection *conn;

	conn = near_dbus_get_connection();

	if (err)
		return close_channel_error(ctx, err);

	/* Check response status */
	err = __seel_apdu_resp_status(apdu, apdu_length);
	if (err)
		return close_channel_error(ctx, err);

	channel_path = __seel_channel_get_path(ctx->channel);
	if (!g_hash_table_remove(ctx->se->channel_hash, channel_path))
		return close_channel_error(ctx, -ENODEV);

	g_dbus_send_reply(conn, ctx->msg, DBUS_TYPE_INVALID);

	dbus_message_unref(ctx->msg);
	ctx->msg = NULL;
	g_free(ctx);

	return;
}

static DBusMessage *close_channel(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct seel_se *se = data;
	const char *path;
	int err;
	struct close_channel_context *ctx;
	struct seel_apdu *close_channel;

	if (se->enabled == false)
		return __near_error_failed(msg, ENODEV);

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_INVALID))
		return __near_error_invalid_arguments(msg);

	ctx = g_try_malloc0(sizeof(struct open_channel_context));
	if (ctx == NULL)
		return __near_error_failed(msg, ENOMEM);

	ctx->channel = g_hash_table_lookup(se->channel_hash, path);
	if (!ctx->channel) {
		g_free(ctx);
		return __near_error_invalid_arguments(msg);
	}

	ctx->se = se;
	ctx->chn = __seel_channel_get_channel(ctx->channel);

	close_channel = __seel_apdu_close_logical_channel(ctx->chn);
	if (!close_channel) {
		g_free(ctx);
		return __near_error_failed(msg, ENOMEM);
	}

	ctx->msg = dbus_message_ref(msg);

	err = __seel_se_queue_io(se, close_channel, close_channel_cb, ctx);
	if (err < 0) {
		near_error("close channel error %d", err);
		return NULL;
	}

	return NULL;
}

static const GDBusMethodTable se_methods[] = {
	{ GDBUS_METHOD("GetProperties",
				NULL, GDBUS_ARGS({"properties", "a{sv}"}),
				get_properties) },
	{ GDBUS_METHOD("SetProperty",
				GDBUS_ARGS({"name", "s"}, {"value", "v"}),
				NULL, set_property) },
	{ GDBUS_ASYNC_METHOD("OpenChannel",
				GDBUS_ARGS({"aid", "ay"}),
				GDBUS_ARGS({"channel", "o"}),
				open_channel) },
	{ GDBUS_ASYNC_METHOD("CloseChannel",
				GDBUS_ARGS({"channel", "o"}),
				NULL, close_channel) },
	{ },
};

static const GDBusSignalTable se_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
				GDBUS_ARGS({"name", "s"}, {"value", "v"})) },
	{ }
};

char *__seel_se_add(uint32_t se_idx, uint8_t ctrl_idx,
		    uint8_t se_type, uint8_t ctrl_type)
{
	struct seel_se *se;

	se = g_try_malloc0(sizeof(struct seel_se));
	if (se == NULL)
		return NULL;

	se->path = se_path(se_idx, ctrl_idx, se_type, ctrl_type);
	if (se->path == NULL)
		return NULL;

	se->ctrl_idx = ctrl_idx;
	se->se_idx = se_idx;
	se->se_type = se_type;
	se->ctrl_type = ctrl_type;
	se->ctrl_driver = __seel_driver_ctrl_find(ctrl_type);
	se->io_driver = __seel_driver_io_find(se_type);
	se->ioreq_pending = false;
	se->cert_driver = __seel_driver_cert_get();
	se->basic_channel = __seel_channel_add(se, 0, NULL, 0, true);
	se->channel_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, se_channel_free);
	se->enabled = false;

	g_hash_table_replace(se_hash, se->path, se);

	g_dbus_register_interface(connection, se->path,
					SEEL_SE_INTERFACE,
					se_methods, se_signals,
					NULL, se, NULL);

	return se->path;
}

int __seel_se_remove(uint32_t se_idx, uint8_t ctrl_idx,
					uint8_t ctrl_type)
{
	struct seel_se *se;

	se = __seel_se_get(se_idx, ctrl_idx, ctrl_type);
	if (se == NULL)
		return -ENODEV;

	__seel_ace_remove(se);

	__seel_channel_remove(se->basic_channel);
	g_hash_table_destroy(se->channel_hash);

	g_dbus_unregister_interface(connection, se->path,
						SEEL_SE_INTERFACE);

	if (!g_hash_table_remove(se_hash, se->path))
		return -ENODEV;

	return 0;
}

int __seel_se_init(DBusConnection *conn)
{
	DBG("");

	connection = dbus_connection_ref(conn);

	se_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, se_free);

	return 0;
}

void __seel_se_cleanup(void)
{
	DBG("");

	dbus_connection_unref(connection);

	g_hash_table_destroy(se_hash);
	se_hash = NULL;
}

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
#include <unistd.h>
#include <errno.h>

#include <glib.h>

#include <gdbus.h>

#include "near.h"

static DBusConnection *connection = NULL;

static GHashTable *adapter_hash;

struct near_adapter {
	char *path;

	char *name;
	uint32_t idx;
	uint32_t protocols;

	near_bool_t powered;
	near_bool_t polling;

	GList *target_list;
	struct near_target *active_target;
	int active_sock;

	GIOChannel *channel;
	guint watch;
	GList *ioreq_list;
};

struct near_adapter_ioreq {
	uint32_t target_idx;
	near_recv cb;
	unsigned char buf[1024];
	size_t len;
	void *data;
};

/* HACK HACK */
#define AF_NFC 39

static void free_adapter(gpointer data)
{
	struct near_adapter *adapter = data;

	g_free(adapter->name);
	g_free(adapter->path);
	g_free(adapter);
}

static void polling_changed(struct near_adapter *adapter)
{

	near_dbus_property_changed_basic(adapter->path,
				NFC_ADAPTER_INTERFACE, "Polling",
					DBUS_TYPE_BOOLEAN, &adapter->polling);
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

static void append_protocols(DBusMessageIter *iter, void *user_data)
{
	struct near_adapter *adapter = user_data;
	const char *str;

	DBG("protocols 0x%x", adapter->protocols);

	if (adapter->protocols & NFC_PROTO_FELICA_MASK) {
		str = "Felica";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (adapter->protocols & NFC_PROTO_MIFARE_MASK) {
		str = "MIFARE";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (adapter->protocols & NFC_PROTO_JEWEL_MASK) {
		str = "Jewel";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (adapter->protocols & NFC_PROTO_ISO14443_MASK) {
		str = "ISO-DEP";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (adapter->protocols & NFC_PROTO_NFC_DEP_MASK) {
		str = "NFC-DEP";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}
}

static void append_targets(DBusMessageIter *iter, void *user_data)
{
	struct near_adapter *adapter = user_data;
	GList *list;

	DBG("");

	for (list = adapter->target_list; list; list = list->next) {
		struct near_target *target = list->data;
		const char *target_path;

		target_path = __near_target_get_path(target);

		if (target_path == NULL)
			continue;

		dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&target_path);
	}
}

static void targets_changed(struct near_adapter *adapter)
{
	near_dbus_property_changed_array(adapter->path,
				NFC_ADAPTER_INTERFACE, "Targets",
				DBUS_TYPE_OBJECT_PATH, append_targets,
				adapter);
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

	near_dbus_dict_append_basic(&dict, "Polling",
				    DBUS_TYPE_BOOLEAN, &adapter->polling);

	near_dbus_dict_append_array(&dict, "Protocols",
				DBUS_TYPE_STRING, append_protocols, adapter);

	near_dbus_dict_append_array(&dict, "Targets",
				DBUS_TYPE_OBJECT_PATH, append_targets, adapter);

	near_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("conn %p", conn);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *start_poll(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_adapter *adapter = data;
	int err;

	DBG("conn %p", conn);

	err = __near_netlink_start_poll(adapter->idx, adapter->protocols);
	if (err < 0)
		return __near_error_failed(msg, -err);

	adapter->polling = TRUE;

	polling_changed(adapter);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *stop_poll(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_adapter *adapter = data;
	int err;

	DBG("conn %p", conn);

	err = __near_netlink_stop_poll(adapter->idx);
	if (err < 0)
		return __near_error_failed(msg, -err);

	adapter->polling = FALSE;

	polling_changed(adapter);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable adapter_methods[] = {
	{ "GetProperties",     "",      "a{sv}", get_properties     },
	{ "SetProperty",       "sv",    "",      set_property       },
	{ "StartPoll",         "",      "",      start_poll         },
	{ "StopPoll",          "",      "",      stop_poll          },
	{ },
};

static GDBusSignalTable adapter_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ "TargetFound",		"o"	},
	{ "TargetLost",			"o"	},
	{ }
};

struct near_adapter * __near_adapter_create(uint32_t idx,
					const char *name, uint32_t protocols)
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
	adapter->active_target = NULL;
	adapter->active_sock = -1;

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

struct near_adapter *__near_adapter_get(uint32_t idx)
{
	return g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
}

int __near_adapter_add(struct near_adapter *adapter)
{
	uint32_t idx = adapter->idx;

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

int __near_adapter_add_target(uint32_t idx, struct near_target *target)
{
	struct near_adapter *adapter;
	uint32_t target_idx;

	DBG("idx %d", idx);

	target_idx = __near_target_get_idx(target);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	adapter->target_list = g_list_prepend(adapter->target_list, target);

	adapter->polling = FALSE;

	polling_changed(adapter);

	targets_changed(adapter);

	__near_tag_read(target);

	return 0;
}

int __near_adapter_remove_target(uint32_t idx, struct near_target *target)
{
	struct near_adapter *adapter;
	uint32_t target_idx;

	DBG("idx %d", idx);

	target_idx = __near_target_get_idx(target);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	if (adapter->active_target == target) {
		if (adapter->active_sock != -1)
			close(adapter->active_sock);
		adapter->active_target = NULL;
	}

	adapter->target_list = g_list_remove(adapter->target_list, target);

	return 0;
}

static struct near_target *find_target(struct near_adapter *adapter,
						uint32_t target_idx)
{
	GList *list;

	for (list = adapter->target_list; list; list = list->next) {
		struct near_target *target = list->data;
		uint32_t idx;

		idx = __near_target_get_idx(target);
		if (idx == target_idx)
			return target;

	}

	return NULL;
}

struct near_target *near_adapter_last_target(uint32_t idx)
{
	struct near_adapter *adapter;
	GList *list;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return NULL;

	list = g_list_first(adapter->target_list);
	if (list == NULL)
		return NULL;

	return list->data;
}

static void adapter_flush_rx(struct near_adapter *adapter, int error)
{
	GList *list;

	for (list = adapter->ioreq_list; list; list = list->next) {
		struct near_adapter_ioreq *req = list->data;

		if (req == NULL)
			continue;

		req->cb(NULL, error, req->data);
		g_free(req);
	}

	g_list_free(adapter->ioreq_list);
	adapter->ioreq_list = NULL;
}

static gboolean execute_recv_cb(gpointer user_data)
{
	struct near_adapter_ioreq *req = user_data;

	DBG("data %p", req->data);

	req->cb(req->buf, req->len, req->data);

	g_free(req);

	return FALSE;
}

static gboolean adapter_recv_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct near_adapter *adapter = user_data;
	struct near_adapter_ioreq *req;
	GList *first;
	int sk;

	DBG("condition 0x%x", condition);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		near_error("Error while reading NFC bytes");

		adapter_flush_rx(adapter, -EIO);
		adapter->watch = 0;
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);
	first = g_list_first(adapter->ioreq_list);
	if (first == NULL)
		return TRUE;

	req = first->data;
	req->len = recv(sk, req->buf, sizeof(req->buf), 0);

	adapter->ioreq_list = g_list_remove(adapter->ioreq_list, req);

	g_idle_add(execute_recv_cb, req);

	return TRUE;
}

int near_adapter_connect(uint32_t idx, uint32_t target_idx, uint8_t protocol)
{
	struct near_adapter *adapter;
	struct near_target *target;
	struct sockaddr_nfc addr;
	int err, sock;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	if (adapter->active_target != NULL)
		return -EALREADY;

	target = find_target(adapter, target_idx);
	if (target == NULL)
		return -ENOLINK;

	sock = socket(AF_NFC, SOCK_SEQPACKET, NFC_SOCKPROTO_RAW);
	if (sock == -1)
		return sock;

	addr.sa_family = AF_NFC;
	addr.dev_idx = idx;
	addr.target_idx = target_idx;
	addr.nfc_protocol = protocol;

	err = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (err) {
		close(sock);
		return err;
	}

	adapter->active_target = target;
	adapter->active_sock = sock;

	if (adapter->channel == NULL)
		adapter->channel = g_io_channel_unix_new(adapter->active_sock);

	g_io_channel_set_flags(adapter->channel, G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_close_on_unref(adapter->channel, TRUE);

	if (adapter->watch == 0)
		adapter->watch = g_io_add_watch(adapter->channel,
				G_IO_IN | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
						adapter_recv_event, adapter);

	return 0;
}

int near_adapter_disconnect(uint32_t idx)
{
	struct near_adapter *adapter;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	if (adapter->active_sock == -1)
		return -ENOLINK;

	if (adapter->watch > 0) {
		g_source_remove(adapter->watch);
		adapter->watch = 0;
	}

	adapter->channel = NULL;
	close(adapter->active_sock);
	adapter->active_sock = -1;
	adapter->active_target = NULL;
	adapter_flush_rx(adapter, -ENOLINK);

	return 0;
}

int near_adapter_send(uint32_t idx, uint8_t *buf, size_t length,
			near_recv cb, void *data)
{
	struct near_adapter *adapter;
	struct near_adapter_ioreq *req = NULL;
	int err;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	if (adapter->active_sock == -1)
		return -ENOLINK;

	if (cb != NULL && adapter->watch != 0) {
		req = g_try_malloc0(sizeof(*req));
		if (req == NULL)
			return -ENOMEM;

		DBG("req %p cb %p data %p", req, cb, data);

		req->target_idx = __near_target_get_idx(adapter->active_target);
		req->cb = cb;
		req->data = data;

		adapter->ioreq_list =
			g_list_append(adapter->ioreq_list, req);
	}

	err = send(adapter->active_sock, buf, length, 0);
	if (err < 0)
		goto out_err;

	return err;

out_err:
	if (req != NULL) {
		GList *last = g_list_last(adapter->ioreq_list);

		g_free(req);
		adapter->ioreq_list =
				g_list_delete_link(adapter->ioreq_list, last);
	}

	return err;
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

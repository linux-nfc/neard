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
#include <string.h>

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

	GHashTable *targets;
	struct near_target *link;
	int sock;

	GIOChannel *channel;
	guint watch;
	GList *ioreq_list;
	GList *ndef_q;
};

struct near_adapter_ioreq {
	uint32_t target_idx;
	near_recv cb;
	unsigned char buf[1024];
	size_t len;
	void *data;
};

/* HACK HACK */
#ifndef AF_NFC
#define AF_NFC 39
#endif

static void free_adapter(gpointer data)
{
	struct near_adapter *adapter = data;

	g_free(adapter->name);
	g_free(adapter->path);
	g_free(adapter);
}

static void free_target(gpointer data)
{
	struct near_target *target = data;

	__near_target_remove(target);
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

static void append_target_path(gpointer key, gpointer value, gpointer user_data)
{
	struct near_target *target = value;
	DBusMessageIter *iter = user_data;
	const char *target_path;

	target_path = __near_target_get_path(target);
	if (target_path == NULL)
		return;

	DBG("%s", target_path);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&target_path);
}

static void append_targets(DBusMessageIter *iter, void *user_data)
{
	struct near_adapter *adapter = user_data;

	DBG("");

	g_hash_table_foreach(adapter->targets, append_target_path, iter);
}

void __near_adapter_target_changed(uint32_t adapter_idx)
{
	struct near_adapter *adapter;

	adapter = g_hash_table_lookup(adapter_hash,
				GINT_TO_POINTER(adapter_idx));
	if (adapter == NULL)
		return;

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
	struct near_adapter *adapter = data;
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

	if (g_str_equal(name, "Powered") == TRUE) {
		near_bool_t powered;

		if (type != DBUS_TYPE_BOOLEAN)
			return __near_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &powered);

		err = __near_netlink_adapter_enable(adapter->idx, powered);
		if (err < 0)
			return __near_error_failed(msg, -err);

		adapter->powered = powered;
	} else
		return __near_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *start_poll(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_adapter *adapter = data;
	int err;

	DBG("conn %p", conn);

	if (g_hash_table_size(adapter->targets) > 0) {
		DBG("Clearing targets");

		g_hash_table_remove_all(adapter->targets);
		__near_adapter_target_changed(adapter->idx);
	}

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

static int __push_ndef_queue(struct near_adapter *adapter,
					struct near_ndef_message *ndef)
{
	if (adapter == NULL || ndef == NULL)
		return -EINVAL;

	adapter->ndef_q = g_list_append(adapter->ndef_q, ndef);

	return 0;
}

static struct near_ndef_message *
__pop_ndef_queue(struct near_adapter *adapter)
{
	GList *list;
	struct near_ndef_message *ndef;

	if (adapter == NULL)
		return NULL;

	list = g_list_first(adapter->ndef_q);
	if (list == NULL)
		return NULL;

	ndef = list->data;
	if (ndef != NULL)
		adapter->ndef_q = g_list_remove(adapter->ndef_q, ndef);

	return ndef;
}

static int __publish_text_record(DBusMessage *msg, void *data)
{
	DBusMessageIter iter, arr_iter;
	struct near_ndef_message *ndef;
	char *cod = NULL, *lang = NULL, *rep = NULL;

	DBG("");

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &arr_iter);

	while (dbus_message_iter_get_arg_type(&arr_iter) !=
					DBUS_TYPE_INVALID) {
		const char *key;
		DBusMessageIter ent_iter;
		DBusMessageIter var_iter;

		dbus_message_iter_recurse(&arr_iter, &ent_iter);
		dbus_message_iter_get_basic(&ent_iter, &key);
		dbus_message_iter_next(&ent_iter);
		dbus_message_iter_recurse(&ent_iter, &var_iter);

		switch (dbus_message_iter_get_arg_type(&var_iter)) {
		case DBUS_TYPE_STRING:
			if (g_strcmp0(key, "Encoding") == 0)
				dbus_message_iter_get_basic(&var_iter, &cod);
			else if (g_strcmp0(key, "Language") == 0)
				dbus_message_iter_get_basic(&var_iter, &lang);
			else if (g_strcmp0(key, "Representation") == 0)
				dbus_message_iter_get_basic(&var_iter, &rep);

			break;
		}

		dbus_message_iter_next(&arr_iter);
	}

	ndef = near_ndef_prepare_text_record(cod, lang, rep);
	if (ndef == NULL)
		return -EINVAL;

	return __push_ndef_queue(data, ndef);
}

static void __add_ndef_cb(uint32_t adapter_idx, uint32_t target_idx, int status)
{
	DBG(" %d", status);
	near_adapter_disconnect(adapter_idx);
}

static DBusMessage *publish(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter arr_iter;
	struct near_adapter *adapter = data;

	DBG("conn %p", conn);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &arr_iter);

	while (dbus_message_iter_get_arg_type(&arr_iter) !=
						DBUS_TYPE_INVALID) {
		const char *key, *value;
		DBusMessageIter ent_iter;
		DBusMessageIter var_iter;

		dbus_message_iter_recurse(&arr_iter, &ent_iter);
		dbus_message_iter_get_basic(&ent_iter, &key);

		if (g_strcmp0(key, "Type") == 0) {
			dbus_message_iter_next(&ent_iter);
			dbus_message_iter_recurse(&ent_iter, &var_iter);

			switch (dbus_message_iter_get_arg_type(&var_iter)) {
			case DBUS_TYPE_STRING:
				dbus_message_iter_get_basic(&var_iter, &value);

				if (g_strcmp0(value, "Text") == 0) {
					if (__publish_text_record(msg, adapter)
							< 0)
						goto error;

					goto reply;
				} else {
					DBG(" '%s' not supported", value);
					goto error;
				}

				break;
			}
		}

		dbus_message_iter_next(&arr_iter);
	}

error:
	return g_dbus_create_error(msg, "org.neard.Error.InvalidArguments",
							"Invalid arguments");

reply:
	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable adapter_methods[] = {
	{ "GetProperties",     "",      "a{sv}", get_properties     },
	{ "SetProperty",       "sv",    "",      set_property       },
	{ "StartPoll",         "",      "",      start_poll         },
	{ "StopPoll",          "",      "",      stop_poll          },
	{ "Publish",         "a{sv}",   "",      publish            },
	{ },
};

static GDBusSignalTable adapter_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ "TargetFound",		"o"	},
	{ "TargetLost",			"o"	},
	{ }
};

struct near_adapter * __near_adapter_create(uint32_t idx,
		const char *name, uint32_t protocols, near_bool_t powered)
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
	adapter->powered = powered;
	adapter->targets = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_target);
	adapter->sock = -1;

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

static int dep_link_up(uint32_t idx, uint32_t target_idx)
{
	return __near_netlink_dep_link_up(idx, target_idx,
					NFC_COMM_ACTIVE, NFC_RF_INITIATOR);
}

static void tag_read_cb(uint32_t adapter_idx, uint32_t target_idx, int status)
{
	struct near_adapter *adapter;
	struct near_target *target;
	struct near_ndef_message *ndef, *ndef_with_header = NULL;
	uint16_t tag_type;
	int err;

	if (status < 0)
		goto out;

	__near_adapter_target_changed(adapter_idx);

	/* Check if adapter ndef queue has any ndef messages,
	 * then write the ndef data on tag. */
	adapter = g_hash_table_lookup(adapter_hash,
					GINT_TO_POINTER(adapter_idx));
	if (adapter == NULL)
		goto out;

	if (g_list_length(adapter->ndef_q) == 0)
		goto out;

	target = g_hash_table_lookup(adapter->targets,
					GINT_TO_POINTER(target_idx));
	if (target == NULL)
		goto out;

	ndef = __pop_ndef_queue(adapter);
	if (ndef == NULL)
		goto out;

	tag_type = __near_target_get_tag_type(target);

	/* Add NDEF header information depends upon tag type */
	if (tag_type & NEAR_TAG_NFC_TYPE1 ||
			tag_type & NEAR_TAG_NFC_TYPE2) {
		ndef_with_header = g_try_malloc0(sizeof(
					struct near_ndef_message));
		if (ndef_with_header == NULL)
			goto out;

		ndef_with_header->offset = 0;
		ndef_with_header->length = ndef->length + 3;
		ndef_with_header->data = g_try_malloc0(ndef->length + 3);
		if (ndef_with_header->data == NULL)
			goto out;

		ndef_with_header->data[0] = TLV_NDEF;
		ndef_with_header->data[1] = ndef->length;
		memcpy(ndef_with_header->data + 2, ndef->data, ndef->length);
		ndef_with_header->data[ndef->length + 2] = TLV_END;

	} else if (tag_type & NEAR_TAG_NFC_TYPE3) {
		ndef_with_header = g_try_malloc0(sizeof(
					struct near_ndef_message));
		if (ndef_with_header == NULL)
			goto out;

		ndef_with_header->offset = 0;
		ndef_with_header->length = ndef->length;
		ndef_with_header->data = g_try_malloc0(
						ndef_with_header->length);
		if (ndef_with_header->data == NULL)
			goto out;

		memcpy(ndef_with_header->data, ndef->data, ndef->length);

	} else if (tag_type & NEAR_TAG_NFC_TYPE4) {
		ndef_with_header = g_try_malloc0(sizeof(
					struct near_ndef_message));
		if (ndef_with_header == NULL)
			goto out;

		ndef_with_header->offset = 0;
		ndef_with_header->length = ndef->length + 2;
		ndef_with_header->data = g_try_malloc0(ndef->length + 2);
		if (ndef_with_header->data == NULL)
			goto out;

		ndef_with_header->data[0] = (uint8_t)(ndef->length >> 8);
		ndef_with_header->data[1] = (uint8_t)(ndef->length);
		memcpy(ndef_with_header->data + 2, ndef->data, ndef->length);
	} else
		goto out;

	g_free(ndef->data);
	g_free(ndef);

	err = __near_tag_add_ndef(target, ndef_with_header, __add_ndef_cb);
	if (err < 0) {
		g_free(ndef_with_header->data);
		g_free(ndef_with_header);
		goto out;
	}

	return;

out:
	if (ndef_with_header != NULL) {
		g_free(ndef_with_header->data);
		g_free(ndef_with_header);
	}

	near_adapter_disconnect(adapter_idx);
}

int __near_adapter_add_target(uint32_t idx, uint32_t target_idx,
			uint32_t protocols, uint16_t sens_res, uint8_t sel_res,
			uint8_t *nfcid, uint8_t nfcid_len)
{
	struct near_adapter *adapter;
	struct near_target *target;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	adapter->polling = FALSE;
	polling_changed(adapter);

	/* TODO target reference */
	target = __near_target_add(idx, target_idx, protocols,
					sens_res, sel_res, nfcid, nfcid_len);
	if (target == NULL)
		return -ENODEV;

	g_hash_table_insert(adapter->targets,
			GINT_TO_POINTER(target_idx), target);	

	__near_tag_read(target, tag_read_cb);

	if (protocols & NFC_PROTO_NFC_DEP_MASK)
		dep_link_up(idx, target_idx);

	return 0;
}

int __near_adapter_remove_target(uint32_t idx, uint32_t target_idx)
{
	struct near_adapter *adapter;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	g_hash_table_remove(adapter->targets, GINT_TO_POINTER(target_idx));

	__near_adapter_target_changed(idx);

	return 0;
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
		near_adapter_disconnect(adapter->idx);
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

	if (adapter->sock != -1)
		return -EALREADY;

	target = g_hash_table_lookup(adapter->targets,
				GINT_TO_POINTER(target_idx));
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

	adapter->sock = sock;
	adapter->link = target;

	if (adapter->channel == NULL)
		adapter->channel = g_io_channel_unix_new(adapter->sock);

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

	if (adapter->sock == -1)
		return -ENOLINK;

	if (adapter->watch > 0) {
		g_source_remove(adapter->watch);
		adapter->watch = 0;
	}

	adapter->channel = NULL;
	close(adapter->sock);
	adapter->sock = -1;
	adapter->link = NULL;
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

	if (adapter->sock == -1 || adapter->link == NULL)
		return -ENOLINK;

	if (cb != NULL && adapter->watch != 0) {
		req = g_try_malloc0(sizeof(*req));
		if (req == NULL)
			return -ENOMEM;

		DBG("req %p cb %p data %p", req, cb, data);

		req->target_idx = __near_target_get_idx(adapter->link);
		req->cb = cb;
		req->data = data;

		adapter->ioreq_list =
			g_list_append(adapter->ioreq_list, req);
	}

	err = send(adapter->sock, buf, length, 0);
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
	DBG("");

	g_hash_table_destroy(adapter_hash);
	adapter_hash = NULL;
}

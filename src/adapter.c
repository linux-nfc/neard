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

/* We check for the tag being present every 2 seconds */
#define CHECK_PRESENCE_PERIOD 2

static DBusConnection *connection = NULL;

static GHashTable *adapter_hash;

enum near_adapter_rf_mode {
	NEAR_ADAPTER_RF_MODE_IDLE      = 0,
	NEAR_ADAPTER_RF_MODE_INITIATOR = 1,
	NEAR_ADAPTER_RF_MODE_TARGET    = 2
};

#define NEAR_ADAPTER_MODE_INITIATOR 0x1
#define NEAR_ADAPTER_MODE_TARGET    0x2
#define NEAR_ADAPTER_MODE_DUAL      0x3

struct near_adapter {
	char *path;

	char *name;
	uint32_t idx;
	uint32_t protocols;
	uint32_t poll_mode;
	enum near_adapter_rf_mode rf_mode;

	near_bool_t powered;
	near_bool_t polling;
	near_bool_t constant_poll;
	near_bool_t dep_up;

	GHashTable *tags;
	struct near_tag *tag_link;
	int tag_sock;

	GHashTable *devices;
	struct near_device *device_link;
	int device_sock;

	GIOChannel *channel;
	guint watch;
	GList *ioreq_list;

	guint presence_timeout;
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

	if (adapter->presence_timeout > 0)
		g_source_remove(adapter->presence_timeout);

	g_free(adapter->name);
	g_free(adapter->path);
	g_free(adapter);
}

static void free_tag(gpointer data)
{
	struct near_tag *tag = data;

	__near_tag_remove(tag);
}

static void free_device(gpointer data)
{
	struct near_device *device = data;

	__near_device_remove(device);
}

static char *rf_mode_to_string(struct near_adapter *adapter)
{
	switch (adapter->rf_mode) {
	case NEAR_ADAPTER_RF_MODE_IDLE:
		return "Idle";
	case NEAR_ADAPTER_RF_MODE_INITIATOR:
		return "Initiator";
	case NEAR_ADAPTER_RF_MODE_TARGET:
		return "Target";
	}

	return NULL;
}

static void polling_changed(struct near_adapter *adapter)
{

	near_dbus_property_changed_basic(adapter->path,
					NFC_ADAPTER_INTERFACE, "Polling",
					DBUS_TYPE_BOOLEAN, &adapter->polling);
}

static void rf_mode_changed(struct near_adapter *adapter)
{
	const char *rf_mode = rf_mode_to_string(adapter);

	if (rf_mode == NULL)
		return;

	near_dbus_property_changed_basic(adapter->path,
					NFC_ADAPTER_INTERFACE, "Mode",
					DBUS_TYPE_STRING, &rf_mode);
}

static int adapter_start_poll(struct near_adapter *adapter)
{
	int err;
	uint32_t im_protos, tm_protos;

	if (g_hash_table_size(adapter->tags) > 0) {
		DBG("Clearing tags");

		g_hash_table_remove_all(adapter->tags);
		__near_adapter_tags_changed(adapter->idx);
	}

	if (g_hash_table_size(adapter->devices) > 0) {
		DBG("Clearing devices");

		g_hash_table_remove_all(adapter->devices);
		__near_adapter_devices_changed(adapter->idx);
	}

	DBG("Poll mode 0x%x", adapter->poll_mode);

	im_protos = tm_protos = 0;

	if (adapter->poll_mode & NEAR_ADAPTER_MODE_INITIATOR)
		im_protos = adapter->protocols;

	if (adapter->poll_mode & NEAR_ADAPTER_MODE_TARGET)
		tm_protos = adapter->protocols;

	err = __near_netlink_start_poll(adapter->idx, im_protos, tm_protos);
	if (err < 0)
		return err;

	adapter->polling = TRUE;

	polling_changed(adapter);

	return 0;
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

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);
	}

	if (adapter->protocols & NFC_PROTO_MIFARE_MASK) {
		str = "MIFARE";

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);
	}

	if (adapter->protocols & NFC_PROTO_JEWEL_MASK) {
		str = "Jewel";

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);
	}

	if (adapter->protocols & NFC_PROTO_ISO14443_MASK) {
		str = "ISO-DEP";

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);
	}

	if (adapter->protocols & NFC_PROTO_NFC_DEP_MASK) {
		str = "NFC-DEP";

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);
	}
}

static void append_tag_path(gpointer key, gpointer value, gpointer user_data)
{
	struct near_tag *tag = value;
	DBusMessageIter *iter = user_data;
	const char *tag_path;

	tag_path = __near_tag_get_path(tag);
	if (tag_path == NULL)
		return;

	DBG("%s", tag_path);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &tag_path);
}

static void append_tags(DBusMessageIter *iter, void *user_data)
{
	struct near_adapter *adapter = user_data;

	DBG("");

	g_hash_table_foreach(adapter->tags, append_tag_path, iter);
}

static void append_device_path(gpointer key, gpointer value, gpointer user_data)
{
	struct near_device *device = value;
	DBusMessageIter *iter = user_data;
	const char *device_path;

	device_path = __near_device_get_path(device);
	if (device_path == NULL)
		return;

	DBG("%s", device_path);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&device_path);
}

static void append_devices(DBusMessageIter *iter, void *user_data)
{
	struct near_adapter *adapter = user_data;

	DBG("");

	g_hash_table_foreach(adapter->devices, append_device_path, iter);
}

void __near_adapter_tags_changed(uint32_t adapter_idx)
{
	struct near_adapter *adapter;

	DBG("");

	adapter = g_hash_table_lookup(adapter_hash,
					GINT_TO_POINTER(adapter_idx));
	if (adapter == NULL)
		return;

	near_dbus_property_changed_array(adapter->path,
					NFC_ADAPTER_INTERFACE, "Tags",
					DBUS_TYPE_OBJECT_PATH, append_tags,
					adapter);
}

void __near_adapter_devices_changed(uint32_t adapter_idx)
{
	struct near_adapter *adapter;

	DBG("");

	adapter = g_hash_table_lookup(adapter_hash,
					GINT_TO_POINTER(adapter_idx));
	if (adapter == NULL)
		return;

	near_dbus_property_changed_array(adapter->path,
					NFC_ADAPTER_INTERFACE, "Devices",
					DBUS_TYPE_OBJECT_PATH, append_devices,
					adapter);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_adapter *adapter = data;
	const char *rf_mode;
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

	rf_mode = rf_mode_to_string(adapter);
	if (rf_mode != NULL)
		near_dbus_dict_append_basic(&dict, "Mode",
						DBUS_TYPE_STRING, &rf_mode);

	near_dbus_dict_append_array(&dict, "Protocols",
				DBUS_TYPE_STRING, append_protocols, adapter);

	near_dbus_dict_append_array(&dict, "Tags",
				DBUS_TYPE_OBJECT_PATH, append_tags, adapter);

	near_dbus_dict_append_array(&dict, "Devices",
				DBUS_TYPE_OBJECT_PATH, append_devices, adapter);

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
		if (err < 0) {
			if (err == -EALREADY) {
				if (powered == TRUE)
					return __near_error_already_enabled(msg);
				else
					return __near_error_already_disabled(msg);
			}

			return __near_error_failed(msg, -err);
		}

		adapter->powered = powered;
	} else {
		return __near_error_invalid_property(msg);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *start_poll_loop(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_adapter *adapter = data;
	const char *dbus_mode;
	int err;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &dbus_mode,
							DBUS_TYPE_INVALID);

	DBG("Mode %s", dbus_mode);

	if (g_strcmp0(dbus_mode, "Initiator") == 0)
		adapter->poll_mode = NEAR_ADAPTER_MODE_INITIATOR;
	else if (g_strcmp0(dbus_mode, "Target") == 0)
		adapter->poll_mode = NEAR_ADAPTER_MODE_TARGET;
	else if (g_strcmp0(dbus_mode, "Dual") == 0)
		adapter->poll_mode = NEAR_ADAPTER_MODE_DUAL;
	else
		adapter->poll_mode = NEAR_ADAPTER_MODE_INITIATOR;

	err = adapter_start_poll(adapter);
	if (err < 0)
		return __near_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *stop_poll_loop(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_adapter *adapter = data;
	int err;

	DBG("conn %p", conn);

	if (adapter->polling == FALSE)
		return __near_error_not_polling(msg);

	err = __near_netlink_stop_poll(adapter->idx);
	if (err < 0)
		return __near_error_failed(msg, -err);

	adapter->polling = FALSE;

	polling_changed(adapter);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void tag_present_cb(uint32_t adapter_idx, uint32_t target_idx,
								int status);

static gboolean check_presence(gpointer user_data)
{
	struct near_adapter *adapter = user_data;
	struct near_tag *tag;
	int err;

	DBG("");

	if (adapter == NULL)
		return FALSE;

	tag = adapter->tag_link;
	if (tag == NULL)
		goto out_err;

	err = __near_tag_check_presence(tag, tag_present_cb);
	if (err < 0) {
		DBG("Could not check target presence");
		goto out_err;
	}

	return FALSE;

out_err:
	near_adapter_disconnect(adapter->idx);
	if (adapter->constant_poll == TRUE)
		adapter_start_poll(adapter);

	return FALSE;
}

static void tag_present_cb(uint32_t adapter_idx, uint32_t target_idx,
								int status)
{
	struct near_adapter *adapter;

	DBG("");

	adapter = g_hash_table_lookup(adapter_hash,
					GINT_TO_POINTER(adapter_idx));
	if (adapter == NULL)
		return;

	if (status < 0) {
		DBG("Tag is gone");

		near_adapter_disconnect(adapter->idx);
		if (adapter->constant_poll == TRUE)
			adapter_start_poll(adapter);

		return;
	}

	adapter->presence_timeout =
		g_timeout_add_seconds(CHECK_PRESENCE_PERIOD,
					check_presence, adapter);
}

void __near_adapter_start_check_presence(uint32_t adapter_idx,
						uint32_t target_idx)
{
	struct near_adapter *adapter;

	DBG("");

	adapter = g_hash_table_lookup(adapter_hash,
			GINT_TO_POINTER(adapter_idx));
	if (adapter == NULL)
		return;

	adapter->presence_timeout =
			g_timeout_add_seconds(CHECK_PRESENCE_PERIOD,
					check_presence, adapter);
}

void __near_adapter_stop_check_presence(uint32_t adapter_idx,
						uint32_t target_idx)
{
	struct near_adapter *adapter;

	DBG("");

	adapter = g_hash_table_lookup(adapter_hash,
			GINT_TO_POINTER(adapter_idx));
	if (adapter == NULL)
		return;

	if (adapter->presence_timeout > 0)
		g_source_remove(adapter->presence_timeout);
}

static const GDBusMethodTable adapter_methods[] = {
	{ GDBUS_METHOD("GetProperties",
				NULL, GDBUS_ARGS({"properties", "a{sv}"}),
				get_properties) },
	{ GDBUS_METHOD("SetProperty",
				GDBUS_ARGS({"name", "s"}, {"value", "v"}),
				NULL, set_property) },
	{ GDBUS_METHOD("StartPollLoop", GDBUS_ARGS({"name", "s"}), NULL,
							start_poll_loop) },
	{ GDBUS_METHOD("StopPollLoop", NULL, NULL, stop_poll_loop) },
	{ },
};

static const GDBusSignalTable adapter_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
				GDBUS_ARGS({"name", "s"}, {"value", "v"})) },
	{ GDBUS_SIGNAL("TagFound", GDBUS_ARGS({"address", "o"})) },
	{ GDBUS_SIGNAL("TagLost", GDBUS_ARGS({"address", "o"})) },
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
	adapter->constant_poll = near_setting_get_bool("ConstantPoll");
	adapter->dep_up = FALSE;
	adapter->tags = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_tag);
	adapter->tag_sock = -1;

	adapter->devices = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_device);
	adapter->device_sock = -1;

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

int __near_adapter_set_dep_state(uint32_t idx, near_bool_t dep)
{
	struct near_adapter *adapter;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	adapter->dep_up = dep;

	if (dep == FALSE && adapter->constant_poll == TRUE)
		adapter_start_poll(adapter);

	if (dep == FALSE) {
		uint32_t target_idx;

		target_idx =  __neard_device_get_idx(adapter->device_link);
		__near_adapter_remove_target(idx, target_idx);
	} else {
		__near_adapter_devices_changed(idx);
	}

	return 0;
}

near_bool_t __near_adapter_get_dep_state(uint32_t idx)
{
	struct near_adapter *adapter;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return FALSE;

	return adapter->dep_up;
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

static void tag_read_cb(uint32_t adapter_idx, uint32_t target_idx, int status)
{
	struct near_adapter *adapter;

	DBG("status %d", status);

	adapter = g_hash_table_lookup(adapter_hash,
					GINT_TO_POINTER(adapter_idx));
	if (adapter == NULL)
		return;

	if (status < 0) {
		near_adapter_disconnect(adapter->idx);
		if (adapter->constant_poll == TRUE)
			adapter_start_poll(adapter);

		return;
	}

	__near_adapter_tags_changed(adapter_idx);

	adapter->presence_timeout =
		g_timeout_add_seconds(CHECK_PRESENCE_PERIOD,
					check_presence, adapter);
}

static void device_read_cb(uint32_t adapter_idx, uint32_t target_idx,
								int status)
{
	struct near_adapter *adapter;

	DBG("status %d", status);

	adapter = g_hash_table_lookup(adapter_hash,
					GINT_TO_POINTER(adapter_idx));
	if (adapter == NULL)
		return;

	if (status < 0) {
		if (adapter->device_link != NULL) {
			__near_netlink_dep_link_down(adapter->idx);
			adapter->device_link = NULL;
		}

		if (adapter->constant_poll == TRUE)
			adapter_start_poll(adapter);

		return;
	}
}

static int adapter_add_tag(struct near_adapter *adapter, uint32_t target_idx,
			uint32_t protocols,
			uint16_t sens_res, uint8_t sel_res,
			uint8_t *nfcid, uint8_t nfcid_len)
{
	struct near_tag *tag;
	uint32_t tag_type;
	int err;

	tag = __near_tag_add(adapter->idx, target_idx, protocols,
				sens_res, sel_res,
				nfcid, nfcid_len);
	if (tag == NULL)
		return -ENODEV;

	g_hash_table_insert(adapter->tags, GINT_TO_POINTER(target_idx), tag);

	tag_type = __near_tag_get_type(tag);

	err = near_adapter_connect(adapter->idx, target_idx, tag_type);
	if (err < 0) {
		near_error("Could not connect");
		return err;
	}

	return __near_tag_read(tag, tag_read_cb);
}

static int adapter_add_device(struct near_adapter *adapter,
				uint32_t target_idx,
				uint8_t *nfcid, uint8_t nfcid_len)
{
	struct near_device *device;
	int err;

	device = __near_device_add(adapter->idx, target_idx, nfcid, nfcid_len);
	if (device == NULL)
		return -ENODEV;

	g_hash_table_insert(adapter->devices, GINT_TO_POINTER(target_idx),
								device);

	/* For p2p, reading is listening for an incoming connection */
	err = __near_device_listen(device, device_read_cb);
	if (err < 0) {
		near_error("Could not read device");
		return err;
	}

	adapter->device_link = device;

	if (adapter->dep_up == TRUE)
		return 0;

	err = __near_netlink_dep_link_up(adapter->idx, target_idx,
					NFC_COMM_ACTIVE, NFC_RF_INITIATOR);

	if (err < 0)
		adapter->device_link = NULL;

	return err;
}

int __near_adapter_add_target(uint32_t idx, uint32_t target_idx,
			uint32_t protocols, uint16_t sens_res, uint8_t sel_res,
			uint8_t *nfcid, uint8_t nfcid_len)
{
	struct near_adapter *adapter;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	adapter->polling = FALSE;
	polling_changed(adapter);

	adapter->rf_mode = NEAR_ADAPTER_RF_MODE_INITIATOR;
	rf_mode_changed(adapter);

	if (protocols & NFC_PROTO_NFC_DEP_MASK)
		return adapter_add_device(adapter, target_idx,
						nfcid, nfcid_len);
	else
		return adapter_add_tag(adapter, target_idx, protocols,
					sens_res, sel_res, nfcid, nfcid_len);
}

int __near_adapter_remove_target(uint32_t idx, uint32_t target_idx)
{
	struct near_adapter *adapter;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	adapter->rf_mode = NEAR_ADAPTER_RF_MODE_IDLE;
	rf_mode_changed(adapter);

	if (g_hash_table_remove(adapter->tags,
			GINT_TO_POINTER(target_idx)) == TRUE) {
		__near_adapter_tags_changed(idx);

		return 0;
	}

	if (g_hash_table_remove(adapter->devices,
			GINT_TO_POINTER(target_idx)) == TRUE) {
		__near_adapter_devices_changed(idx);

		return 0;
	}

	return 0;
}

int __near_adapter_add_device(uint32_t idx, uint8_t *nfcid, uint8_t nfcid_len)
{
	struct near_adapter *adapter;
	int ret;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	adapter->polling = FALSE;
	adapter->dep_up = TRUE;
	adapter->rf_mode = NEAR_ADAPTER_RF_MODE_TARGET;
	polling_changed(adapter);
	rf_mode_changed(adapter);

	ret = adapter_add_device(adapter, 0, nfcid, nfcid_len);
	if (ret < 0)
		return ret;

	__near_adapter_devices_changed(idx);

	return 0;
}

int __near_adapter_remove_device(uint32_t idx)
{
	struct near_adapter *adapter;
	uint32_t device_idx = 0;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	if (g_hash_table_remove(adapter->devices,
			GINT_TO_POINTER(device_idx)) == FALSE)
		return 0;

	adapter->rf_mode = NEAR_ADAPTER_RF_MODE_IDLE;
	rf_mode_changed(adapter);
	__near_adapter_devices_changed(idx);

	adapter->dep_up = FALSE;

	if (adapter->constant_poll == TRUE)
		adapter_start_poll(adapter);

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

		adapter->presence_timeout =
			g_timeout_add_seconds(2 * CHECK_PRESENCE_PERIOD,
					      check_presence, adapter);
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
	struct near_tag *tag;
	struct sockaddr_nfc addr;
	int err, sock;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	if (adapter->tag_sock != -1)
		return -EALREADY;

	tag = g_hash_table_lookup(adapter->tags,
				GINT_TO_POINTER(target_idx));
	if (tag == NULL)
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

	adapter->tag_sock = sock;
	adapter->tag_link = tag;

	if (adapter->channel == NULL)
		adapter->channel = g_io_channel_unix_new(adapter->tag_sock);

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
	uint32_t target_idx;
	uint16_t tag_type;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL)
		return -ENODEV;

	DBG("link %p", adapter->tag_link);

	if (adapter->tag_link == NULL)
		return -ENOLINK;

	tag_type = __near_tag_get_type(adapter->tag_link);
	target_idx = near_tag_get_target_idx(adapter->tag_link);

	DBG("tag type %d", tag_type);

	__near_adapter_remove_target(adapter->idx, target_idx);

	if (adapter->tag_sock == -1)
		return -ENOLINK;

	if (adapter->watch > 0) {
		g_source_remove(adapter->watch);
		adapter->watch = 0;
	}

	g_io_channel_unref(adapter->channel);
	adapter->channel = NULL;
	adapter->tag_sock = -1;
	adapter->tag_link = NULL;

	return 0;
}

int near_adapter_send(uint32_t idx, uint8_t *buf, size_t length,
			near_recv cb, void *data, near_release data_rel)
{
	struct near_adapter *adapter;
	struct near_adapter_ioreq *req = NULL;
	int err;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (adapter == NULL) {
		err = -ENODEV;
		goto out_err;
	}

	if (adapter->tag_sock == -1 || adapter->tag_link == NULL) {
		err = -ENOLINK;
		goto out_err;
	}

	if (cb != NULL && adapter->watch != 0) {
		req = g_try_malloc0(sizeof(*req));
		if (req == NULL) {
			err = -ENOMEM;
			goto out_err;
		}

		DBG("req %p cb %p data %p", req, cb, data);

		req->target_idx = near_tag_get_target_idx(adapter->tag_link);
		req->cb = cb;
		req->data = data;

		adapter->ioreq_list =
			g_list_append(adapter->ioreq_list, req);
	}

	err = send(adapter->tag_sock, buf, length, 0);
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

	if (data_rel != NULL)
		return (*data_rel)(err, data);

	return err;
}

static void adapter_listen(gpointer key, gpointer value, gpointer user_data)
{
	struct near_adapter *adapter = value;
	struct near_device_driver *driver = user_data;

	DBG("%s", adapter->path);

	if (adapter->path == NULL)
		return;

	driver->listen(adapter->idx, device_read_cb);
}

void __near_adapter_listen(struct near_device_driver *driver)
{
	g_hash_table_foreach(adapter_hash, adapter_listen, driver);
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

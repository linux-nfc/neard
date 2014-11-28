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

	bool powered;
	bool polling;
	bool constant_poll;
	bool dep_up;

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
	guint dep_timer;
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

	if (adapter->dep_timer > 0)
		g_source_remove(adapter->dep_timer);

	g_free(adapter->name);
	g_free(adapter->path);
	g_hash_table_destroy(adapter->tags);
	g_hash_table_destroy(adapter->devices);
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
	g_dbus_emit_property_changed(connection, adapter->path,
					NFC_ADAPTER_INTERFACE, "Polling");
}

static void rf_mode_changed(struct near_adapter *adapter)
{
	g_dbus_emit_property_changed(connection, adapter->path,
					NFC_ADAPTER_INTERFACE, "Mode");
}

static int adapter_start_poll(struct near_adapter *adapter)
{
	int err;
	uint32_t im_protos, tm_protos;

	if (g_hash_table_size(adapter->tags) > 0) {
		DBG("Clearing tags");

		g_hash_table_remove_all(adapter->tags);
	}

	if (g_hash_table_size(adapter->devices) > 0) {
		DBG("Clearing devices");

		g_hash_table_remove_all(adapter->devices);
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

	adapter->polling = true;

	polling_changed(adapter);

	return 0;
}

static gboolean property_get_mode(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_adapter *adapter = user_data;
	const char *rf_mode;

	rf_mode = rf_mode_to_string(adapter);
	if (!rf_mode)
		return FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &rf_mode);

	return TRUE;
}

static gboolean property_get_polling(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_adapter *adapter = user_data;
	dbus_bool_t val;

	val = adapter->polling;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &val);

	return TRUE;
}

static gboolean property_get_powered(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_adapter *adapter = user_data;
	dbus_bool_t val;

	val = adapter->powered;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &val);

	return TRUE;
}

static void set_powered(GDBusPendingPropertySet id, dbus_bool_t powered,
								void *data)
{
	struct near_adapter *adapter = data;
	int err;

	err = __near_netlink_adapter_enable(adapter->idx, powered);
	if (err < 0) {
		if (err == -EALREADY) {
			if (powered)
				g_dbus_pending_property_error(id,
						NFC_ERROR_INTERFACE ".Failed",
						"Device already enabled");
			else
				g_dbus_pending_property_error(id,
						NFC_ERROR_INTERFACE ".Failed",
						"Device already disabled");
		}

		g_dbus_pending_property_error(id,
						NFC_ERROR_INTERFACE ".Failed",
						strerror(err));

		return;
	}

	g_dbus_pending_property_success(id);

	adapter->powered = powered;

	g_dbus_emit_property_changed(connection, adapter->path,
					NFC_ADAPTER_INTERFACE, "Powered");
}

static void property_set_powered(const GDBusPropertyTable *property,
					DBusMessageIter *value,
					GDBusPendingPropertySet id, void *data)
{
	dbus_bool_t powered;

	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_BOOLEAN) {
		g_dbus_pending_property_error(id,
					NFC_ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	dbus_message_iter_get_basic(value, &powered);

	set_powered(id, powered, data);
}

static void append_protocols(DBusMessageIter *iter,
					struct near_adapter *adapter)
{
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

	if ((adapter->protocols & NFC_PROTO_ISO14443_MASK) ||
	    (adapter->protocols & NFC_PROTO_ISO14443_B_MASK)) {
		str = "ISO-DEP";

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);
	}

	if (adapter->protocols & NFC_PROTO_NFC_DEP_MASK) {
		str = "NFC-DEP";

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);
	}

	if (adapter->protocols & NFC_PROTO_ISO15693_MASK) {
		str = "ISO-15693";

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);
	}
}

static gboolean property_get_protocols(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_adapter *adapter = user_data;
	DBusMessageIter dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
						DBUS_TYPE_STRING_AS_STRING, &dict);

	append_protocols(&dict, adapter);

	dbus_message_iter_close_container(iter, &dict);

	return TRUE;
}

static DBusMessage *start_poll_loop(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_adapter *adapter = data;
	const char *dbus_mode;
	int err;

	DBG("conn %p", conn);

	if (!adapter->powered) {
		near_error("Adapter is down, can not start polling");
		return __near_error_failed(msg, ENODEV);
	}

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

	if (!adapter->polling)
		return __near_error_not_polling(msg);

	err = __near_netlink_stop_poll(adapter->idx);
	if (err < 0)
		return __near_error_failed(msg, -err);

	adapter->polling = false;

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

	if (!adapter)
		return FALSE;

	tag = adapter->tag_link;
	if (!tag)
		goto out_err;

	err = __near_tag_check_presence(tag, tag_present_cb);
	if (err < 0) {
		DBG("Could not check target presence");
		goto out_err;
	}

	return FALSE;

out_err:
	near_adapter_disconnect(adapter->idx);
	if (adapter->constant_poll)
		adapter_start_poll(adapter);

	return FALSE;
}

static gboolean dep_timer(gpointer user_data)
{
	struct near_adapter *adapter = user_data;

	DBG("");

	if (!adapter)
		return FALSE;

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
	if (!adapter)
		return;

	if (status < 0) {
		DBG("Tag is gone");

		near_adapter_disconnect(adapter->idx);
		if (adapter->constant_poll)
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
	if (!adapter)
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
	if (!adapter)
		return;

	if (adapter->presence_timeout > 0)
		g_source_remove(adapter->presence_timeout);
}

static const GDBusMethodTable adapter_methods[] = {
	{ GDBUS_METHOD("StartPollLoop", GDBUS_ARGS({"name", "s"}), NULL,
							start_poll_loop) },
	{ GDBUS_METHOD("StopPollLoop", NULL, NULL, stop_poll_loop) },
	{ },
};

static const GDBusPropertyTable adapter_properties[] = {
	{ "Mode", "s", property_get_mode },
	{ "Powered", "b", property_get_powered, property_set_powered },
	{ "Polling", "b", property_get_polling },
	{ "Protocols", "as", property_get_protocols },

	{ }
};

struct near_adapter *__near_adapter_create(uint32_t idx,
		const char *name, uint32_t protocols, bool powered)
{
	struct near_adapter *adapter;
	bool powered_setting;

	adapter = g_try_malloc0(sizeof(struct near_adapter));
	if (!adapter)
		return NULL;

	adapter->name = g_strdup(name);
	if (!adapter->name) {
		g_free(adapter);
		return NULL;
	}

	powered_setting = near_setting_get_bool("DefaultPowered");
	if (powered_setting && !powered &&
	    !__near_netlink_adapter_enable(idx, powered_setting))
			powered = true;

	DBG("Powered %d", powered);

	adapter->idx = idx;
	adapter->protocols = protocols;
	adapter->powered = powered;
	adapter->constant_poll = near_setting_get_bool("ConstantPoll");
	adapter->dep_up = false;
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

int __near_adapter_set_dep_state(uint32_t idx, bool dep)
{
	struct near_adapter *adapter;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (!adapter)
		return -ENODEV;

	adapter->dep_up = dep;

	if (!dep && adapter->constant_poll) {
		/*
		 * The immediate polling may fail if the adapter is busy in
		 * that very moment. In this case we need to try polling later
		 * again, so constant polling will work properly.
		 */
		if(adapter_start_poll(adapter) == -EBUSY) {
			near_error("Adapter is busy, retry polling later");
			g_timeout_add_seconds(1, dep_timer, adapter);
		}
	}

	if (!dep) {
		uint32_t target_idx;

		target_idx =  __neard_device_get_idx(adapter->device_link);
		__near_adapter_remove_target(idx, target_idx);
	} else {
		if (adapter->dep_timer > 0)
			g_source_remove(adapter->dep_timer);

		if (!__near_device_register_interface(adapter->device_link))
			return -ENODEV;
	}

	return 0;
}

bool __near_adapter_get_dep_state(uint32_t idx)
{
	struct near_adapter *adapter;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (!adapter)
		return false;

	return adapter->dep_up;
}

int __near_adapter_add(struct near_adapter *adapter)
{
	uint32_t idx = adapter->idx;

	DBG("%s", adapter->path);

	if (g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx)))
		return -EEXIST;

	g_hash_table_insert(adapter_hash, GINT_TO_POINTER(idx), adapter);

	DBG("connection %p", connection);

	g_dbus_register_interface(connection, adapter->path,
					NFC_ADAPTER_INTERFACE,
					adapter_methods, NULL,
					adapter_properties, adapter, NULL);

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
	if (!adapter)
		return;

	if (status < 0) {
		near_adapter_disconnect(adapter->idx);
		if (adapter->constant_poll)
			adapter_start_poll(adapter);

		return;
	}

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
	if (!adapter)
		return;

	if (status < 0) {
		if (adapter->device_link) {
			__near_netlink_dep_link_down(adapter->idx);
			adapter->device_link = NULL;
		}

		if (adapter->constant_poll)
			adapter_start_poll(adapter);

		return;
	}
}

static int adapter_add_tag(struct near_adapter *adapter, uint32_t target_idx,
			uint32_t protocols,
			uint16_t sens_res, uint8_t sel_res,
			uint8_t *nfcid, uint8_t nfcid_len,
			uint8_t iso15693_dsfid,
			uint8_t iso15693_uid_len, uint8_t *iso15693_uid)
{
	struct near_tag *tag;
	uint32_t tag_type;
	int err;

	tag = __near_tag_add(adapter->idx, target_idx, protocols,
				sens_res, sel_res,
				nfcid, nfcid_len,
				iso15693_dsfid, iso15693_uid_len, iso15693_uid);
	if (!tag)
		return -ENODEV;

	g_hash_table_insert(adapter->tags, GINT_TO_POINTER(target_idx), tag);

	tag_type = __near_tag_get_type(tag);

	err = near_adapter_connect(adapter->idx, target_idx, tag_type);
	if (err < 0) {
		near_error("Could not connect");
		return err;
	}

	err = __near_tag_read(tag, tag_read_cb);
	if (err < 0) {
		near_error("Could not read the tag");

		near_adapter_disconnect(adapter->idx);
		__near_adapter_remove_target(adapter->idx, target_idx);
	}

	return err;
}

static int adapter_add_device(struct near_adapter *adapter,
				uint32_t target_idx,
				uint8_t *nfcid, uint8_t nfcid_len)
{
	struct near_device *device;
	int err;

	DBG();

	device = __near_device_add(adapter->idx, target_idx, nfcid, nfcid_len);
	if (!device)
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

	if (adapter->dep_up) {
		if (!__near_device_register_interface(device))
			return -ENODEV;

		return 0;
	}

	err = __near_netlink_dep_link_up(adapter->idx, target_idx,
					NFC_COMM_ACTIVE, NFC_RF_INITIATOR);

	if (err < 0)
		adapter->device_link = NULL;

	DBG("Starting DEP timer");

	adapter->dep_timer = g_timeout_add_seconds(1, dep_timer, adapter);

	return err;
}

int __near_adapter_add_target(uint32_t idx, uint32_t target_idx,
			uint32_t protocols, uint16_t sens_res, uint8_t sel_res,
			uint8_t *nfcid, uint8_t nfcid_len,
			uint8_t iso15693_dsfid,
			uint8_t iso15693_uid_len, uint8_t *iso15693_uid)
{
	struct near_adapter *adapter;
	int ret;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (!adapter)
		return -ENODEV;

	adapter->polling = false;
	polling_changed(adapter);

	adapter->rf_mode = NEAR_ADAPTER_RF_MODE_INITIATOR;
	rf_mode_changed(adapter);

	if (protocols & NFC_PROTO_NFC_DEP_MASK)
		ret = adapter_add_device(adapter, target_idx,
						nfcid, nfcid_len);
	else
		ret = adapter_add_tag(adapter, target_idx, protocols,
					sens_res, sel_res, nfcid, nfcid_len,
					iso15693_dsfid,
					iso15693_uid_len, iso15693_uid);

	if (ret < 0 && adapter->constant_poll)
		adapter_start_poll(adapter);

	return ret;
}

int __near_adapter_remove_target(uint32_t idx, uint32_t target_idx)
{
	struct near_adapter *adapter;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (!adapter)
		return -ENODEV;

	adapter->rf_mode = NEAR_ADAPTER_RF_MODE_IDLE;
	rf_mode_changed(adapter);

	if (g_hash_table_remove(adapter->tags, GINT_TO_POINTER(target_idx)))
		return 0;

	if (g_hash_table_remove(adapter->devices, GINT_TO_POINTER(target_idx)))
		return 0;

	return 0;
}

static gboolean poll_error(gpointer user_data)
{
	struct near_adapter *adapter = user_data;
	bool reset;

	DBG("adapter %d", adapter->idx);

	reset = near_setting_get_bool("ResetOnError");
	if (reset) {
		near_error("Resetting nfc%d", adapter->idx);
		 __near_netlink_adapter_enable(adapter->idx, false);
		 __near_netlink_adapter_enable(adapter->idx, true);
	}

	adapter_start_poll(adapter);

	return FALSE;
}

int __near_adapter_get_targets_done(uint32_t idx)
{
	struct near_adapter *adapter;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (!adapter)
		return -ENODEV;

	if (g_hash_table_size(adapter->devices) > 0)
		return 0;

	if (g_hash_table_size(adapter->tags) > 0)
		return 0;

	near_error("No targets found - Polling error");

	adapter->polling = false;
	polling_changed(adapter);

	g_idle_add(poll_error, adapter);

	return 0;
}

int __near_adapter_add_device(uint32_t idx, uint8_t *nfcid, uint8_t nfcid_len)
{
	struct near_adapter *adapter;
	int ret;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (!adapter)
		return -ENODEV;

	adapter->polling = false;
	adapter->dep_up = true;
	adapter->rf_mode = NEAR_ADAPTER_RF_MODE_TARGET;
	polling_changed(adapter);
	rf_mode_changed(adapter);

	ret = adapter_add_device(adapter, 0, nfcid, nfcid_len);
	if (ret < 0)
		return ret;

	return 0;
}

int __near_adapter_remove_device(uint32_t idx)
{
	struct near_adapter *adapter;
	uint32_t device_idx = 0;

	DBG("idx %d", idx);

	adapter = g_hash_table_lookup(adapter_hash, GINT_TO_POINTER(idx));
	if (!adapter)
		return -ENODEV;

	if (!g_hash_table_remove(adapter->devices, GINT_TO_POINTER(device_idx)))
		return 0;

	adapter->rf_mode = NEAR_ADAPTER_RF_MODE_IDLE;
	rf_mode_changed(adapter);

	adapter->dep_up = false;

	if (adapter->constant_poll)
		adapter_start_poll(adapter);

	return 0;
}

static void adapter_flush_rx(struct near_adapter *adapter, int error)
{
	GList *list;

	for (list = adapter->ioreq_list; list; list = list->next) {
		struct near_adapter_ioreq *req = list->data;

		if (!req)
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
	if (!first)
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
	if (!adapter)
		return -ENODEV;

	if (adapter->tag_sock != -1)
		return -EALREADY;

	tag = g_hash_table_lookup(adapter->tags,
				GINT_TO_POINTER(target_idx));
	if (!tag)
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

	if (!adapter->channel)
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
	if (!adapter)
		return -ENODEV;

	DBG("link %p", adapter->tag_link);

	if (!adapter->tag_link)
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
	if (!adapter) {
		err = -ENODEV;
		goto out_err;
	}

	if (adapter->tag_sock == -1 || !adapter->tag_link) {
		err = -ENOLINK;
		goto out_err;
	}

	if (cb && adapter->watch != 0) {
		req = g_try_malloc0(sizeof(*req));
		if (!req) {
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
	if (req) {
		GList *last = g_list_last(adapter->ioreq_list);

		g_free(req);
		adapter->ioreq_list =
				g_list_delete_link(adapter->ioreq_list, last);
	}

	if (data_rel)
		return (*data_rel)(err, data);

	return err;
}

static void adapter_listen(gpointer key, gpointer value, gpointer user_data)
{
	struct near_adapter *adapter = value;
	struct near_device_driver *driver = user_data;

	DBG("%s", adapter->path);

	if (!adapter->path)
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

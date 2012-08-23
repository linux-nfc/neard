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
#include <string.h>

#include <glib.h>

#include <gdbus.h>

#include "near.h"

struct near_device {
	char *path;

	uint32_t adapter_idx;
	uint32_t target_idx;

	uint8_t nfcid[NFC_MAX_NFCID1_LEN];
	uint8_t nfcid_len;

	size_t data_length;
	uint8_t *data;

	uint32_t n_records;
	GList *records;

	DBusMessage *push_msg; /* Push pending message */
};

static DBusConnection *connection = NULL;

static GHashTable *device_hash;

static GSList *driver_list = NULL;

static void free_device(gpointer data)
{
	struct near_device *device = data;
	GList *list;

	DBG("device %p", device);

	for (list = device->records; list; list = list->next) {
		struct near_ndef_record *record = list->data;

		__near_ndef_record_free(record);
	}

	g_list_free(device->records);
	g_free(device->path);
	g_free(device->data);
	g_free(device);
}

struct near_device *near_device_get_device(uint32_t adapter_idx,
						uint32_t target_idx)
{
	struct near_device *device;
	char *path;

	DBG("");

	path = g_strdup_printf("%s/nfc%d/device%d", NFC_PATH,
					adapter_idx, target_idx);
	if (path == NULL)
		return NULL;

	device = g_hash_table_lookup(device_hash, path);
	g_free(path);

	/* TODO refcount */
	return device;
}

void __near_device_remove(struct near_device *device)
{
	char *path = device->path;

	DBG("path %s", device->path);

	if (g_hash_table_lookup(device_hash, device->path) == NULL)
		return;

	g_dbus_unregister_interface(connection, device->path,
						NFC_DEVICE_INTERFACE);

	g_hash_table_remove(device_hash, path);
}

const char *__near_device_get_path(struct near_device *device)
{
	return device->path;
}

static void append_records(DBusMessageIter *iter, void *user_data)
{
	struct near_device *device = user_data;
	GList *list;

	DBG("");

	for (list = device->records; list; list = list->next) {
		struct near_ndef_record *record = list->data;
		char *path;

		path = __near_ndef_record_get_path(record);
		if (path == NULL)
			continue;

		dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&path);
	}
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_device *device = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	near_dbus_dict_open(&array, &dict);

	near_dbus_dict_append_array(&dict, "Records",
				DBUS_TYPE_OBJECT_PATH, append_records, device);

	near_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("conn %p", conn);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void push_cb(uint32_t adapter_idx, uint32_t target_idx, int status)
{
	struct near_device *device;
	DBusConnection *conn;
	DBusMessage *reply;

	DBG("Push status %d", status);

	conn = near_dbus_get_connection();
	device = near_device_get_device(adapter_idx, target_idx);

	if (conn == NULL || device == NULL)
		return;

	if (status != 0) {
		reply = __near_error_failed(device->push_msg, EINVAL);
		if (reply != NULL)
			g_dbus_send_message(conn, reply);
	} else {
		g_dbus_send_reply(conn, device->push_msg, DBUS_TYPE_INVALID);
	}

	dbus_message_unref(device->push_msg);
	device->push_msg = NULL;
}

static char *sn_from_message(DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessageIter arr_iter;

	DBG("");

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &arr_iter);

	while (dbus_message_iter_get_arg_type(&arr_iter) !=
						DBUS_TYPE_INVALID) {
		const char *key, *value;
		DBusMessageIter ent_iter;
		DBusMessageIter var_iter;

		dbus_message_iter_recurse(&arr_iter, &ent_iter);
		dbus_message_iter_get_basic(&ent_iter, &key);

		if (g_strcmp0(key, "Type") != 0) {
			dbus_message_iter_next(&arr_iter);
			continue;
		}

		dbus_message_iter_next(&ent_iter);
		dbus_message_iter_recurse(&ent_iter, &var_iter);

		switch (dbus_message_iter_get_arg_type(&var_iter)) {
		case DBUS_TYPE_STRING:
			dbus_message_iter_get_basic(&var_iter, &value);

			if (g_strcmp0(value, "Text") == 0)
				return NEAR_DEVICE_SN_SNEP;
			else if (g_strcmp0(value, "URI") == 0)
				return NEAR_DEVICE_SN_SNEP;
			else if (g_strcmp0(value, "SmartPoster") == 0)
				return NEAR_DEVICE_SN_SNEP;
			else if (g_strcmp0(value, "Handover") == 0)
				return NEAR_DEVICE_SN_HANDOVER;
			else
				return NULL;

			break;
		}

		dbus_message_iter_next(&arr_iter);
	}

	return NULL;
}

static DBusMessage *push_ndef(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct near_device *device = data;
	struct near_ndef_message *ndef;
	char *service_name;
	int err;

	DBG("conn %p", conn);

	if (device->push_msg)
		return __near_error_in_progress(msg);

	device->push_msg = dbus_message_ref(msg);

	service_name = sn_from_message(msg);
	if (service_name == NULL) {
		err = -EINVAL;
		goto error;
	}

	ndef = __ndef_build_from_message(msg);
	if (ndef == NULL) {
		err = -EINVAL;
		goto error;
	}

	err = __near_device_push(device, ndef, service_name, push_cb);
	if (err < 0)
		goto error;

	g_free(ndef);
	g_free(ndef->data);

	return NULL;

error:
	dbus_message_unref(device->push_msg);
	device->push_msg = NULL;

	return __near_error_failed(msg, -err);
}

static const GDBusMethodTable device_methods[] = {
	{ GDBUS_METHOD("GetProperties",
				NULL, GDBUS_ARGS({"properties", "a{sv}"}),
				get_properties) },
	{ GDBUS_METHOD("SetProperty",
				GDBUS_ARGS({"name", "s"}, {"value", "v"}),
				NULL, set_property) },
	{ GDBUS_ASYNC_METHOD("Push", GDBUS_ARGS({"attributes", "a{sv}"}),
							NULL, push_ndef) },
	{ },
};

static const GDBusSignalTable device_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
				GDBUS_ARGS({"name", "s"}, {"value", "v"})) },
	{ }
};

int near_device_add_data(uint32_t adapter_idx, uint32_t target_idx,
			uint8_t *data, size_t data_length)
{
	struct near_device *device;

	device = near_device_get_device(adapter_idx, target_idx);
	if (device == NULL)
		return -ENODEV;

	device->data_length = data_length;
	device->data = g_try_malloc0(data_length);
	if (device->data == NULL)
		return -ENOMEM;

	if (data != NULL)
		memcpy(device->data, data, data_length);

	return 0;
}

int near_device_add_records(struct near_device *device, GList *records,
				near_device_io_cb cb, int status)
{
	GList *list;
	struct near_ndef_record *record;
	char *path;

	DBG("records %p", records);

	for (list = records; list; list = list->next) {
		record = list->data;

		path = g_strdup_printf("%s/nfc%d/device%d/record%d",
					NFC_PATH, device->adapter_idx,
					device->target_idx, device->n_records);

		if (path == NULL)
			continue;

		__near_ndef_record_register(record, path);

		device->n_records++;
		device->records = g_list_append(device->records, record);
	}

	__near_agent_ndef_parse_records(device->records);

	if (cb != NULL)
		cb(device->adapter_idx, device->target_idx, status);

	g_list_free(records);

	return 0;
}

struct near_device *__near_device_add(uint32_t adapter_idx, uint32_t target_idx,
					uint8_t *nfcid, uint8_t nfcid_len)
{
	struct near_device *device;
	char *path;

	device = near_device_get_device(adapter_idx, target_idx);
	if (device != NULL)
		return NULL;

	device = g_try_malloc0(sizeof(struct near_device));
	if (device == NULL)
		return NULL;

	device->path = g_strdup_printf("%s/nfc%d/device%d", NFC_PATH,
					adapter_idx, target_idx);
	if (device->path == NULL) {
		g_free(device);
		return NULL;
	}
	device->adapter_idx = adapter_idx;
	device->target_idx = target_idx;
	device->n_records = 0;

	if (nfcid_len <= NFC_MAX_NFCID1_LEN && nfcid_len > 0) {
		device->nfcid_len = nfcid_len;
		memcpy(device->nfcid, nfcid, nfcid_len);
	}

	path = g_strdup(device->path);
	if (path == NULL) {
		g_free(device);
		return NULL;
	}

	g_hash_table_insert(device_hash, path, device);

	DBG("connection %p", connection);

	g_dbus_register_interface(connection, device->path,
					NFC_DEVICE_INTERFACE,
					device_methods, device_signals,
							NULL, device, NULL);

	return device;
}

int __near_device_listen(struct near_device *device, near_device_io_cb cb)
{
	GSList *list;

	DBG("");

	for (list = driver_list; list; list = list->next) {
		struct near_device_driver *driver = list->data;

		return driver->listen(device->adapter_idx, cb);
	}

	return 0;
}

int __near_device_push(struct near_device *device,
			struct near_ndef_message *ndef, char *service_name,
			near_device_io_cb cb)
{
	GSList *list;

	DBG("");

	if (__near_adapter_get_dep_state(device->adapter_idx) == FALSE) {
		near_error("DEP link is not established");
		return -ENOLINK;
	}

	for (list = driver_list; list; list = list->next) {
		struct near_device_driver *driver = list->data;

		return driver->push(device->adapter_idx, device->target_idx,
					ndef, service_name, cb);
	}

	return 0;
}

static gint cmp_prio(gconstpointer a, gconstpointer b)
{
	const struct near_tag_driver *driver1 = a;
	const struct near_tag_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

int near_device_driver_register(struct near_device_driver *driver)
{
	DBG("");

	if (driver->listen == NULL)
		return -EINVAL;

	driver_list = g_slist_insert_sorted(driver_list, driver, cmp_prio);

	__near_adapter_listen(driver);

	return 0;
}

void near_device_driver_unregister(struct near_device_driver *driver)
{
	DBG("");

	driver_list = g_slist_remove(driver_list, driver);
}

int __near_device_init(void)
{
	DBG("");

	connection = near_dbus_get_connection();

	device_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, free_device);

	return 0;
}

void __near_device_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(device_hash);
	device_hash = NULL;
}

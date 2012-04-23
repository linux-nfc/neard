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

static GDBusMethodTable device_methods[] = {
	{ "GetProperties",     "",      "a{sv}", get_properties     },
	{ "SetProperty",       "sv",    "",      set_property       },
	{ },
};

static GDBusSignalTable device_signals[] = {
	{ "PropertyChanged",		"sv"	},
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

	if (nfcid_len <= NFC_MAX_NFCID1_LEN) {
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

		return driver->listen(device->adapter_idx,
						device->target_idx, cb);
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

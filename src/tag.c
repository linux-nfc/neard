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

#define TYPE3_IDM_LEN 8
#define TYPE3_ATTR_BLOCK_SIZE 16

struct near_tag {
	char *path;

	uint32_t adapter_idx;
	uint32_t target_idx;

	uint32_t protocol;
	uint32_t type;
	enum near_tag_sub_type sub_type;
	enum near_tag_memory_layout layout;
	near_bool_t readonly;

	uint8_t nfcid[NFC_MAX_NFCID1_LEN];
	uint8_t nfcid_len;

	size_t data_length;
	uint8_t *data;

	uint32_t n_records;
	GList *records;

	/* Tag specific structures */
	struct {
		uint8_t IDm[TYPE3_IDM_LEN];
		uint8_t attr[TYPE3_ATTR_BLOCK_SIZE];
	} t3;

	struct {
		uint16_t max_ndef_size;
		uint16_t c_apdu_max_size;
	} t4;
};

static DBusConnection *connection = NULL;

static GHashTable *tag_hash;

static GSList *driver_list = NULL;

static void append_records(DBusMessageIter *iter, void *user_data)
{
	struct near_tag *tag = user_data;
	GList *list;

	DBG("");

	for (list = tag->records; list; list = list->next) {
		struct near_ndef_record *record = list->data;
		char *path;

		path = __near_ndef_record_get_path(record);
		if (path == NULL)
			continue;

		dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&path);
	}
}

static const char *type_string(struct near_tag *tag)
{
	const char *type;

	DBG("type 0x%x", tag->type);

	switch (tag->type) {
	case NFC_PROTO_JEWEL:
		type = "Type 1";
		break;

	case NFC_PROTO_MIFARE:
		type = "Type 2";
		break;

	case NFC_PROTO_FELICA:
		type = "Type 3";
		break;

	case NFC_PROTO_ISO14443:
		type = "Type 4";
		break;

	default:
		type = NULL;
		near_error("Unknown tag type 0x%x", tag->type);
		break;
	}

	return type;
}

static const char *protocol_string(struct near_tag *tag)
{
	const char *protocol;

	DBG("protocol 0x%x", tag->protocol);

	switch (tag->protocol) {
	case NFC_PROTO_FELICA_MASK:
		protocol = "Felica";
		break;

	case NFC_PROTO_MIFARE_MASK:
		protocol = "MIFARE";
		break;

	case NFC_PROTO_JEWEL_MASK:
		protocol = "Jewel";
		break;

	case NFC_PROTO_ISO14443_MASK:
		protocol = "ISO-DEP";
		break;

	default:
		near_error("Unknown tag protocol 0x%x", tag->protocol);
		protocol = NULL;
	}

	return protocol;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_tag *tag = data;
	const char *protocol, *type;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	near_dbus_dict_open(&array, &dict);

	type = type_string(tag);
	if (type != NULL)
		near_dbus_dict_append_basic(&dict, "Type",
					DBUS_TYPE_STRING, &type);

	protocol = protocol_string(tag);
	if (protocol != NULL)
		near_dbus_dict_append_basic(&dict, "Protocol",
					DBUS_TYPE_STRING, &protocol);

	near_dbus_dict_append_basic(&dict, "ReadOnly",
					DBUS_TYPE_BOOLEAN, &tag->readonly);

	near_dbus_dict_append_array(&dict, "Records",
				DBUS_TYPE_OBJECT_PATH, append_records, tag);

	near_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("conn %p", conn);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable tag_methods[] = {
	{ "GetProperties",     "",      "a{sv}", get_properties     },
	{ "SetProperty",       "sv",    "",      set_property       },
	{ },
};

static GDBusSignalTable tag_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ }
};


void __near_tag_append_records(struct near_tag *tag, DBusMessageIter *iter)
{
	GList *list;

	for (list = tag->records; list; list = list->next) {
		struct near_ndef_record *record = list->data;
		char *path;

		path = __near_ndef_record_get_path(record);
		if (path == NULL)
			continue;

		dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&path);
	}
}

static int tag_initialize(struct near_tag *tag, char *path,
			uint32_t adapter_idx, uint32_t target_idx,
			uint8_t * data, size_t data_length)
{
	DBG("data length %zu", data_length);

	tag->path = path;
	tag->adapter_idx = adapter_idx;
	tag->target_idx = target_idx;
	tag->n_records = 0;
	tag->readonly = 0;

	if (data_length > 0) {
		tag->data_length = data_length;
		tag->data = g_try_malloc0(data_length);
		if (tag->data == NULL)
			return -ENOMEM;

		if (data != NULL)
			memcpy(tag->data, data, data_length);
	}

	return 0;
}

struct near_tag *__near_tag_new(uint32_t adapter_idx, uint32_t target_idx,
				uint8_t *data, size_t data_length)
{
	struct near_tag *tag;
	char *path;

	path = g_strdup_printf("%s/nfc%d/tag%d", NFC_PATH,
					adapter_idx, target_idx);

	if (path == NULL)
		return NULL;

	if (g_hash_table_lookup(tag_hash, path) != NULL)
		return NULL;

	tag = g_try_malloc0(sizeof(struct near_tag));
	if (tag == NULL)
		return NULL;

	if (tag_initialize(tag, path, adapter_idx, target_idx,
					data, data_length) < 0) {
		g_free(tag);
		return NULL;
	}

	g_hash_table_insert(tag_hash, path, tag);

	DBG("connection %p", connection);

	g_dbus_register_interface(connection, tag->path,
					NFC_TAG_INTERFACE,
					tag_methods, tag_signals,
							NULL, tag, NULL);

	return tag;
}

void __near_tag_free(struct near_tag *tag)
{
	GList *list;

	DBG("");

	for (list = tag->records; list; list = list->next) {
		struct near_ndef_record *record = list->data;

		__near_ndef_record_free(record);
	}

	g_list_free(tag->records);
	g_free(tag->path);
	g_free(tag->data);
	g_free(tag);
}

uint32_t __near_tag_n_records(struct near_tag *tag)
{
	return tag->n_records;
}

int __near_tag_add_record(struct near_tag *tag,
				struct near_ndef_record *record)
{
	DBG("");

	tag->n_records++;
	tag->records = g_list_append(tag->records, record);

	return 0;
}

int near_tag_set_ro(struct near_tag *tag, near_bool_t readonly)
{
	tag->readonly = readonly;

	return 0;
}

near_bool_t near_tag_get_ro(struct near_tag *tag)
{
	return tag->readonly;
}

uint8_t *near_tag_get_data(struct near_tag *tag, size_t *data_length)
{
	if (data_length == NULL)
		return NULL;

	*data_length = tag->data_length;

	return tag->data;
}

uint32_t near_tag_get_adapter_idx(struct near_tag *tag)
{
	return tag->adapter_idx;
}

uint32_t near_tag_get_target_idx(struct near_tag *tag)
{
	return tag->target_idx;
}

enum near_tag_memory_layout near_tag_get_memory_layout(struct near_tag *tag)
{
	if (tag == NULL)
		return NEAR_TAG_MEMORY_UNKNOWN;

	return tag->layout;
}

void near_tag_set_memory_layout(struct near_tag *tag,
					enum near_tag_memory_layout layout)
{
	if (tag == NULL)
		return;

	tag->layout = layout;
}

void near_tag_set_max_ndef_size(struct near_tag *tag, uint16_t size)
{
	if (tag == NULL)
		return;

	tag->t4.max_ndef_size = size;
}

uint16_t near_tag_get_max_ndef_size(struct near_tag *tag)
{
	if (tag == NULL)
		return 0;

	return tag->t4.max_ndef_size;
}

void near_tag_set_c_apdu_max_size(struct near_tag *tag, uint16_t size)
{
	if (tag == NULL)
		return;

	tag->t4.c_apdu_max_size = size;
}

uint16_t near_tag_get_c_apdu_max_size(struct near_tag *tag)
{
	if (tag == NULL)
		return 0;

	return tag->t4.c_apdu_max_size;
}

void near_tag_set_idm(struct near_tag *tag, uint8_t *idm, uint8_t len)
{
	if (tag == NULL || len > TYPE3_IDM_LEN)
		return;

	memset(tag->t3.IDm, 0, TYPE3_IDM_LEN);
	memcpy(tag->t3.IDm, idm, len);
}

uint8_t *near_tag_get_idm(struct near_tag *tag, uint8_t *len)
{
	if (tag == NULL || len == NULL)
		return NULL;

	*len = TYPE3_IDM_LEN;
	return tag->t3.IDm;
}

void near_tag_set_attr_block(struct near_tag *tag, uint8_t *attr, uint8_t len)
{
	if (tag == NULL || len > TYPE3_ATTR_BLOCK_SIZE)
		return;

	memset(tag->t3.attr, 0, TYPE3_ATTR_BLOCK_SIZE);
	memcpy(tag->t3.attr, attr, len);
}

uint8_t *near_tag_get_attr_block(struct near_tag *tag, uint8_t *len)
{
	if (tag == NULL || len == NULL)
		return NULL;

	*len = TYPE3_ATTR_BLOCK_SIZE;
	return tag->t3.attr;
}

static gint cmp_prio(gconstpointer a, gconstpointer b)
{
	const struct near_tag_driver *driver1 = a;
	const struct near_tag_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

int near_tag_driver_register(struct near_tag_driver *driver)
{
	DBG("");

	if (driver->read_tag == NULL)
		return -EINVAL;

	driver_list = g_slist_insert_sorted(driver_list, driver, cmp_prio);

	return 0;
}

void near_tag_driver_unregister(struct near_tag_driver *driver)
{
	DBG("");

	driver_list = g_slist_remove(driver_list, driver);
}

int __near_tag_read(struct near_target *target, near_tag_io_cb cb)
{
	GSList *list;
	uint16_t type;

	DBG("");

	type = __near_target_get_tag_type(target);
	if (type == NFC_PROTO_MAX)
		return -ENODEV;

	DBG("type 0x%x", type);

	for (list = driver_list; list; list = list->next) {
		struct near_tag_driver *driver = list->data;

		DBG("driver type 0x%x", driver->type);

		if (driver->type == type) {
			uint32_t adapter_idx, target_idx;		

			target_idx = __near_target_get_idx(target);
			adapter_idx = __near_target_get_adapter_idx(target);

			return driver->read_tag(adapter_idx, target_idx, cb);
		}
	}

	return 0;
}

int __near_tag_add_ndef(struct near_target *target,
				struct near_ndef_message *ndef,
				near_tag_io_cb cb)
{
	GSList *list;
	uint16_t type;

	DBG("");

	type = __near_target_get_tag_type(target);
	if (type == NFC_PROTO_MAX)
		return -ENODEV;

	DBG("type 0x%x", type);

	for (list = driver_list; list; list = list->next) {
		struct near_tag_driver *driver = list->data;

		DBG("driver type 0x%x", driver->type);

		if (driver->type == type) {
			uint32_t adapter_idx, target_idx;

			target_idx = __near_target_get_idx(target);
			adapter_idx = __near_target_get_adapter_idx(target);

			return driver->add_ndef(adapter_idx, target_idx,
								ndef, cb);
		}
	}

	return 0;
}

int __near_tag_check_presence(struct near_target *target, near_tag_io_cb cb)
{
	GSList *list;
	uint16_t type;

	DBG("");

	type = __near_target_get_tag_type(target);
	if (type == NFC_PROTO_MAX)
		return -ENODEV;

	DBG("type 0x%x", type);

	for (list = driver_list; list; list = list->next) {
		struct near_tag_driver *driver = list->data;

		DBG("driver type 0x%x", driver->type);

		if (driver->type == type) {
			uint32_t adapter_idx, target_idx;

			target_idx = __near_target_get_idx(target);
			adapter_idx = __near_target_get_adapter_idx(target);

			if (driver->check_presence == NULL)
				continue;

			return driver->check_presence(adapter_idx, target_idx, cb);
		}
	}

	return -EOPNOTSUPP;
}

static void free_tag(gpointer data)
{
	struct near_tag *tag = data;

	DBG("");

	__near_tag_free(tag);
}

int __near_tag_init(void)
{
	DBG("");

	connection = near_dbus_get_connection();

	tag_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, free_tag);

	return 0;
}

void __near_tag_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(tag_hash);
	tag_hash = NULL;
}

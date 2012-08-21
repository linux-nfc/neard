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
	near_bool_t blank;

	/* Tag specific structures */
	struct {
		uint8_t IDm[TYPE3_IDM_LEN];
		uint8_t attr[TYPE3_ATTR_BLOCK_SIZE];
		uint8_t ic_type;
	} t3;

	struct {
		uint16_t max_ndef_size;
		uint16_t c_apdu_max_size;
	} t4;

	DBusMessage *write_msg; /* Pending write message */
	struct near_ndef_message *write_ndef;
};

static DBusConnection *connection = NULL;

static GHashTable *tag_hash;

static GSList *driver_list = NULL;

struct near_tag *near_tag_get_tag(uint32_t adapter_idx, uint32_t target_idx)
{
	struct near_tag *tag;
	char *path;

	path = g_strdup_printf("%s/nfc%d/tag%d", NFC_PATH,
					adapter_idx, target_idx);
	if (path == NULL)
		return NULL;

	tag = g_hash_table_lookup(tag_hash, path);
	g_free(path);

	/* TODO refcount */
	return tag;
}

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

static void tag_read_cb(uint32_t adapter_idx, uint32_t target_idx, int status)
{
	__near_adapter_tags_changed(adapter_idx);
}

static void write_cb(uint32_t adapter_idx, uint32_t target_idx, int status)
{
	struct near_tag *tag;
	DBusConnection *conn;
	DBusMessage *reply;

	DBG("Write status %d", status);

	conn = near_dbus_get_connection();
	tag = near_tag_get_tag(adapter_idx, target_idx);

	if (conn == NULL || tag == NULL)
		return;

	if (status != 0) {
		reply = __near_error_failed(tag->write_msg, EINVAL);
		if (reply != NULL)
			g_dbus_send_message(conn, reply);
	} else {
		g_dbus_send_reply(conn, tag->write_msg, DBUS_TYPE_INVALID);
	}

	dbus_message_unref(tag->write_msg);
	tag->write_msg = NULL;

	near_ndef_records_free(tag->records);
	tag->n_records = 0;
	tag->records = NULL;
	g_free(tag->data);

	if (status == 0)
		__near_tag_read(tag, tag_read_cb);
}

static void format_cb(uint32_t adapter_idx, uint32_t target_idx, int status)
{
	struct near_tag *tag;
	int err;

	DBG("format status %d", status);

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (tag == NULL)
		return;

	if (tag->write_msg == NULL)
		return;

	if (status == 0) {
		err = __near_tag_write(tag, tag->write_ndef,
						write_cb);
		if (err < 0)
			goto error;
	} else {
		err = status;
		goto error;
	}

	return;

error:
	write_cb(tag->adapter_idx, tag->target_idx, err);
}

static DBusMessage *write_ndef(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct near_tag *tag = data;
	struct near_ndef_message *ndef, *ndef_with_header = NULL;
	int err;

	DBG("conn %p", conn);

	if (tag->readonly == TRUE) {
		DBG("Read only tag");
		return __near_error_permission_denied(msg);
	}

	if (tag->write_msg)
		return __near_error_in_progress(msg);

	ndef = __ndef_build_from_message(msg);
	if (ndef == NULL)
		return __near_error_failed(msg, EINVAL);

	tag->write_msg = dbus_message_ref(msg);

	/* Add NDEF header information depends upon tag type */
	switch (tag->type) {
	case NFC_PROTO_JEWEL:
	case NFC_PROTO_MIFARE:
		ndef_with_header = g_try_malloc0(sizeof(
					struct near_ndef_message));
		if (ndef_with_header == NULL)
			goto fail;

		ndef_with_header->offset = 0;
		ndef_with_header->length = ndef->length + 3;
		ndef_with_header->data = g_try_malloc0(ndef->length + 3);
		if (ndef_with_header->data == NULL)
			goto fail;

		ndef_with_header->data[0] = TLV_NDEF;
		ndef_with_header->data[1] = ndef->length;
		memcpy(ndef_with_header->data + 2, ndef->data, ndef->length);
		ndef_with_header->data[ndef->length + 2] = TLV_END;

		break;

	case NFC_PROTO_FELICA:
		ndef_with_header = g_try_malloc0(sizeof(
					struct near_ndef_message));
		if (ndef_with_header == NULL)
			goto fail;

		ndef_with_header->offset = 0;
		ndef_with_header->length = ndef->length;
		ndef_with_header->data = g_try_malloc0(
						ndef_with_header->length);
		if (ndef_with_header->data == NULL)
			goto fail;

		memcpy(ndef_with_header->data, ndef->data, ndef->length);

		break;

	case NFC_PROTO_ISO14443:
		ndef_with_header = g_try_malloc0(sizeof(
					struct near_ndef_message));
		if (ndef_with_header == NULL)
			goto fail;

		ndef_with_header->offset = 0;
		ndef_with_header->length = ndef->length + 2;
		ndef_with_header->data = g_try_malloc0(ndef->length + 2);
		if (ndef_with_header->data == NULL)
			goto fail;

		ndef_with_header->data[0] = (uint8_t)(ndef->length >> 8);
		ndef_with_header->data[1] = (uint8_t)(ndef->length);
		memcpy(ndef_with_header->data + 2, ndef->data, ndef->length);

		break;

	default:
		g_free(ndef->data);
		g_free(ndef);

		return __near_error_failed(msg, EOPNOTSUPP);
	}

	g_free(ndef->data);
	g_free(ndef);

	tag->write_ndef = ndef_with_header;
	err = __near_tag_write(tag, ndef_with_header, write_cb);
	if (err < 0) {
		g_free(ndef_with_header->data);
		g_free(ndef_with_header);

		return __near_error_failed(msg, -err);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

fail:
	dbus_message_unref(tag->write_msg);
	tag->write_msg = NULL;

	return __near_error_failed(msg, ENOMEM);
}

static const GDBusMethodTable tag_methods[] = {
	{ GDBUS_METHOD("GetProperties",
				NULL, GDBUS_ARGS({"properties", "a{sv}"}),
				get_properties) },
	{ GDBUS_METHOD("SetProperty",
				GDBUS_ARGS({"name", "s"}, {"value", "v"}),
				NULL, set_property) },
	{ GDBUS_ASYNC_METHOD("Write", GDBUS_ARGS({"attributes", "a{sv}"}),
							NULL, write_ndef) },
	{ },
};

static const GDBusSignalTable tag_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
				GDBUS_ARGS({"name", "s"}, {"value", "v"})) },
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

#define NFC_TAG_A (NFC_PROTO_ISO14443_MASK | NFC_PROTO_NFC_DEP_MASK | \
				NFC_PROTO_JEWEL_MASK | NFC_PROTO_MIFARE_MASK)
#define NFC_TAG_A_TYPE2      0x00
#define NFC_TAG_A_TYPE4      0x01
#define NFC_TAG_A_NFC_DEP    0x02
#define NFC_TAG_A_TYPE4_DEP  0x03

#define NFC_TAG_A_SENS_RES_SSD_JEWEL      0x00
#define NFC_TAG_A_SENS_RES_PLATCONF_JEWEL 0x0c

#define NFC_TAG_A_SEL_PROT(sel_res) (((sel_res) & 0x60) >> 5)
#define NFC_TAG_A_SEL_CASCADE(sel_res) (((sel_res) & 0x04) >> 2)
#define NFC_TAG_A_SENS_RES_SSD(sens_res) ((sens_res) & 0x001f)
#define NFC_TAG_A_SENS_RES_PLATCONF(sens_res) (((sens_res) & 0x0f00) >> 8)

static enum near_tag_sub_type get_tag_type2_sub_type(uint8_t sel_res)
{
	switch(sel_res) {
	case 0x00 :
		return NEAR_TAG_NFC_T2_MIFARE_ULTRALIGHT;
	case 0x08:
		return NEAR_TAG_NFC_T2_MIFARE_CLASSIC_1K;
	case 0x09:
		return NEAR_TAG_NFC_T2_MIFARE_MINI;
	case 0x18:
		return NEAR_TAG_NFC_T2_MIFARE_CLASSIC_4K;
	case 0x20:
		return NEAR_TAG_NFC_T2_MIFARE_DESFIRE;
	case 0x28 :
		return NEAR_TAG_NFC_T2_JCOP30;
	case 0x38:
		return NEAR_TAG_NFC_T2_MIFARE_4K_EMUL;
	case 0x88:
		return NEAR_TAG_NFC_T2_MIFARE_1K_INFINEON;
	case 0x98:
		return NEAR_TAG_NFC_T2_MPCOS;
	}

	return NEAR_TAG_NFC_SUBTYPE_UNKNOWN;
}

static void set_tag_type(struct near_tag *tag,
				uint16_t sens_res, uint8_t sel_res)
{
	uint8_t platconf, ssd, proto;

	DBG("protocol 0x%x sens_res 0x%x sel_res 0x%x", tag->protocol,
							sens_res, sel_res);

	switch (tag->protocol) {
	case NFC_PROTO_JEWEL_MASK:
		platconf = NFC_TAG_A_SENS_RES_PLATCONF(sens_res);
		ssd = NFC_TAG_A_SENS_RES_SSD(sens_res);

		DBG("Jewel");

		if ((ssd == NFC_TAG_A_SENS_RES_SSD_JEWEL) &&
				(platconf == NFC_TAG_A_SENS_RES_PLATCONF_JEWEL))
			tag->type = NFC_PROTO_JEWEL;
		break;

	case NFC_PROTO_MIFARE_MASK:
	case NFC_PROTO_ISO14443_MASK:
		proto = NFC_TAG_A_SEL_PROT(sel_res);

		DBG("proto 0x%x", proto);

		switch(proto) {
		case NFC_TAG_A_TYPE2:
			tag->type = NFC_PROTO_MIFARE;
			tag->sub_type = get_tag_type2_sub_type(sel_res);
			break;
		case NFC_TAG_A_TYPE4:
			tag->type = NFC_PROTO_ISO14443;
			break;
		case NFC_TAG_A_TYPE4_DEP:
			tag->type = NFC_PROTO_NFC_DEP;
			break;
		}
		break;

	case NFC_PROTO_FELICA_MASK:
		tag->type = NFC_PROTO_FELICA;
		break;

	default:
		tag->type = NFC_PROTO_MAX;
		break;
	}

	DBG("tag type 0x%x", tag->type);
}

static int tag_initialize(struct near_tag *tag,
			uint32_t adapter_idx, uint32_t target_idx,
			uint32_t protocols,
			uint16_t sens_res, uint8_t sel_res,
			uint8_t *nfcid, uint8_t nfcid_len)
{
	DBG("");

	tag->path = g_strdup_printf("%s/nfc%d/tag%d", NFC_PATH,
					adapter_idx, target_idx);
	if (tag->path == NULL)
		return -ENOMEM;
	tag->adapter_idx = adapter_idx;
	tag->target_idx = target_idx;
	tag->protocol = protocols;
	tag->n_records = 0;
	tag->readonly = FALSE;

	if (nfcid_len <= NFC_MAX_NFCID1_LEN) {
		tag->nfcid_len = nfcid_len;
		memcpy(tag->nfcid, nfcid, nfcid_len);
	}

	set_tag_type(tag, sens_res, sel_res);

	return 0;
}

struct near_tag *__near_tag_add(uint32_t adapter_idx, uint32_t target_idx,
				uint32_t protocols,
				uint16_t sens_res, uint8_t sel_res,
				uint8_t *nfcid, uint8_t nfcid_len)
{
	struct near_tag *tag;
	char *path;

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (tag != NULL)
		return NULL;

	tag = g_try_malloc0(sizeof(struct near_tag));
	if (tag == NULL)
		return NULL;

	if (tag_initialize(tag, adapter_idx, target_idx,
				protocols,
				sens_res, sel_res,
				nfcid, nfcid_len) < 0) {
		g_free(tag);
		return NULL;
	}

	path = g_strdup(tag->path);
	if (path == NULL) {
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

void __near_tag_remove(struct near_tag *tag)
{
	char *path = tag->path;

	DBG("path %s", tag->path);

	if (g_hash_table_lookup(tag_hash, tag->path) == NULL)
		return;

	g_dbus_unregister_interface(connection, tag->path,
						NFC_TAG_INTERFACE);

	g_hash_table_remove(tag_hash, path);
}

const char *__near_tag_get_path(struct near_tag *tag)
{
	return tag->path;
}


uint32_t __near_tag_get_idx(struct near_tag *tag)
{
	return tag->target_idx;
}

uint32_t __near_tag_get_type(struct near_tag *tag)
{
	return tag->type;
}

enum near_tag_sub_type near_tag_get_subtype(uint32_t adapter_idx,
				uint32_t target_idx)

{
	struct near_tag *tag;

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (tag == NULL)
		return NEAR_TAG_NFC_SUBTYPE_UNKNOWN;

	return tag->sub_type;
}

uint8_t *near_tag_get_nfcid(uint32_t adapter_idx, uint32_t target_idx,
				uint8_t *nfcid_len)
{
	struct near_tag *tag;
	uint8_t *nfcid;

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (tag == NULL)
		goto fail;

	nfcid = g_try_malloc0(tag->nfcid_len);
	if (nfcid == NULL)
		goto fail;

	memcpy(nfcid, tag->nfcid, tag->nfcid_len);
	*nfcid_len = tag->nfcid_len;

	return nfcid;

fail:
	*nfcid_len = 0;
	return NULL;
}

int near_tag_set_nfcid(uint32_t adapter_idx, uint32_t target_idx,
					uint8_t *nfcid, size_t nfcid_len)
{
	struct near_tag *tag;

	DBG("NFCID len %zd", nfcid_len);

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (tag == NULL)
		return -ENODEV;

	if (tag->nfcid_len > 0)
		return -EALREADY;

	if (nfcid_len > NFC_MAX_NFCID1_LEN)
		return -EINVAL;

	memcpy(tag->nfcid, nfcid, nfcid_len);
	tag->nfcid_len = nfcid_len;

	return 0;
}

int near_tag_add_data(uint32_t adapter_idx, uint32_t target_idx,
			uint8_t *data, size_t data_length)
{
	struct near_tag *tag;

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (tag == NULL)
		return -ENODEV;

	tag->data_length = data_length;
	tag->data = g_try_malloc0(data_length);
	if (tag->data == NULL)
		return -ENOMEM;

	if (data != NULL)
		memcpy(tag->data, data, data_length);

	return 0;
}

int near_tag_add_records(struct near_tag *tag, GList *records,
				near_tag_io_cb cb, int status)
{
	GList *list;
	struct near_ndef_record *record;
	char *path;

	DBG("records %p", records);

	for (list = records; list; list = list->next) {
		record = list->data;

		path = g_strdup_printf("%s/nfc%d/tag%d/record%d",
					NFC_PATH, tag->adapter_idx,
					tag->target_idx, tag->n_records);

		if (path == NULL)
			continue;

		__near_ndef_record_register(record, path);

		tag->n_records++;
		tag->records = g_list_append(tag->records, record);
	}

	__near_agent_ndef_parse_records(tag->records);

	if (cb != NULL)
		cb(tag->adapter_idx, tag->target_idx, status);

	g_list_free(records);

	return 0;
}

void near_tag_set_ro(struct near_tag *tag, near_bool_t readonly)
{
	tag->readonly = readonly;
}

void near_tag_set_blank(struct near_tag *tag, near_bool_t blank)
{
	tag->blank = blank;
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

void near_tag_set_ic_type(struct near_tag *tag, uint8_t ic_type)
{
	if (tag == NULL)
		return;

	tag->t3.ic_type = ic_type;
}

uint8_t near_tag_get_ic_type(struct near_tag *tag)
{
	if (tag == NULL)
		return 0;

	return tag->t3.ic_type;
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

	if (driver->read == NULL)
		return -EINVAL;

	driver_list = g_slist_insert_sorted(driver_list, driver, cmp_prio);

	return 0;
}

void near_tag_driver_unregister(struct near_tag_driver *driver)
{
	DBG("");

	driver_list = g_slist_remove(driver_list, driver);
}

int __near_tag_read(struct near_tag *tag, near_tag_io_cb cb)
{
	GSList *list;

	DBG("type 0x%x", tag->type);

	for (list = driver_list; list; list = list->next) {
		struct near_tag_driver *driver = list->data;

		DBG("driver type 0x%x", driver->type);

		if (driver->type == tag->type)
			return driver->read(tag->adapter_idx, tag->target_idx,
									cb);
	}

	return 0;
}

int __near_tag_write(struct near_tag *tag,
				struct near_ndef_message *ndef,
				near_tag_io_cb cb)
{
	GSList *list;
	int err;

	DBG("type 0x%x", tag->type);

	for (list = driver_list; list; list = list->next) {
		struct near_tag_driver *driver = list->data;

		DBG("driver type 0x%x", driver->type);

		if (driver->type == tag->type) {
			if (tag->blank == TRUE && driver->format != NULL) {
				DBG("Blank tag detected, formatting");
				err = driver->format(tag->adapter_idx,
						tag->target_idx, format_cb);
				if (err < 0)
					return err;
			} else {
				return driver->write(tag->adapter_idx,
						tag->target_idx, ndef,
						cb);
			}
		}
	}

	return 0;
}

int __near_tag_check_presence(struct near_tag *tag, near_tag_io_cb cb)
{
	GSList *list;

	DBG("type 0x%x", tag->type);

	for (list = driver_list; list; list = list->next) {
		struct near_tag_driver *driver = list->data;

		DBG("driver type 0x%x", driver->type);

		if (driver->type == tag->type) {
			if (driver->check_presence == NULL)
				continue;

			return driver->check_presence(tag->adapter_idx, tag->target_idx, cb);
		}
	}

	return -EOPNOTSUPP;
}

static void free_tag(gpointer data)
{
	struct near_tag *tag = data;

	DBG("tag %p", tag);

	near_ndef_records_free(tag->records);

	g_free(tag->path);
	g_free(tag->data);
	g_free(tag);
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

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
	bool readonly;

	uint8_t nfcid[NFC_MAX_NFCID1_LEN];
	uint8_t nfcid_len;

	uint8_t iso15693_dsfid;
	uint8_t iso15693_uid[NFC_MAX_ISO15693_UID_LEN];

	size_t data_length;
	uint8_t *data;

	uint32_t next_record;
	GList *records;
	bool blank;

	/* Tag specific structures */
	struct {
		uint8_t IDm[TYPE3_IDM_LEN];
		uint8_t attr[TYPE3_ATTR_BLOCK_SIZE];
		uint8_t ic_type;
	} t3;

	struct {
		uint16_t max_ndef_size;
		uint16_t c_apdu_max_size;
		uint16_t r_apdu_max_size;
		uint16_t file_id;
	} t4;

	struct {
		uint8_t blk_size;
		uint8_t num_blks;
	} t5;

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
	if (!path)
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
		if (!path)
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
		type = "Type 4A";
		break;

	case NFC_PROTO_ISO14443_B:
		type = "Type 4B";
		break;

	case NFC_PROTO_ISO15693:
		type = "Type 5";
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
	case NFC_PROTO_ISO14443_B_MASK:
		protocol = "ISO-DEP";
		break;

	case NFC_PROTO_ISO15693_MASK:
		protocol = "ISO-15693";
		break;

	default:
		near_error("Unknown tag protocol 0x%x", tag->protocol);
		protocol = NULL;
	}

	return protocol;
}

static gboolean property_get_type(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_tag *tag = user_data;
	const char *type;

	type = type_string(tag);
	if (!type)
		return FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &type);

	return TRUE;
}

static gboolean property_get_protocol(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_tag *tag = user_data;
	const char *protocol;

	protocol = protocol_string(tag);
	if (!protocol)
		return FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &protocol);

	return TRUE;
}

static gboolean property_get_readonly(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_tag *tag = user_data;
	dbus_bool_t readonly;

	readonly = tag->readonly;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &readonly);

	return TRUE;
}

static gboolean property_get_adapter(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_tag *tag = user_data;
	struct near_adapter *adapter;
	const char *path;

	adapter = __near_adapter_get(tag->adapter_idx);
	if (!adapter)
		return FALSE;

	path = __near_adapter_get_path(adapter);
	if (!path)
		return FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	return TRUE;

}

static void tag_read_cb(uint32_t adapter_idx, uint32_t target_idx, int status)
{
	struct near_tag *tag;

	tag = near_tag_get_tag(adapter_idx, target_idx);

	if (!tag)
		return;

	if (tag->write_msg) {
		dbus_message_unref(tag->write_msg);
		tag->write_msg = NULL;
	}

	__near_adapter_start_check_presence(adapter_idx, target_idx);
}

static void write_cb(uint32_t adapter_idx, uint32_t target_idx, int status)
{
	struct near_tag *tag;
	DBusConnection *conn;
	DBusMessage *reply;

	DBG("Write status %d", status);

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag)
		return;

	conn = near_dbus_get_connection();
	if (!conn)
		goto out;

	if (status != 0) {
		reply = __near_error_failed(tag->write_msg, EINVAL);
		if (reply)
			g_dbus_send_message(conn, reply);
	} else {
		g_dbus_send_reply(conn, tag->write_msg, DBUS_TYPE_INVALID);
	}

	near_ndef_records_free(tag->records);
	tag->records = NULL;
	g_free(tag->data);
	tag->data = NULL;

	if (status == 0) {
		/*
		 * If writing succeeded,
		 * check presence will be restored after reading
		 */
		__near_tag_read(tag, tag_read_cb);
		return;
	}

out:
	dbus_message_unref(tag->write_msg);
	tag->write_msg = NULL;

	__near_adapter_start_check_presence(tag->adapter_idx, tag->target_idx);
}

static void format_cb(uint32_t adapter_idx, uint32_t target_idx, int status)
{
	struct near_tag *tag;
	int err;

	DBG("format status %d", status);

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag)
		return;

	if (!tag->write_msg)
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
	int tlv_len_size, err;

	DBG("conn %p", conn);

	if (tag->readonly) {
		DBG("Read only tag");
		return __near_error_permission_denied(msg);
	}

	if (tag->write_msg)
		return __near_error_in_progress(msg);

	ndef = __ndef_build_from_message(msg);
	if (!ndef)
		return __near_error_failed(msg, EINVAL);

	tag->write_msg = dbus_message_ref(msg);

	/* Add NDEF header information depends upon tag type */
	switch (tag->type) {
	case NFC_PROTO_JEWEL:
	case NFC_PROTO_MIFARE:
	case NFC_PROTO_ISO15693:
		if (ndef->length < 0xff)
			tlv_len_size = 3;
		else
			tlv_len_size = 5;

		ndef_with_header = g_try_malloc0(sizeof(
					struct near_ndef_message));
		if (!ndef_with_header)
			goto fail;

		ndef_with_header->offset = 0;
		ndef_with_header->length = ndef->length + tlv_len_size;
		ndef_with_header->data =
				g_try_malloc0(ndef->length + tlv_len_size);
		if (!ndef_with_header->data)
			goto fail;

		ndef_with_header->data[0] = TLV_NDEF;

		if (ndef->length < 0xff) {
			ndef_with_header->data[1] = ndef->length;
		} else {
			ndef_with_header->data[1] = 0xff;
			ndef_with_header->data[2] =
					(uint8_t)(ndef->length >> 8);
			ndef_with_header->data[3] = (uint8_t)(ndef->length);
		}

		memcpy(ndef_with_header->data + tlv_len_size - 1, ndef->data,
				ndef->length);
		ndef_with_header->data[ndef->length + tlv_len_size - 1] =
									TLV_END;
		break;

	case NFC_PROTO_FELICA:
		ndef_with_header = g_try_malloc0(sizeof(
					struct near_ndef_message));
		if (!ndef_with_header)
			goto fail;

		ndef_with_header->offset = 0;
		ndef_with_header->length = ndef->length;
		ndef_with_header->data = g_try_malloc0(
						ndef_with_header->length);
		if (!ndef_with_header->data)
			goto fail;

		memcpy(ndef_with_header->data, ndef->data, ndef->length);

		break;

	case NFC_PROTO_ISO14443:
	case NFC_PROTO_ISO14443_B:
		ndef_with_header = g_try_malloc0(sizeof(
					struct near_ndef_message));
		if (!ndef_with_header)
			goto fail;

		ndef_with_header->offset = 0;
		ndef_with_header->length = ndef->length + 2;
		ndef_with_header->data = g_try_malloc0(ndef->length + 2);
		if (!ndef_with_header->data)
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
	{ GDBUS_ASYNC_METHOD("Write", GDBUS_ARGS({"attributes", "a{sv}"}),
							NULL, write_ndef) },
	{ },
};

static const GDBusPropertyTable tag_properties[] = {
	{ "Type", "s", property_get_type },
	{ "Protocol", "s", property_get_protocol },
	{ "ReadOnly", "b", property_get_readonly },
	{ "Adapter", "o", property_get_adapter },

	{ }
};

void __near_tag_append_records(struct near_tag *tag, DBusMessageIter *iter)
{
	GList *list;

	for (list = tag->records; list; list = list->next) {
		struct near_ndef_record *record = list->data;
		char *path;

		path = __near_ndef_record_get_path(record);
		if (!path)
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
	switch (sel_res) {
	case 0x00:
		return NEAR_TAG_NFC_T2_MIFARE_ULTRALIGHT;
	case 0x08:
		return NEAR_TAG_NFC_T2_MIFARE_CLASSIC_1K;
	case 0x09:
		return NEAR_TAG_NFC_T2_MIFARE_MINI;
	case 0x18:
		return NEAR_TAG_NFC_T2_MIFARE_CLASSIC_4K;
	case 0x20:
		return NEAR_TAG_NFC_T2_MIFARE_DESFIRE;
	case 0x28:
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

		switch (proto) {
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

	case NFC_PROTO_ISO14443_B_MASK:
		tag->type = NFC_PROTO_ISO14443_B;
		break;

	case NFC_PROTO_ISO15693_MASK:
		tag->type = NFC_PROTO_ISO15693;
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
			uint8_t *nfcid, uint8_t nfcid_len,
			uint8_t iso15693_dsfid,
			uint8_t iso15693_uid_len, uint8_t *iso15693_uid)
{
	DBG("");

	tag->path = g_strdup_printf("%s/nfc%d/tag%d", NFC_PATH,
					adapter_idx, target_idx);
	if (!tag->path)
		return -ENOMEM;
	tag->adapter_idx = adapter_idx;
	tag->target_idx = target_idx;
	tag->protocol = protocols;
	tag->next_record = 0;
	tag->readonly = false;

	if (nfcid_len && nfcid_len <= NFC_MAX_NFCID1_LEN) {
		tag->nfcid_len = nfcid_len;
		memcpy(tag->nfcid, nfcid, nfcid_len);
	} else if (iso15693_uid_len) {
		tag->iso15693_dsfid = iso15693_dsfid;
		memcpy(tag->iso15693_uid, iso15693_uid, iso15693_uid_len);
	}

	set_tag_type(tag, sens_res, sel_res);

	return 0;
}

struct near_tag *__near_tag_add(uint32_t adapter_idx, uint32_t target_idx,
				uint32_t protocols,
				uint16_t sens_res, uint8_t sel_res,
				uint8_t *nfcid, uint8_t nfcid_len,
				uint8_t iso15693_dsfid,
				uint8_t iso15693_uid_len, uint8_t *iso15693_uid)
{
	struct near_tag *tag;
	char *path;

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (tag)
		return NULL;

	tag = g_try_malloc0(sizeof(struct near_tag));
	if (!tag)
		return NULL;

	if (tag_initialize(tag, adapter_idx, target_idx,
				protocols,
				sens_res, sel_res,
				nfcid, nfcid_len,
				iso15693_dsfid,
				iso15693_uid_len, iso15693_uid) < 0) {
		g_free(tag);
		return NULL;
	}

	path = g_strdup(tag->path);
	if (!path) {
		g_free(tag);
		return NULL;
	}

	g_hash_table_insert(tag_hash, path, tag);

	DBG("connection %p", connection);

	g_dbus_register_interface(connection, tag->path,
					NFC_TAG_INTERFACE,
					tag_methods, NULL,
				        tag_properties, tag, NULL);

	return tag;
}

void __near_tag_remove(struct near_tag *tag)
{
	char *path = tag->path;

	DBG("path %s", tag->path);

	g_hash_table_remove(tag_hash, path);
}

const char *__near_tag_get_path(struct near_tag *tag)
{
	return tag->path;
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
	if (!tag)
		return NEAR_TAG_NFC_SUBTYPE_UNKNOWN;

	return tag->sub_type;
}

uint8_t *near_tag_get_nfcid(uint32_t adapter_idx, uint32_t target_idx,
				uint8_t *nfcid_len)
{
	struct near_tag *tag;
	uint8_t *nfcid;

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag)
		goto fail;

	nfcid = g_try_malloc0(tag->nfcid_len);
	if (!nfcid)
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
	if (!tag)
		return -ENODEV;

	if (tag->nfcid_len > 0)
		return -EALREADY;

	if (nfcid_len > NFC_MAX_NFCID1_LEN)
		return -EINVAL;

	memcpy(tag->nfcid, nfcid, nfcid_len);
	tag->nfcid_len = nfcid_len;

	return 0;
}

uint8_t *near_tag_get_iso15693_dsfid(uint32_t adapter_idx, uint32_t target_idx)
{
	struct near_tag *tag;
	uint8_t *iso15693_dsfid;

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag)
		goto fail;

	iso15693_dsfid = g_try_malloc0(NFC_MAX_ISO15693_DSFID_LEN);
	if (!iso15693_dsfid)
		goto fail;

	memcpy(iso15693_dsfid, &tag->iso15693_dsfid,
		NFC_MAX_ISO15693_DSFID_LEN);

	return iso15693_dsfid;

fail:
	return NULL;
}

uint8_t *near_tag_get_iso15693_uid(uint32_t adapter_idx, uint32_t target_idx)
{
	struct near_tag *tag;
	uint8_t *iso15693_uid;

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag)
		goto fail;

	iso15693_uid = g_try_malloc0(NFC_MAX_ISO15693_UID_LEN);
	if (!iso15693_uid)
		goto fail;

	memcpy(iso15693_uid, tag->iso15693_uid, NFC_MAX_ISO15693_UID_LEN);

	return iso15693_uid;

fail:
	return NULL;
}

int near_tag_add_data(uint32_t adapter_idx, uint32_t target_idx,
			uint8_t *data, size_t data_length)
{
	struct near_tag *tag;

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag)
		return -ENODEV;

	tag->data_length = data_length;
	tag->data = g_try_malloc0(data_length);
	if (!tag->data)
		return -ENOMEM;

	if (data)
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
					tag->target_idx, tag->next_record);

		if (!path)
			continue;

		__near_ndef_record_register(record, path);

		tag->next_record++;
		tag->records = g_list_append(tag->records, record);
	}

	__near_agent_ndef_parse_records(tag->records);

	near_dbus_property_changed_array(tag->path,
					NFC_TAG_INTERFACE, "Records",
					DBUS_TYPE_OBJECT_PATH, append_records,
					tag);

	if (cb)
		cb(tag->adapter_idx, tag->target_idx, status);

	g_list_free(records);

	return 0;
}

void near_tag_set_ro(struct near_tag *tag, bool readonly)
{
	tag->readonly = readonly;
}

void near_tag_set_blank(struct near_tag *tag, bool blank)
{
	tag->blank = blank;
}

bool near_tag_get_blank(struct near_tag *tag)
{
	return tag->blank;
}

uint8_t *near_tag_get_data(struct near_tag *tag, size_t *data_length)
{
	if (!data_length)
		return NULL;

	*data_length = tag->data_length;

	return tag->data;
}

size_t near_tag_get_data_length(struct near_tag *tag)
{
	return tag->data_length;
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
	if (!tag)
		return NEAR_TAG_MEMORY_UNKNOWN;

	return tag->layout;
}

void near_tag_set_memory_layout(struct near_tag *tag,
					enum near_tag_memory_layout layout)
{
	if (!tag)
		return;

	tag->layout = layout;
}

void near_tag_set_max_ndef_size(struct near_tag *tag, uint16_t size)
{
	if (!tag)
		return;

	tag->t4.max_ndef_size = size;
}

uint16_t near_tag_get_max_ndef_size(struct near_tag *tag)
{
	if (!tag)
		return 0;

	return tag->t4.max_ndef_size;
}

void near_tag_set_c_apdu_max_size(struct near_tag *tag, uint16_t size)
{
	if (!tag)
		return;

	tag->t4.c_apdu_max_size = size;
}

uint16_t near_tag_get_c_apdu_max_size(struct near_tag *tag)
{
	if (!tag)
		return 0;

	return tag->t4.c_apdu_max_size;
}

void near_tag_set_r_apdu_max_size(struct near_tag *tag, uint16_t size)
{
	if (!tag)
		return;

	tag->t4.r_apdu_max_size = size;
}

uint16_t near_tag_get_r_apdu_max_size(struct near_tag *tag)
{
	if (!tag)
		return 0;

	return tag->t4.r_apdu_max_size;
}

void near_tag_set_file_id(struct near_tag *tag, uint16_t file_id)
{
	if (!tag)
		return;

	tag->t4.file_id = file_id;
}

uint16_t near_tag_get_file_id(struct near_tag *tag)
{
	if (!tag)
		return 0;

	return tag->t4.file_id;
}

void near_tag_set_idm(struct near_tag *tag, uint8_t *idm, uint8_t len)
{
	if (!tag || len > TYPE3_IDM_LEN)
		return;

	memset(tag->t3.IDm, 0, TYPE3_IDM_LEN);
	memcpy(tag->t3.IDm, idm, len);
}

uint8_t *near_tag_get_idm(struct near_tag *tag, uint8_t *len)
{
	if (!tag || !len)
		return NULL;

	*len = TYPE3_IDM_LEN;
	return tag->t3.IDm;
}

void near_tag_set_attr_block(struct near_tag *tag, uint8_t *attr, uint8_t len)
{
	if (!tag || len > TYPE3_ATTR_BLOCK_SIZE)
		return;

	memset(tag->t3.attr, 0, TYPE3_ATTR_BLOCK_SIZE);
	memcpy(tag->t3.attr, attr, len);
}

uint8_t *near_tag_get_attr_block(struct near_tag *tag, uint8_t *len)
{
	if (!tag || !len)
		return NULL;

	*len = TYPE3_ATTR_BLOCK_SIZE;
	return tag->t3.attr;
}

void near_tag_set_ic_type(struct near_tag *tag, uint8_t ic_type)
{
	if (!tag)
		return;

	tag->t3.ic_type = ic_type;
}

uint8_t near_tag_get_ic_type(struct near_tag *tag)
{
	if (!tag)
		return 0;

	return tag->t3.ic_type;
}

uint8_t near_tag_get_blk_size(struct near_tag *tag)
{
	return tag->t5.blk_size;
}

void near_tag_set_blk_size(struct near_tag *tag, uint8_t blk_size)
{
	tag->t5.blk_size = blk_size;
}

uint8_t near_tag_get_num_blks(struct near_tag *tag)
{
	return tag->t5.num_blks;
}

void near_tag_set_num_blks(struct near_tag *tag, uint8_t num_blks)
{
	tag->t5.num_blks = num_blks;
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

	if (!driver->read)
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

	/* Stop check presence while reading */
	__near_adapter_stop_check_presence(tag->adapter_idx, tag->target_idx);

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
			/* Stop check presence while writing */
			__near_adapter_stop_check_presence(tag->adapter_idx,
								tag->target_idx);

			if (tag->blank && driver->format) {
				DBG("Blank tag detected, formatting");
				err = driver->format(tag->adapter_idx,
						tag->target_idx, format_cb);
			} else {
				err = driver->write(tag->adapter_idx,
							tag->target_idx, ndef,
							cb);
			}

			break;
		}
	}

	if (!list)
		err = -EOPNOTSUPP;

	if (err < 0)
		__near_adapter_start_check_presence(tag->adapter_idx,
							tag->target_idx);

	return err;
}

int __near_tag_check_presence(struct near_tag *tag, near_tag_io_cb cb)
{
	GSList *list;

	DBG("type 0x%x", tag->type);

	for (list = driver_list; list; list = list->next) {
		struct near_tag_driver *driver = list->data;

		DBG("driver type 0x%x", driver->type);

		if (driver->type == tag->type) {
			if (!driver->check_presence)
				continue;

			return driver->check_presence(tag->adapter_idx, tag->target_idx, cb);
		}
	}

	return -EOPNOTSUPP;
}

int near_tag_activate_target(uint32_t adapter_idx, uint32_t target_idx,
			uint32_t protocol)
{
	return __near_netlink_activate_target(adapter_idx, target_idx,
					protocol);
}

static void free_tag(gpointer data)
{
	struct near_tag *tag = data;

	DBG("tag %p", tag);

	near_ndef_records_free(tag->records);

	g_dbus_unregister_interface(connection, tag->path,
						NFC_TAG_INTERFACE);

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

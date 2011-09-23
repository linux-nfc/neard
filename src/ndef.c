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

#define RECORD_TNF_EMPTY     0x00
#define RECORD_TNF_WELLKNOWN 0x01
#define RECORD_TNF_MIME      0x02
#define RECORD_TNF_URI       0x03
#define RECORD_TNF_EXTERNAL  0x04
#define RECORD_TNF_UNKNOWN   0x05
#define RECORD_TNF_UNCHANGED 0x06

#define RECORD_MB_BIT(val)  ((val & 0x80) >> 7)
#define RECORD_ME_BIT(val)  ((val & 0x40) >> 6)
#define RECORD_CF_BIT(val)  ((val & 0x20) >> 5)
#define RECORD_SR_BIT(val)  ((val & 0x10) >> 4)
#define RECORD_IL_BIT(val)  ((val & 0x8)  >> 3)
#define RECORD_TNF_BIT(val) (val & 0x7)

#define NDEF_MSG_MIN_LENGTH 0x03

enum record_type {
	RECORD_TYPE_WKT_SMART_POSTER          =   0x01,
	RECORD_TYPE_WKT_URI                   =   0x02,
	RECORD_TYPE_WKT_TEXT                  =   0x03,
	RECORD_TYPE_WKT_SIZE                  =   0x04,
	RECORD_TYPE_WKT_TYPE                  =   0x05,
	RECORD_TYPE_WKT_ACTION                =   0x06,
	RECORD_TYPE_WKT_HANDOVER_REQUEST      =   0x07,
	RECORD_TYPE_WKT_HANDOVER_SELECT       =   0x08,
	RECORD_TYPE_WKT_HANDOVER_CARRIER      =   0x09,
	RECORD_TYPE_WKT_ALTERNATIVE_CARRIER   =   0x0a,
	RECORD_TYPE_WKT_COLLISION_RESOLUTION  =   0x0b,
	RECORD_TYPE_WKT_ERROR                 =   0x0c,
	RECORD_TYPE_UNKNOWN                   =   0xfe,
	RECORD_TYPE_ERROR                     =   0xff
};

struct near_ndef_record {
	char *path;
	uint8_t tnf;
	enum record_type type;
};

static DBusConnection *connection = NULL;

char *__near_ndef_record_get_path(struct near_ndef_record *record)
{
	return record->path;
}

static void append_record(struct near_ndef_record *record,
					DBusMessageIter *dict)
{
	char *type;

	DBG("");

	if (record == NULL || dict == NULL)
		return;

	switch (record->type) {
	case RECORD_TYPE_WKT_SIZE:
	case RECORD_TYPE_WKT_TYPE:
	case RECORD_TYPE_WKT_ACTION:
	case RECORD_TYPE_WKT_ALTERNATIVE_CARRIER:
	case RECORD_TYPE_WKT_COLLISION_RESOLUTION:
	case RECORD_TYPE_WKT_ERROR:
	case RECORD_TYPE_UNKNOWN:
	case RECORD_TYPE_ERROR:
		break;

	case RECORD_TYPE_WKT_TEXT:
		type = "Text";
		near_dbus_dict_append_basic(dict, "Type",
					DBUS_TYPE_STRING, &type);
		break;

	case RECORD_TYPE_WKT_URI:
		type = "URI";
		near_dbus_dict_append_basic(dict, "Type",
					DBUS_TYPE_STRING, &type);
		break;

	case RECORD_TYPE_WKT_SMART_POSTER:
		type = "SmartPoster";
		near_dbus_dict_append_basic(dict, "Type",
					DBUS_TYPE_STRING, &type);
		break;

	case RECORD_TYPE_WKT_HANDOVER_REQUEST:
		type = "HandoverRequest";
		near_dbus_dict_append_basic(dict, "Type",
					DBUS_TYPE_STRING, &type);
		break;

	case RECORD_TYPE_WKT_HANDOVER_SELECT:
		type = "HandoverSelect";
		near_dbus_dict_append_basic(dict, "Type",
					DBUS_TYPE_STRING, &type);
		break;

	case RECORD_TYPE_WKT_HANDOVER_CARRIER:
		type = "HandoverCarrier";
		near_dbus_dict_append_basic(dict, "Type",
					DBUS_TYPE_STRING, &type);
		break;
	}

}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_ndef_record *record = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	if (conn == NULL || msg == NULL ||
		data == NULL)
		return NULL;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	near_dbus_dict_open(&array, &dict);

	append_record(record, &dict);

	near_dbus_dict_close(&array, &dict);

	return reply;
}

static GDBusMethodTable record_methods[] = {
	{ "GetProperties",     "",      "a{sv}", get_properties     },
	{ },
};

static void free_ndef_record(struct near_ndef_record *record)
{
	if (record == NULL)
		return;

	g_free(record->path);

	g_free(record);
	record = NULL;
}

void __near_ndef_record_free(struct near_ndef_record *record)
{
	g_dbus_unregister_interface(connection, record->path,
						NFC_RECORD_INTERFACE);

	free_ndef_record(record);
}

/**
 * @brief returns record type
 * Validate type name format, type and type length and returns
 * type.
 *
 * @param tnf     TypeNameFormat value
 * @param type    Type name in hex foarmat
 * @param type_lenth Type name length
 *
 * @return enum record type
 */

static enum record_type get_record_type(uint8_t tnf,
				uint8_t *type, size_t type_length)
{
	DBG("");

	if (tnf == RECORD_TNF_WELLKNOWN) {
		if (type_length == 1) {
			if (type[0] == 'T')
				return RECORD_TYPE_WKT_TEXT;
			else if (type[0] == 'U')
				return RECORD_TYPE_WKT_URI;
			else if (type[0] == 's')
				return RECORD_TYPE_WKT_SIZE;
			else if (type[0] == 't')
				return RECORD_TYPE_WKT_TYPE;
			else
				return RECORD_TYPE_UNKNOWN;

		} else if (type_length == 2) {
			if (strncmp((char *)type, "Sp", 2) == 0)
				return RECORD_TYPE_WKT_SMART_POSTER;
			else if (strncmp((char *) type, "Hr", 2) == 0)
				return RECORD_TYPE_WKT_HANDOVER_REQUEST;
			else if (strncmp((char *) type, "Hs", 2) == 0)
				return RECORD_TYPE_WKT_HANDOVER_SELECT;
			else if (strncmp((char *) type, "Hc", 2) == 0)
				return RECORD_TYPE_WKT_HANDOVER_CARRIER;
			else if (strncmp((char *) type, "ac", 2) == 0)
				return RECORD_TYPE_WKT_ALTERNATIVE_CARRIER;
			else if (strncmp((char *) type, "cr", 2) == 0)
				return RECORD_TYPE_WKT_COLLISION_RESOLUTION;
			else
				return RECORD_TYPE_UNKNOWN;

		} else if (type_length == 3) {
			if (strncmp((char *)type, "act", 3) == 0)
				return RECORD_TYPE_WKT_ACTION;
			else if (strncmp((char *)type, "err", 3) == 0)
				return RECORD_TYPE_WKT_ERROR;
			else
				return RECORD_TYPE_UNKNOWN;

		}

	}

	return RECORD_TYPE_UNKNOWN;
}

static uint8_t validate_record_begin_and_end_bits(uint8_t *msg_mb,
					uint8_t *msg_me, uint8_t rec_mb,
					uint8_t rec_me)
{
	DBG("");

	if (msg_mb == NULL || msg_me == NULL)
		return 0;

	/* Validating record header begin and end bits
	 * eg: Single record: [mb:1,me:1]
	 *     Two records:   [mb:1,me:0 - mb:0,me:1]
	 *     Three or more records [mb:1,me:0 - mb:0,me:0 .. mb:0,me:1]
	 **/

	if (rec_mb == 1) {
		if (*msg_mb != 1)
			*msg_mb = rec_mb;
		else
			return -EINVAL;

	}

	if (rec_me == 1) {
		if (*msg_me != 1) {
			if (*msg_mb == 1)
				*msg_me = rec_me;
			else
				return -EINVAL;

		} else
			return -EINVAL;

	}

	return 0;
}

int near_ndef_parse(struct near_tag *tag,
			uint8_t *ndef_data, size_t ndef_length)
{
	uint8_t p_mb = 0, p_me = 0, err;
	uint32_t n_records, adapter_idx, target_idx;
	size_t offset = 0;
	struct near_ndef_record *record = NULL;

	DBG("");

	if (tag == NULL || ndef_data == NULL ||
		ndef_length < NDEF_MSG_MIN_LENGTH) {
			err = EINVAL;
			goto fail;
	}

	while (offset < ndef_length) {
		uint8_t c_mb, c_me, t_sr, t_il, t_tnf;
		uint8_t type_length, il_length = 0, r_type;
		uint8_t *type = NULL;
		uint32_t payload_length = 0;

		c_mb = RECORD_MB_BIT(ndef_data[offset]);
		c_me = RECORD_ME_BIT(ndef_data[offset]);
		t_sr = RECORD_SR_BIT(ndef_data[offset]);
		t_il = RECORD_IL_BIT(ndef_data[offset]);
		t_tnf = RECORD_TNF_BIT(ndef_data[offset]);

		/* Validate record header begin and end bits*/
		if (validate_record_begin_and_end_bits(&p_mb, &p_me,
							c_mb, c_me) != 0) {
			DBG("validate mb me failed");
			err = EINVAL;
			goto fail;
		}

		offset++;
		type_length = ndef_data[offset];

		offset++;

		if (t_sr == 1) {
			payload_length = ndef_data[offset];
			offset++;
		} else {
			payload_length = *((uint32_t *)(ndef_data + offset));
			offset += 4;

			if (offset >= ndef_length) {
				err = EINVAL;
				goto fail;
			}

		}

		if (t_il == 1) {
			il_length = ndef_data[offset];
			offset++;

			if (offset >= ndef_length) {
				err = EINVAL;
				goto fail;
			}

		}

		if ((offset + type_length + il_length + payload_length)
			> ndef_length) {
			err = EINVAL;
			goto fail;
		}

		if (type_length > 0) {
			type = g_try_malloc0(type_length);
			if (type == NULL) {
				err = ENOMEM;
				goto fail;
			}

			memcpy(type, ndef_data + offset, type_length);
		}

		r_type = get_record_type(t_tnf, type, type_length);
		offset += (type_length + il_length);

		record = g_try_malloc0(sizeof(struct near_ndef_record));
		if (record == NULL) {
			err = ENOMEM;
			goto fail;
		}

		record->tnf = t_tnf;
		record->type = r_type;

		n_records   = __near_tag_n_records(tag);
		target_idx  = near_tag_get_target_idx(tag);
		adapter_idx = near_tag_get_adapter_idx(tag);

		record->path = g_strdup_printf("%s/nfc%d/target%d/record%d",
							NFC_PATH, adapter_idx,
							target_idx, n_records);
		DBG("Record path '%s'", record->path);

		__near_tag_add_record(tag, record);

		g_dbus_register_interface(connection, record->path,
							NFC_RECORD_INTERFACE,
							record_methods,
							NULL, NULL,
							record, NULL);
		offset += payload_length;
	}

	return 0;

fail:
	near_error("ndef parsing failed");
	free_ndef_record(record);

	return -err;
}

int __near_ndef_init(void)
{
	DBG("");

	connection = near_dbus_get_connection();

	return 0;
}

void __near_ndef_cleanup(void)
{
}

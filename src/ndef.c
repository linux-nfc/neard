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

#define RECORD_TNF_WKT_TEXT             'T'
#define RECORD_TNF_WKT_URI              'U'
#define RECORD_TNF_WKT_SIZE             's'
#define RECORD_TNF_WKT_TYPE             't'
#define RECORD_TNF_WKT_SMART_POSTER     "Sp"
#define RECORD_TNF_WKT_REC_ACTION       "act"
#define RECORD_TNF_WKT_HANDOVER_REQUEST "Hr"
#define RECORD_TNF_WKT_HANDOVER_SELECT  "Hs"
#define RECORD_TNF_WKT_HANDOVER_CARRIER "Hc"

#define RECORD_MB(record)  (((record)[0] & 0x80) >> 7)
#define RECORD_ME(record)  (((record)[0] & 0x40) >> 6)
#define RECORD_CF(record)  (((record)[0] & 0x20) >> 5)
#define RECORD_SR(record)  (((record)[0] & 0x10) >> 4)
#define RECORD_IL(record)  (((record)[0] & 0x8)  >> 3)
#define RECORD_TNF(record) ((record)[0] & 0x7)

struct near_ndef_record {
	char *path;

	uint8_t tnf;
	gboolean smart_poster;
	gboolean hand_over;

	uint8_t *type;
	size_t type_length;

	uint8_t *payload;
	size_t payload_length;
};

static DBusConnection *connection = NULL;

char *__near_ndef_record_get_path(struct near_ndef_record *record)
{
	return record->path;
}

void __near_ndef_record_free(struct near_ndef_record *record)
{
	g_dbus_unregister_interface(connection, record->path,
						NFC_RECORD_INTERFACE);

	g_free(record->path);
	g_free(record);
}


static gboolean record_sp(uint8_t tnf, uint8_t *type, size_t type_length)
{
	DBG("tnf 0x%x type length %zu", tnf, type_length);

	if (tnf == RECORD_TNF_WELLKNOWN
			&& type_length == 2
	    		&& strncmp((char *)type, "Sp", 2) == 0)
		return TRUE;

	return FALSE;

}

static uint8_t record_type_offset(uint8_t *record, size_t *type_length)
{
	uint8_t sr, il;
	uint32_t offset = 0;

	sr = RECORD_SR(record);
	il = RECORD_IL(record);
	*type_length = record[1];

	/* Record header */
	offset += 1;

	/* Type length */
	offset += 1;

	if (sr == 1)
		offset += 1;
	else
		offset += 4;
	
	if (il == 1)
		offset += 1;

	return offset;
}

static uint8_t record_payload_offset(uint8_t *record, size_t *payload_length)
{
	uint8_t sr, tnf, il, type_length, id_length;
	uint32_t offset = 0;

	sr = RECORD_SR(record);
	il = RECORD_IL(record);
	tnf = RECORD_TNF(record);
	type_length = record[1];

	/* Record header */
	offset += 1;

	/* Type length */
	offset += 1;

	if (sr == 1) {
		*payload_length = record[offset];
		/* Payload length is 1 byte */
		offset += 1;
	} else {
		*payload_length = *((uint32_t *)(record + offset));
		/* Payload length is 4 bytes */
		offset += 4;
	}
	
	if (il == 1) {
		id_length = record[offset];
		offset += id_length;
	} else {
		id_length = 0;
	}	

	/* Type value */
	offset += type_length;

	if (tnf == 0) {
		offset -= type_length;
		offset -= id_length;
	}

	DBG("type length %d payload length %zu id length %d offset %d", type_length, *payload_length, id_length, offset);

	return offset;
}

static void append_rtd_text(struct near_ndef_record *record,
					DBusMessageIter *dict)
{
	uint8_t utf, language_length;
	char *encoding, *language, *value;

	DBG("");

	utf = (record->payload[0] & 0x80) >> 7;
	if (utf == 0)
		encoding = "UTF-8";
	else
		encoding = "UTF-16";

	DBG("encoding %s", encoding);

	language_length  = record->payload[0] & 0x1f;
	language = g_strndup((char *)&record->payload[1], language_length);

	DBG("language %s", language);

	value = g_strndup((char *)&record->payload[1 + language_length],
				record->payload_length - 1 -language_length);

	DBG("value %s", value);

	near_dbus_dict_append_basic(dict, "Encoding",
				    DBUS_TYPE_STRING, &encoding);

	near_dbus_dict_append_basic(dict, "Language",
				    DBUS_TYPE_STRING, &language);

	near_dbus_dict_append_basic(dict, "Representation",
				    DBUS_TYPE_STRING, &value);

	g_free(language);
	g_free(value);
}

static void append_rtd_uri(struct near_ndef_record *record,
					DBusMessageIter *dict)
{
	char *prefix, *value, *uri;

	switch (record->payload[0]) {
	case 0x0:
		prefix = NULL;
		break;
	case 0x1:
		prefix = "http://www.";
		break;
	case 0x2:
		prefix = "https://www.";
		break;
	case 0x3:
		prefix = "http://";
		break;
	case 0x4:
		prefix = "https://";
		break;
	case 0x5:
		prefix = "tel:";
		break;
	case 0x6:
		prefix = "mailto:";
		break;
	case 0x7:
		prefix = "ftp://anonymous:anonymous@";
		break;
	case 0x8:
		prefix = "ftp://ftp.";
		break;
	case 0x9:
		prefix = "ftps://";
		break;
	}

	uri = g_strndup((char *)&record->payload[1],
				record->payload_length - 1);
	value = g_strdup_printf("%s%s", prefix, uri);

	DBG("value %s", value);

	near_dbus_dict_append_basic(dict, "Representation",
				    DBUS_TYPE_STRING, &value);

	g_free(uri);
	g_free(value);
}

static void append_rtd(struct near_ndef_record *record, DBusMessageIter *dict)
{
	char *type = (char *) record->type;
	char *dbus_type = NULL;

	DBG("");

	if (record->type_length == 1) {
		switch (record->type[0]) {
		case RECORD_TNF_WKT_TEXT:
			dbus_type = "Text";
			append_rtd_text(record, dict);
			break;
		case RECORD_TNF_WKT_URI:
			dbus_type = "URI";
			append_rtd_uri(record, dict);
			break;
		case RECORD_TNF_WKT_SIZE:
			dbus_type = "Size";
			break;
		case RECORD_TNF_WKT_TYPE:
			dbus_type = "MIME Type";
			break;
		}
	} else if (record->type_length == 2) {
		if (strncmp(type, RECORD_TNF_WKT_SMART_POSTER, 2))
			dbus_type = "Smart Poster";
		if (strncmp(type, RECORD_TNF_WKT_HANDOVER_REQUEST, 2))
			dbus_type = "Hand Over Request";
		if (strncmp(type, RECORD_TNF_WKT_HANDOVER_SELECT, 2))
			dbus_type = "Hand Over Select";
		if (strncmp(type, RECORD_TNF_WKT_HANDOVER_CARRIER, 2))
			dbus_type = "Hand Over Carrier";
	} else if (record->type_length == 3)
		if (strncmp(type, RECORD_TNF_WKT_REC_ACTION, 3))
			dbus_type = "Recommended Action";

	if (dbus_type != NULL)
		near_dbus_dict_append_basic(dict, "Type",
				    DBUS_TYPE_STRING, &dbus_type);

}

static void append_record(struct near_ndef_record *record,
					DBusMessageIter *dict)
{
	char *type = NULL;
	gboolean representable = FALSE;

	if (record->tnf == RECORD_TNF_WELLKNOWN)
		return append_rtd(record, dict);

	switch (record->tnf) {
	case RECORD_TNF_EMPTY:
		type = "Empty";

	case RECORD_TNF_MIME:
		type = "MIME";
		representable = TRUE;

	case RECORD_TNF_URI:
		type = "URI";
		representable = TRUE;
	case RECORD_TNF_EXTERNAL:
		type = "NFC Forum External";
	case RECORD_TNF_UNKNOWN:
		type = "Unknown";
	case RECORD_TNF_UNCHANGED:
		type = "Unchanged";

	}

	near_dbus_dict_append_basic(dict, "Type",
				    DBUS_TYPE_STRING, &type);

	if (representable == TRUE) {
		char *value;

		value = g_strndup((char *)record->payload,
					record->payload_length);

		near_dbus_dict_append_basic(dict, "Representation",
				    DBUS_TYPE_STRING, &value);

		g_free(value);
	}
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_ndef_record *record = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	near_dbus_dict_open(&array, &dict);

	near_dbus_dict_append_basic(&dict, "SmartPoster",
				    DBUS_TYPE_BOOLEAN, &record->smart_poster);

	near_dbus_dict_append_basic(&dict, "HandOver",
				    DBUS_TYPE_BOOLEAN, &record->hand_over);

	append_record(record, &dict);

	near_dbus_dict_close(&array, &dict);

	return reply;
}

static GDBusMethodTable record_methods[] = {
	{ "GetProperties",     "",      "a{sv}", get_properties     },
	{ },
};

int near_ndef_parse(struct near_tag *tag,
			uint8_t *ndef_data, size_t ndef_length)
{
	struct near_ndef_record *record;
	uint8_t *raw_record, payload_offset, type_offset;
	gboolean smart_poster;

	raw_record = ndef_data;

	while (1) {
		uint8_t mb, me, sr, tnf, il;
		uint32_t n_records, target_idx, adapter_idx;
		size_t i, type_length;
	
		mb = RECORD_MB(raw_record);
		me = RECORD_ME(raw_record);
		sr = RECORD_SR(raw_record);
		il = RECORD_IL(raw_record);
		tnf = RECORD_TNF(raw_record);
		DBG("Record MB 0x%x ME 0x%x SR 0x%x IL 0x%x TNF 0x%x", mb, me, sr, il, tnf);

		type_offset = record_type_offset(raw_record, &type_length);

		smart_poster = record_sp(tnf, raw_record + type_offset,
								type_length);
		if (smart_poster == TRUE) {
			size_t payload_length;

			DBG("Smart Poster");

			payload_offset = record_payload_offset(raw_record, &payload_length);

			raw_record += payload_offset;

			continue;
		}

		record = g_try_malloc0(sizeof(struct near_ndef_record));
		if (record == NULL)
			return -ENOMEM;

		record->tnf = tnf;

		payload_offset = record_payload_offset(raw_record, &record->payload_length);
		record->payload = raw_record + payload_offset;

		type_offset = record_type_offset(raw_record, &record->type_length);
		record->type = raw_record + type_offset;

		record->smart_poster = smart_poster;

		n_records = __near_tag_n_records(tag);
		target_idx = near_tag_get_target_idx(tag);
		adapter_idx = near_tag_get_adapter_idx(tag);
		record->path = g_strdup_printf("%s/nfc%d/target%d/record%d",
						NFC_PATH, adapter_idx, target_idx,
						n_records); 

		for (i = 0; i < record->payload_length; i++)
			DBG("Payload[%d] %c 0x%x", i, record->payload[i], record->payload[i]);

		DBG("Record path %s", record->path);
		__near_tag_add_record(tag, record);

		g_dbus_register_interface(connection, record->path,
					NFC_RECORD_INTERFACE,
					record_methods, NULL,
						NULL, record, NULL);

		if (me == 1)
			break;

		raw_record = record->payload + record->payload_length;
	}

	return 0;
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

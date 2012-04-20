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

enum record_tnf {
	RECORD_TNF_EMPTY     = 0x00,
	RECORD_TNF_WELLKNOWN = 0x01,
	RECORD_TNF_MIME      = 0x02,
	RECORD_TNF_URI       = 0x03,
	RECORD_TNF_EXTERNAL  = 0x04,
	RECORD_TNF_UNKNOWN   = 0x05,
	RECORD_TNF_UNCHANGED = 0x06,
};

#define RECORD_ACTION_DO   0x00
#define RECORD_ACTION_SAVE 0x01
#define RECORD_ACTION_EDIT 0x02

#define RECORD_MB_BIT(val)  ((val & 0x80) >> 7)
#define RECORD_ME_BIT(val)  ((val & 0x40) >> 6)
#define RECORD_CF_BIT(val)  ((val & 0x20) >> 5)
#define RECORD_SR_BIT(val)  ((val & 0x10) >> 4)
#define RECORD_IL_BIT(val)  ((val & 0x8)  >> 3)
#define RECORD_TNF_BIT(val) (val & 0x7)

#define NDEF_MSG_MIN_LENGTH 0x03

#define RECORD_MB    0x80
#define RECORD_ME    0x40
#define RECORD_CF    0x20
#define RECORD_SR    0x10
#define RECORD_IL    0x08
#define RECORD_TNF_EMPTY_SET(val)     ((val & ~0x7) | RECORD_TNF_EMPTY)
#define RECORD_TNF_WKT_SET(val)       ((val & ~0x7) | RECORD_TNF_WELLKNOWN)
#define RECORD_TNF_MIME_SET(val)      ((val & ~0x7) | RECORD_TNF_MIME)
#define RECORD_TNF_URI_SET(val)       ((val & ~0x7) | RECORD_TNF_URI)
#define RECORD_TNF_EXTERNAL_SET(val)  ((val & ~0x7) | RECORD_TNF_EXTERNAL)
#define RECORD_TNF_UKNOWN_SET(val)    ((val & ~0x7) | RECORD_TNF_UNKNOWN)
#define RECORD_TNF_UNCHANGED_SET(val) ((val & ~0x7) | RECORD_TNF_UNCHANGED)

#define NDEF_MSG_SHORT_RECORD_MAX_LENGTH 0xFF
#define NDEF_TEXT_RECORD_TYPE_NAME_HEX_VALUE 0x54
#define NDEF_TEXT_RECORD_UTF16_STATUS 0x80

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
	RECORD_TYPE_MIME_TYPE                 =   0x0d,
	RECORD_TYPE_UNKNOWN                   =   0xfe,
	RECORD_TYPE_ERROR                     =   0xff
};

struct near_ndef_record_header {
	uint8_t mb;
	uint8_t me;
	uint8_t cf;
	uint8_t sr;
	uint8_t il;
	uint8_t tnf;
	uint8_t il_length;
	uint8_t *il_field;
	uint32_t payload_len;
	uint32_t offset;
	enum record_type rec_type;
	char *type_name;
};

struct near_ndef_text_record {
	char *encoding;
	char *language_code;
	char *data;
};

struct near_ndef_uri_record {
	uint8_t identifier;

	uint32_t  field_length;
	uint8_t  *field;
};

struct near_ndef_sp_record {
	struct near_ndef_uri_record *uri;

	uint8_t number_of_title_records;
	struct near_ndef_text_record **title_records;

	uint32_t size; /* from Size record*/
	char *type;    /* from Type record*/
	char *action;
	/* TODO add icon and other records fields*/
};

struct near_ndef_mime_record {
	char *type;
};

struct near_ndef_record {
	char *path;

	struct near_ndef_record_header *header;

	/* WKT record */
	struct near_ndef_text_record *text;
	struct near_ndef_uri_record  *uri;
	struct near_ndef_sp_record   *sp;

	/* MIME type */
	struct near_ndef_mime_record *mime;
};

static DBusConnection *connection = NULL;

static inline void fillb8(uint8_t *ptr, uint32_t len)
{
	(*(uint8_t *)(ptr)) = ((uint8_t)(len));
}

static inline void fillb16(uint8_t *ptr, uint32_t len)
{
	fillb8((ptr), (uint16_t)(len) >> 8);
	fillb8((uint8_t *)(ptr) + 1, len);
}

static inline void fillb32(uint8_t *ptr, uint32_t len)
{
	fillb16((ptr), (uint32_t)(len) >> 16);
	fillb16((uint8_t *)(ptr) + 2, (uint32_t)(len));
}

char *__near_ndef_record_get_path(struct near_ndef_record *record)
{
	return record->path;
}

static void append_text_record(struct near_ndef_text_record *text,
					DBusMessageIter *dict)
{
	DBG("");

	if (text == NULL || dict == NULL)
		return;

	if (text->encoding != NULL)
		near_dbus_dict_append_basic(dict, "Encoding",
						DBUS_TYPE_STRING,
						&(text->encoding));

	if (text->language_code != NULL)
		near_dbus_dict_append_basic(dict, "Language",
						DBUS_TYPE_STRING,
						&(text->language_code));

	if (text->data != NULL)
		near_dbus_dict_append_basic(dict, "Representation",
						DBUS_TYPE_STRING,
						&(text->data));

}

static const char *uri_prefix[NFC_MAX_URI_ID + 1] = {
	"",
	"http://www.",
	"https://www.",
	"http://",
	"https://",
	"tel:",
	"mailto:",
	"ftp://anonymous:anonymous@",
	"ftp://ftp.",
	"ftps://",
	"sftp://",
	"smb://",
	"nfs://",
	"ftp://",
	"dav://",
	"news:",
	"telnet://",
	"imap:",
	"rstp://",
	"urn:",
	"pop:",
	"sip:",
	"sips:",
	"tftp:",
	"btspp://",
	"btl2cap://",
	"btgoep://",
	"tcpobex://",
	"irdaobex://",
	"file://",
	"urn:epc:id:",
	"urn:epc:tag:",
	"urn:epc:pat:",
	"urn:epc:raw:",
	"urn:epc:",
	"urn:nfc:",
};

const char *__near_ndef_get_uri_prefix(uint8_t id)
{
	if (id > NFC_MAX_URI_ID)
		return NULL;

	return uri_prefix[id];
}

static void append_uri_record(struct near_ndef_uri_record *uri,
					DBusMessageIter *dict)
{
	char *value;
	const char *prefix = NULL;

	DBG("");

	if (uri == NULL || dict == NULL)
		return;

	if (uri->identifier > NFC_MAX_URI_ID) {
		near_error("Invalid URI identifier 0x%x", uri->identifier);
		return;
	}

	prefix = uri_prefix[uri->identifier];

	DBG("URI prefix %s", prefix);

	value = g_strdup_printf("%s%.*s", prefix, uri->field_length,
							 uri->field);

	near_dbus_dict_append_basic(dict, "URI", DBUS_TYPE_STRING, &value);

	g_free(value);
}

static void append_smart_poster_record(struct near_ndef_sp_record *sp,
						DBusMessageIter *dict)
{
	uint8_t i;

	DBG("");

	if (sp == NULL || dict == NULL)
		return;

	if (sp->action != NULL)
		near_dbus_dict_append_basic(dict, "Action", DBUS_TYPE_STRING,
							&(sp->action));

	if (sp->uri != NULL)
		append_uri_record(sp->uri, dict);

	if (sp->title_records != NULL &&
			sp->number_of_title_records > 0) {
		for (i = 0; i < sp->number_of_title_records; i++)
			append_text_record(sp->title_records[i], dict);
	}

	if (sp->type != NULL)
		near_dbus_dict_append_basic(dict, "MIMEType", DBUS_TYPE_STRING,
								&(sp->type));

	if (sp->size > 0)
		near_dbus_dict_append_basic(dict, "Size", DBUS_TYPE_UINT32,
							&(sp->size));
}

static void append_mime_record(struct near_ndef_mime_record *mime,
					DBusMessageIter *dict)
{
	DBG("");

	if (mime == NULL || dict == NULL)
		return;

	if (mime->type != NULL)
		near_dbus_dict_append_basic(dict, "MIME",
						DBUS_TYPE_STRING,
						&(mime->type));
}

static void append_record(struct near_ndef_record *record,
					DBusMessageIter *dict)
{
	char *type;

	DBG("");

	if (record == NULL || dict == NULL)
		return;

	switch (record->header->rec_type) {
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
		append_text_record(record->text, dict);
		break;

	case RECORD_TYPE_WKT_URI:
		type = "URI";
		near_dbus_dict_append_basic(dict, "Type",
					DBUS_TYPE_STRING, &type);
		append_uri_record(record->uri, dict);
		break;

	case RECORD_TYPE_WKT_SMART_POSTER:
		type = "SmartPoster";
		near_dbus_dict_append_basic(dict, "Type",
					DBUS_TYPE_STRING, &type);
		append_smart_poster_record(record->sp, dict);
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

	case RECORD_TYPE_MIME_TYPE:
		type = "MIME Type (RFC 2046)";
		near_dbus_dict_append_basic(dict, "Type",
					DBUS_TYPE_STRING, &type);
		append_mime_record(record->mime, dict);
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

static void free_text_record(struct near_ndef_text_record *text)
{
	if (text == NULL)
		return;

	g_free(text->encoding);
	g_free(text->language_code);
	g_free(text->data);
	g_free(text);

	text = NULL;
}

static void free_uri_record(struct near_ndef_uri_record *uri)
{
	if (uri == NULL)
		return;

	g_free(uri->field);
	g_free(uri);

	uri = NULL;
}

static void free_sp_record(struct near_ndef_sp_record *sp)
{
	uint8_t i;

	if (sp == NULL)
		return;

	free_uri_record(sp->uri);

	if (sp->title_records != NULL) {
		for (i = 0; i < sp->number_of_title_records; i++)
			free_text_record(sp->title_records[i]);
	}

	g_free(sp->title_records);
	g_free(sp->type);
	g_free(sp->action);
	g_free(sp);

	sp = NULL;
}

static void free_mime_record(struct near_ndef_mime_record *mime)
{
	if (mime == NULL)
		return;

	g_free(mime->type);
	g_free(mime);

	mime = NULL;
}

static void free_ndef_record(struct near_ndef_record *record)
{
	if (record == NULL)
		return;

	g_free(record->path);

	if (record->header != NULL) {

		switch (record->header->rec_type) {
		case RECORD_TYPE_WKT_SIZE:
		case RECORD_TYPE_WKT_TYPE:
		case RECORD_TYPE_WKT_ACTION:
		case RECORD_TYPE_WKT_HANDOVER_REQUEST:
		case RECORD_TYPE_WKT_HANDOVER_SELECT:
		case RECORD_TYPE_WKT_HANDOVER_CARRIER:
		case RECORD_TYPE_WKT_ALTERNATIVE_CARRIER:
		case RECORD_TYPE_WKT_COLLISION_RESOLUTION:
		case RECORD_TYPE_WKT_ERROR:
		case RECORD_TYPE_UNKNOWN:
		case RECORD_TYPE_ERROR:
			break;

		case RECORD_TYPE_WKT_TEXT:
			free_text_record(record->text);
			break;

		case RECORD_TYPE_WKT_URI:
			free_uri_record(record->uri);
			break;

		case RECORD_TYPE_WKT_SMART_POSTER:
			free_sp_record(record->sp);
			break;

		case RECORD_TYPE_MIME_TYPE:
			free_mime_record(record->mime);
		}

		g_free(record->header->il_field);
		g_free(record->header->type_name);
	}

	g_free(record->header);
	g_free(record);
	record = NULL;
}

void __near_ndef_record_free(struct near_ndef_record *record)
{
	g_dbus_unregister_interface(connection, record->path,
						NFC_RECORD_INTERFACE);

	free_ndef_record(record);
}

static char *action_to_string(uint8_t action)
{
	switch (action) {
	case RECORD_ACTION_DO:
		return "Do";
	case RECORD_ACTION_SAVE:
		return "Save";
	case RECORD_ACTION_EDIT:
		return "Edit";
	default:
		near_error("Unknown action 0x%x", action);
		return NULL;
	}
}

/**
 * @brief returns record type for external type
 * Validate type and type length and returns
 * type.
 *
 * @param type    Type name in hex foarmat
 * @param type_lenth Type name length
 *
 * @return enum record type
 */

static enum record_type get_external_record_type(uint8_t *type,
						size_t type_length)
{
	DBG("");

	if (strncmp((char *) type, "nokia.com:bt", 12) == 0)
		return RECORD_TYPE_MIME_TYPE;
	else
		return RECORD_TYPE_UNKNOWN;
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

static enum record_type get_record_type(enum record_tnf tnf,
				uint8_t *type, size_t type_length)
{
	DBG("");

	switch (tnf) {
	case RECORD_TNF_EMPTY:
	case RECORD_TNF_URI:
	case RECORD_TNF_UNKNOWN:
	case RECORD_TNF_UNCHANGED:
		break;

	case RECORD_TNF_WELLKNOWN:
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

	case RECORD_TNF_MIME:
		return RECORD_TYPE_MIME_TYPE;

	case RECORD_TNF_EXTERNAL:
		return get_external_record_type(type, type_length);

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

/**
 * @brief Parse the ndef record header.
 *
 * Parse the ndef record header and cache the begin, end, chunkflag,
 * short-record and type-name-format bits. ID length and field, record
 * type, paylaod length and offset (where payload byte starts in input
 * parameter). Validate offset for everystep forward against total
 * available length.
 *
 * @note : Caller responsibility to free the memory.
 *
 * @param[in] rec      ndef byte stream
 * @param[in] offset   record header offset
 * @param[in] length   total length in byte stream
 *
 * @return struct near_ndef_record_header * RecordHeader on Success
 *                                          NULL   on Failure
 */
static struct near_ndef_record_header *parse_record_header(uint8_t *rec,
					uint32_t offset, uint32_t length)
{
	struct near_ndef_record_header *rec_header = NULL;
	uint8_t type_len, *type = NULL;

	DBG("length %d", length);

	if (rec == NULL || offset >= length)
		return NULL;

	/* This check is for empty record. */
	if ((length - offset) < NDEF_MSG_MIN_LENGTH)
		return NULL;

	rec_header = g_try_malloc0(sizeof(struct near_ndef_record_header));
	if (rec_header == NULL)
		return NULL;

	rec_header->mb = RECORD_MB_BIT(rec[offset]);
	rec_header->me = RECORD_ME_BIT(rec[offset]);
	rec_header->sr = RECORD_SR_BIT(rec[offset]);
	rec_header->il = RECORD_IL_BIT(rec[offset]);
	rec_header->tnf = RECORD_TNF_BIT(rec[offset]);

	DBG("mb %d me %d sr %d il %d tnf %d",
		rec_header->mb, rec_header->me, rec_header->sr,
		rec_header->il, rec_header->tnf);

	offset++;
	type_len = rec[offset++];

	if (rec_header->sr == 1) {
		rec_header->payload_len = rec[offset++];
	} else {
		rec_header->payload_len =
			g_ntohl(*((uint32_t *)(rec + offset)));
		offset += 4;

		if (offset >= length)
			goto fail;
	}

	DBG("payload length %d", rec_header->payload_len);

	if (rec_header->il == 1) {
		rec_header->il_length = rec[offset++];

		if (offset >= length)
			goto fail;
	}

	if (type_len > 0) {
		if ((offset + type_len) > length)
			goto fail;

		type = g_try_malloc0(type_len);
		if (type == NULL)
			goto fail;

		memcpy(type, rec + offset, type_len);
		offset += type_len;

		if (offset >= length)
			goto fail;
	}

	if (rec_header->il_length > 0) {
		if ((offset + rec_header->il_length) > length)
			goto fail;

		rec_header->il_field = g_try_malloc0(rec_header->il_length);
		if (rec_header->il_field == NULL)
			goto fail;

		memcpy(rec_header->il_field, rec + offset,
					rec_header->il_length);
		offset += rec_header->il_length;

		if (offset >= length)
			goto fail;
	}

	if ((offset + rec_header->payload_len) > length)
		goto fail;

	rec_header->rec_type = get_record_type(rec_header->tnf, type, type_len);
	rec_header->offset = offset;
	rec_header->type_name = g_strndup((char *) type, type_len);

	g_free(type);

	return rec_header;

fail:
	near_error("parsing record header failed");

	g_free(type);
	g_free(rec_header->il_field);
	g_free(rec_header->type_name);
	g_free(rec_header);

	return NULL;
}

/**
 * @brief Parse the Text record payload
 *
 * Parse the Text record.
 *
 * @param[in] rec     NDEF pointer set to record payload first byte
 * @param[in] length  payload_len
 *
 * @return struct near_ndef_text_record * Record on Success
 *                                       NULL   on Failure
 */

static struct near_ndef_text_record *
parse_text_record(uint8_t *rec, uint32_t length)
{
	struct near_ndef_text_record *text_record = NULL;
	uint8_t status, lang_length;
	uint32_t offset;

	DBG("");

	if (rec == NULL)
		return NULL;

	offset = 0;
	text_record = g_try_malloc0(sizeof(struct near_ndef_text_record));
	if (text_record == NULL)
		return NULL;

	/* 0x80 is used to get 7th bit value (0th bit is LSB) */
	status = ((rec[offset] & 0x80) >> 7);

	text_record->encoding = (status == 0) ?
					g_strdup("UTF-8") : g_strdup("UTF-16");

	/* 0x3F is used to get 5th-0th bits value (0th bit is LSB) */
	lang_length = (rec[offset] & 0x3F);
	offset++;

	if (lang_length > 0) {
		if ((offset + lang_length) >= length)
			goto fail;

		text_record->language_code = g_strndup(
						(char *)(rec + offset),
						lang_length);
	} else {
		text_record->language_code = NULL;
	}

	offset += lang_length;

	if ((length - lang_length - 1) > 0) {
		text_record->data = g_strndup((char *)(rec + offset),
					length - lang_length - 1);
	} else {
		text_record->data = NULL;
	}

	if (offset >= length)
		goto fail;

	DBG("Encoding  '%s'", text_record->encoding);
	DBG("Language Code  '%s'", text_record->language_code);
	DBG("Data  '%s'", text_record->data);

	return text_record;

fail:
	near_error("text record parsing failed");
	free_text_record(text_record);

	return NULL;
}

/**
 * @brief Parse the URI record payload
 *
 * Parse the URI record.
 *
 * @param[in] rec          NDEF pointer set to record payload first byte
 * @param[in] length  Payload length
 *
 * @return struct near_ndef_uri_record * Record on Success
 *                                       NULL   on Failure
 */

static struct near_ndef_uri_record *
parse_uri_record(uint8_t *rec, uint32_t length)
{
	struct near_ndef_uri_record *uri_record = NULL;
	uint32_t index, offset;

	DBG("");

	if (rec == NULL)
		return NULL;

	offset = 0;
	uri_record = g_try_malloc0(sizeof(struct near_ndef_uri_record));
	if (uri_record == NULL)
		return NULL;

	uri_record->identifier = rec[offset];
	offset++;

	uri_record->field_length = length - 1;

	if (uri_record->field_length > 0) {
		uri_record->field = g_try_malloc0(uri_record->field_length);
		if (uri_record->field == NULL)
			goto fail;

		memcpy(uri_record->field, rec + offset,
				uri_record->field_length);

		for (index = 0; index < uri_record->field_length; index++) {
			/* URI Record Type Definition 1.0 [3.2.3]
			 * Any character value within the URI between
			 * (and including) 0 and 31 SHALL be recorded as
			 * an error, and the URI record to be discarded */
			if (uri_record->field[index] <= 31)
				goto fail;
		}

	}

	DBG("Identfier  '0X%X'", uri_record->identifier);
	DBG("Field  '%.*s'", uri_record->field_length, uri_record->field);

	return uri_record;

fail:
	near_error("uri record parsing failed");
	free_uri_record(uri_record);

	return NULL;
}

/**
 * @brief Validate titles records language code in Smartposter.
 * There must not be two or more records with the same language identifier.
 *
 * @param[in] GSList *  list of title recods (struct near_ndef_text_record *)
 *
 * @return Zero on success
 *         Negative value on failure
 */

static int8_t validate_language_code_in_sp_record(GSList *titles)
{
	uint8_t i, j, length;
	struct near_ndef_text_record *title1, *title2;

	DBG("");

	if (titles == NULL)
		return -EINVAL;

	length = g_slist_length(titles);

	for (i = 0; i < length; i++) {
		title1 = g_slist_nth_data(titles, i);

		for (j = i + 1; j < length; j++) {
			title2 = g_slist_nth_data(titles, j);

			if ((title1->language_code == NULL) &&
					(title2->language_code == NULL))
				continue;

			if (g_strcmp0(title1->language_code,
					title2->language_code) == 0)
				return -EINVAL;
		}
	}

	return 0;
}

/**
 * @brief Parse the smart poster record payload.
 *
 * Parse the smart poster record and cache the
 * data in respective fields of smart poster structure.
 *
 * @note Caller responsibility to free the memory.
 *
 * @param[in] rec         NDEF pointer set to record payload first byte
 * @param[in] length Record payload length
 *
 * @return struct near_ndef_sp_record * Record on Success
 *                                      NULL   on Failure
 */

static struct near_ndef_sp_record *
parse_smart_poster_record(uint8_t *rec,	uint32_t length)
{
	struct near_ndef_sp_record *sp_record = NULL;
	struct near_ndef_record_header *rec_header = NULL;
	uint8_t mb = 0, me = 0, i;
	uint32_t offset;
	GSList *titles = NULL, *temp;

	DBG("");

	if (rec == NULL)
		return NULL;

	offset = 0;
	sp_record = g_try_malloc0(sizeof(struct near_ndef_sp_record));
	if (sp_record == NULL)
		return NULL;

	while (offset < length) {

		DBG("Record header : 0x%x", rec[offset]);

		rec_header = parse_record_header(rec, offset, length);
		if (rec_header == NULL)
			goto fail;

		if (validate_record_begin_and_end_bits(&mb, &me,
					rec_header->mb,	rec_header->me) != 0) {
			DBG("validate mb me failed");
			goto fail;
		}

		offset = rec_header->offset;

		switch (rec_header->rec_type) {
		case RECORD_TYPE_WKT_SMART_POSTER:
		case RECORD_TYPE_WKT_HANDOVER_REQUEST:
		case RECORD_TYPE_WKT_HANDOVER_SELECT:
		case RECORD_TYPE_WKT_HANDOVER_CARRIER:
		case RECORD_TYPE_WKT_ALTERNATIVE_CARRIER:
		case RECORD_TYPE_WKT_COLLISION_RESOLUTION:
		case RECORD_TYPE_MIME_TYPE:
		case RECORD_TYPE_WKT_ERROR:
		case RECORD_TYPE_UNKNOWN:
		case RECORD_TYPE_ERROR:
			break;

		case RECORD_TYPE_WKT_URI:
			/* URI record should be only one. */
			if (sp_record->uri != NULL)
				goto fail;

			sp_record->uri = parse_uri_record(rec + offset,
						rec_header->payload_len);
			if (sp_record->uri == NULL)
				goto fail;

			break;

		case RECORD_TYPE_WKT_TEXT:
			/*
			 * Title records can zero or more. First fill the
			 * records in list and validate language identifier
			 * and then cache them into sp record structure.
			 */
			{
			struct near_ndef_text_record *title;
			title = parse_text_record(rec + offset,
						rec_header->payload_len);
			if (title == NULL)
				goto fail;

			titles = g_slist_append(titles, title);
			}
			break;

		case RECORD_TYPE_WKT_SIZE:
			/*
			 * If payload length is not exactly 4 bytes
			 * then record is wrong.
			 */
			if (rec_header->payload_len != 4)
				goto fail;

			sp_record->size =
				g_ntohl(*((uint32_t *)(rec + offset)));
			break;

		case RECORD_TYPE_WKT_TYPE:

			if (rec_header->payload_len > 0) {
				sp_record->type = g_try_malloc0(
						rec_header->payload_len);
				if (sp_record->type == NULL)
					goto fail;

				sp_record->type = g_strndup(
						(char *) rec + offset,
						rec_header->payload_len);
			}

			break;

		case RECORD_TYPE_WKT_ACTION:
			/*
			 * If the action record exists, payload should be
			 * single byte, otherwise consider it as error.
			 */
			if (rec_header->payload_len != 1)
				goto fail;

			sp_record->action =
				g_strdup(action_to_string(rec[offset]));

			break;
		}

		offset += rec_header->payload_len;
		g_free(rec_header->il_field);
		g_free(rec_header->type_name);
		g_free(rec_header);
		rec_header = NULL;
	}

	/*
	 * Code to fill smart poster record structure from
	 * 'titles' list.
	 */
	if (titles == NULL)
		return sp_record;

	if (validate_language_code_in_sp_record(titles) != 0) {
		DBG("language code validation failed");
		goto fail;
	}

	temp = titles;
	sp_record->number_of_title_records = g_slist_length(temp);
	sp_record->title_records = g_try_malloc0(
				sp_record->number_of_title_records *
				 sizeof(struct near_ndef_text_record *));
	if (sp_record->title_records == NULL)
		goto fail;

	for (i = 0; i < sp_record->number_of_title_records; i++) {
		sp_record->title_records[i] = temp->data;
		temp = temp->next;
	}

	g_slist_free(titles);
	titles = NULL;

	return sp_record;

fail:
	near_error("smart poster record parsing failed");

	if (rec_header != NULL) {
		g_free(rec_header->type_name);
		g_free(rec_header->il_field);
		g_free(rec_header);
	}

	free_sp_record(sp_record);
	g_slist_free(titles);

	return NULL;
}

static struct near_ndef_mime_record *
parse_mime_type(struct near_ndef_record *record,
			uint8_t *ndef_data, size_t ndef_length, size_t offset,
			uint32_t payload_length)
{
	struct near_ndef_mime_record *mime = NULL;
	int err = 0;

	DBG("");

	if ((ndef_data == NULL) || ((offset + payload_length) > ndef_length))
		return NULL;

	mime = g_try_malloc0(sizeof(struct near_ndef_mime_record));
	if (mime == NULL)
		return NULL;

	mime->type = g_strdup(record->header->type_name);

	DBG("MIME Type  '%s'", mime->type);
	if (strcmp(mime->type, "application/vnd.bluetooth.ep.oob") == 0) {
		err = __near_bt_parse_oob_record(BT_MIME_V2_1,
				&ndef_data[offset]);
	} else if (strcmp(mime->type, "nokia.com:bt") == 0) {
		err = __near_bt_parse_oob_record(BT_MIME_V2_0,
				&ndef_data[offset]);
	}

	if (err < 0) {
		DBG("Parsing mime error %d", err);
		g_free(mime->type);
		g_free(mime);
		return NULL;
	}

	return mime;
}

int __near_ndef_record_register(struct near_ndef_record *record, char *path)
{
	record->path = path;

	g_dbus_register_interface(connection, record->path,
						NFC_RECORD_INTERFACE,
						record_methods,
						NULL, NULL,
						record, NULL);

	return 0;
}

GList *near_ndef_parse(uint8_t *ndef_data, size_t ndef_length)
{
	GList *records;
	uint8_t p_mb = 0, p_me = 0;
	size_t offset = 0;
	struct near_ndef_record *record = NULL;

	DBG("");

	records = NULL;

	if (ndef_data == NULL ||
		ndef_length < NDEF_MSG_MIN_LENGTH)
			goto fail;

	while (offset < ndef_length) {

		DBG("Record Header : 0x%X", ndef_data[offset]);

		record = g_try_malloc0(sizeof(struct near_ndef_record));
		if (record == NULL)
			goto fail;

		record->header = parse_record_header(ndef_data, offset,
							ndef_length);
		if (record->header == NULL)
			goto fail;

		if (validate_record_begin_and_end_bits(&p_mb, &p_me,
					record->header->mb,
					record->header->me) != 0) {
			DBG("validate mb me failed");
			goto fail;
		}

		offset = record->header->offset;

		switch (record->header->rec_type) {
		case RECORD_TYPE_WKT_SIZE:
		case RECORD_TYPE_WKT_TYPE:
		case RECORD_TYPE_WKT_ACTION:
		case RECORD_TYPE_WKT_HANDOVER_REQUEST:
		case RECORD_TYPE_WKT_HANDOVER_SELECT:
		case RECORD_TYPE_WKT_HANDOVER_CARRIER:
		case RECORD_TYPE_WKT_ALTERNATIVE_CARRIER:
		case RECORD_TYPE_WKT_COLLISION_RESOLUTION:
		case RECORD_TYPE_WKT_ERROR:
		case RECORD_TYPE_UNKNOWN:
		case RECORD_TYPE_ERROR:
			break;

		case RECORD_TYPE_WKT_TEXT:
			record->text = parse_text_record(ndef_data + offset,
						record->header->payload_len);

			if (record->text == NULL)
				goto fail;

			break;

		case RECORD_TYPE_WKT_URI:
			record->uri = parse_uri_record(ndef_data + offset,
						record->header->payload_len);

			if (record->uri == NULL)
				goto fail;

			break;

		case RECORD_TYPE_WKT_SMART_POSTER:
			record->sp = parse_smart_poster_record(
						ndef_data + offset,
						record->header->payload_len);

			if (record->sp == NULL)
				goto fail;

			break;

		case RECORD_TYPE_MIME_TYPE:
			record->mime = parse_mime_type(record, ndef_data,
						ndef_length, offset,
						record->header->payload_len);


			if (record->mime == NULL)
				goto fail;

			break;
		}

		records = g_list_append(records, record);

		offset += record->header->payload_len;
	}

	return records;

fail:
	near_error("ndef parsing failed");
	free_ndef_record(record);

	return records;
}

/**
 * @brief Allocates ndef message struture
 *
 * Allocates ndef message structure and fill message header byte,
 * type length byte, payload length and type name. Offset is payload
 * first byte (caller of this API can start filling their payload
 * from offset value).
 *
 * @note : caller responsibility to free the input and output
 *         parameters memory.
 *
 * @param[in] type_name    Record type name
 * @param[in] payload_len  Record payload length
 *
 * @return struct near_ndef_message * - Success
 *         NULL - Failure
 */
static struct near_ndef_message *ndef_message_alloc(char* type_name,
							uint32_t payload_len)
{
	struct near_ndef_message *msg;
	uint8_t hdr = 0, type_len, sr_bit;

	msg = g_try_malloc0(sizeof(struct near_ndef_message));
	if (msg == NULL)
		return NULL;

	msg->length = 0;
	msg->offset = 0;
	msg->length++; /* record header*/
	msg->length++; /* type name length byte*/

	type_len = (type_name != NULL) ? strlen(type_name) : 0;
	sr_bit =  (payload_len <= NDEF_MSG_SHORT_RECORD_MAX_LENGTH)
			? TRUE : FALSE;

	msg->length += (sr_bit == TRUE) ? 1 : 4;
	msg->length += type_len;
	msg->length += payload_len;

	msg->data = g_try_malloc0(msg->length);
	if (msg->data == NULL)
		goto fail;

	hdr |= RECORD_MB;
	hdr |= RECORD_ME;

	if (sr_bit == TRUE)
		hdr |= RECORD_SR;

	hdr = RECORD_TNF_WKT_SET(hdr);

	msg->data[msg->offset++] = hdr;
	msg->data[msg->offset++] = type_len;

	if (sr_bit == TRUE) {
		msg->data[msg->offset++] = payload_len;
	} else {
		fillb32((msg->data + msg->offset), payload_len);
		msg->offset += 4;
	}

	if (type_name != NULL) {
		memcpy(msg->data + msg->offset, type_name, type_len);
		msg->offset += type_len;
	}

	return msg;

fail:
	near_error("ndef message struct allocation failed");
	g_free(msg->data);
	g_free(msg);

	return NULL;
}

/**
 * @brief Prepare Text ndef record
 *
 * Prepare text ndef record with provided input data and return
 * ndef message structure (lenght and byte stream) in success or
 * NULL in failure case.
 *
 * @note : caller responsibility to free the input and output
 *         parameters memory.
 *
 * @param[in] encoding      Encoding (UTF-8 | UTF-16)
 * @param[in] language_code Language Code
 * @param[in] text          Actual text
 *
 * @return struct near_ndef_message * - Success
 *         NULL - Failure
 */
struct near_ndef_message *near_ndef_prepare_text_record(char *encoding,
						char *language_code, char *text)
{
	struct near_ndef_message *msg;
	uint32_t text_len, payload_length;
	uint8_t  code_len, status = 0;

	DBG("");

	/* Validate input parameters*/
	if (((g_strcmp0(encoding, "UTF-8") != 0) &&
		 (g_strcmp0(encoding, "UTF-16") != 0)) ||
		 (language_code == NULL) ||
		 (text == NULL)) {
		return NULL;
	}

	code_len = strlen(language_code);
	text_len = strlen(text);
	payload_length = 1 + code_len + text_len;

	msg = ndef_message_alloc("T", payload_length);
	if (msg == NULL)
		return NULL;

	if (g_strcmp0(encoding, "UTF-16") == 0)
		status |= NDEF_TEXT_RECORD_UTF16_STATUS;

	status = status | code_len;
	msg->data[msg->offset++] = status;

	if (code_len > 0)
		memcpy(msg->data + msg->offset, language_code, code_len);

	msg->offset += code_len;

	if (text_len > 0)
		memcpy(msg->data + msg->offset, text, text_len);

	msg->offset += text_len;

	if (msg->offset > msg->length)
		goto fail;

	return msg;

fail:
	near_error("text record preparation failed");
	g_free(msg->data);
	g_free(msg);

	return NULL;
}

/**
 * @brief Prepare URI ndef record
 *
 * Prepare uri ndef record with provided input data and return
 * ndef message structure (length and byte stream) in success or
 * NULL in failure case.
 *
 * @note : caller responsibility to free the input and output
 *         parameters memory.
 *
 * @param[in] identifier    URI Identifier
 * @param[in] field_length  URI field length
 * @param[in] field         URI field
 *
 * @return struct near_ndef_message * - Success
 *         NULL - Failure
 */
struct near_ndef_message *near_ndef_prepare_uri_record(uint8_t identifier,
					uint32_t field_length, uint8_t *field)
{
	struct near_ndef_message *msg = NULL;
	uint32_t payload_length;

	DBG("");

	/* Validate input parameters*/
	if ((field_length == 0 && field != NULL) ||
		(field_length != 0 && field == NULL)) {
		return NULL;
	}

	payload_length = field_length + 1;

	msg = ndef_message_alloc("U", payload_length);
	if (msg == NULL)
		return NULL;

	msg->data[msg->offset++] = identifier;

	if (field_length > 0) {
		memcpy(msg->data + msg->offset, field, field_length);
		msg->offset += field_length;
	}

	if (msg->offset > msg->length)
		goto fail;

	return msg;

fail:
	near_error("uri record preparation failed");
	g_free(msg->data);
	g_free(msg);

	return NULL;
}

/**
 * @brief Prepare Smartposter ndef record with mandatory URI fields.
 *
 * Prepare smartposter ndef record with provided input data and
 * return ndef message structure (length and byte stream) in success or
 * NULL in failure case.
 *
 * @note : caller responsibility to free the input and output
 *         parameters memory.
 *
 * @param[in] uri_identfier
 * @param[in] uri_field_length
 * @param[in] uri_field
 *
 * @return struct near_ndef_message * - Success
 *         NULL - Failure
 */
struct near_ndef_message *
near_ndef_prepare_smartposter_record(uint8_t uri_identifier,
					uint32_t uri_field_length,
					uint8_t *uri_field)
{
	struct near_ndef_message *msg = NULL, *uri = NULL;

	/* URI is mandatory in Smartposter */
	uri = near_ndef_prepare_uri_record(uri_identifier, uri_field_length,
								uri_field);
	if (uri == NULL)
		goto fail;

	/* URI record length is equal to payload length of Sp record */
	msg = ndef_message_alloc("Sp", uri->length);
	if (msg == NULL)
		goto fail;

	memcpy(msg->data + msg->offset, uri->data, uri->length);
	msg->offset += uri->length;

	if (msg->offset > msg->length)
		goto fail;

	if (uri != NULL) {
		g_free(uri->data);
		g_free(uri);
	}

	return msg;

fail:
	near_error("smartposter record preparation failed");

	if (uri != NULL) {
		g_free(uri->data);
		g_free(uri);
	}

	if (msg != NULL) {
		g_free(msg->data);
		g_free(msg);
	}

	return NULL;
}

static char *get_uri_field(DBusMessage *msg)
{
	DBusMessageIter iter, arr_iter;
	char *uri = NULL;

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
			if (g_strcmp0(key, "URI") == 0)
				dbus_message_iter_get_basic(&var_iter, &uri);

			break;
		}

		dbus_message_iter_next(&arr_iter);
	}

	return uri;
}

static struct near_ndef_message *build_text_record(DBusMessage *msg)
{
	DBusMessageIter iter, arr_iter;
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

	return near_ndef_prepare_text_record(cod, lang, rep);
}

static struct near_ndef_message *build_uri_record(DBusMessage *msg)
{
	char *uri = NULL;
	const char *uri_prefix = NULL;
	uint8_t id_len, i;
	uint32_t uri_len;

	DBG("");

	uri = get_uri_field(msg);
	if (uri == NULL)
		return NULL;

	for (i = 1; i <= NFC_MAX_URI_ID; i++) {
		uri_prefix = __near_ndef_get_uri_prefix(i);

		if (uri_prefix != NULL &&
				g_str_has_prefix(uri, uri_prefix) == TRUE)
			break;
	}

	/* If uri_prefix is NULL then ID will be zero */
	if (uri_prefix == NULL) {
		i = 0;
		id_len = 0;
	} else
		id_len = strlen(uri_prefix);

	uri_len = strlen(uri) - id_len;
	return near_ndef_prepare_uri_record(i, uri_len,
						(uint8_t *)(uri + id_len));
}

static struct near_ndef_message *build_sp_record(DBusMessage *msg)
{
	char *uri = NULL;
	const char *uri_prefix;
	uint8_t id_len, i;
	uint32_t uri_len;

	DBG("");

	/*
	 * Currently this funtion supports only mandatory URI record,
	 * TODO: Other records support.
	 */
	uri = get_uri_field(msg);
	if (uri == NULL)
		return NULL;

	for (i = 1; i <= NFC_MAX_URI_ID; i++) {
		uri_prefix = __near_ndef_get_uri_prefix(i);

		if (uri_prefix != NULL &&
				g_str_has_prefix(uri, uri_prefix) == TRUE)
			break;
	}

	if (uri_prefix == NULL) {
		i = 0;
		id_len = 0;
	} else
		id_len = strlen(uri_prefix);

	uri_len = strlen(uri) - id_len;
	return near_ndef_prepare_smartposter_record(i, uri_len,
						(uint8_t *)(uri + id_len));
}

struct near_ndef_message *__ndef_build_from_message(DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessageIter arr_iter;
	struct near_ndef_message *ndef;

	DBG("");

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &arr_iter);

	ndef = NULL;

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

			if (g_strcmp0(value, "Text") == 0) {
				ndef = build_text_record(msg);
				break;
			} else if (g_strcmp0(value, "URI") == 0) {
				ndef = build_uri_record(msg);
				break;
			} else if (g_strcmp0(value, "SmartPoster") == 0) {
				ndef = build_sp_record(msg);
				break;
			} else {
				near_error("%s not supported", value);
				ndef = NULL;
				break;
			}

			break;
		}

		dbus_message_iter_next(&arr_iter);
	}

	return ndef;
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

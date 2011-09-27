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
	uint8_t action;

	struct near_ndef_uri_record *uri;

	uint8_t number_of_title_records;
	struct near_ndef_text_record **title_records;

	uint32_t size; /* from Size record*/
	char *type;    /* from Type record*/
	/* TODO add icon and other records fields*/
};

struct near_ndef_record {
	char *path;
	uint8_t tnf;
	enum record_type type;

	struct near_ndef_text_record *text;
	struct near_ndef_uri_record  *uri;
	struct near_ndef_sp_record   *sp;
};

static DBusConnection *connection = NULL;

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

static void append_uri_record(struct near_ndef_uri_record *uri,
					DBusMessageIter *dict)
{
	char *value, *prefix = NULL;

	DBG("");

	if (uri == NULL || dict == NULL)
		return;

	switch (uri->identifier) {
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

	near_dbus_dict_append_basic(dict, "Action", DBUS_TYPE_BYTE,
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
	g_free(sp);

	sp = NULL;
}

static void free_ndef_record(struct near_ndef_record *record)
{
	if (record == NULL)
		return;

	g_free(record->path);

	switch (record->type) {
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
	}

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

/**
 * @brief Parse the Text record
 *
 * Parse the Text record.
 *
 * @param[in] ndef_data      NDEF raw data pointer
 * @param[in] ndef_length    NDEF raw data length
 * @param[in] offset         Text record payload offset
 * @param[in] payload_length Text record payload length
 *
 * @return struct near_ndef_text_record * Record on Success
 *                                       NULL   on Failure
 */

static struct near_ndef_text_record *parse_text_record(uint8_t *ndef_data,
				size_t ndef_length, size_t offset,
				uint32_t payload_length)
{
	struct near_ndef_text_record *text_record = NULL;
	uint8_t status, lang_length;

	DBG("");

	if ((ndef_data == NULL) || ((offset + payload_length) > ndef_length))
		return NULL;


	text_record = g_try_malloc0(sizeof(struct near_ndef_text_record));
	if (text_record == NULL)
		return NULL;

	/* 0x80 is used to get 7th bit value (0th bit is LSB) */
	status = ((ndef_data[offset] & 0x80) >> 7);

	text_record->encoding = (status == 0) ?
					g_strdup("UTF-8") : g_strdup("UTF-16");

	/* 0x3F is used to get 5th-0th bits value (0th bit is LSB) */
	lang_length = (ndef_data[offset] & 0x3F);
	offset++;

	if (lang_length > 0) {
		if ((offset + lang_length) >= ndef_length)
			goto fail;

		text_record->language_code = g_strndup(
						(char *)(ndef_data+offset),
						lang_length);
	} else {
		text_record->language_code = NULL;
	}

	offset += lang_length;

	if ((payload_length - lang_length - 1) > 0) {
		text_record->data = g_strndup((char *)(ndef_data+offset),
					payload_length - lang_length - 1);
	} else {
		text_record->data = NULL;
	}

	if (offset >= ndef_length)
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
 * @brief Parse the URI record
 *
 * Parse the URI record.
 *
 * @param[in] ndef_data      NDEF raw data pointer
 * @param[in] ndef_length    NDEF raw data length
 * @param[in] offset         URI record payload offset
 * @param[in] payload_length URI record payload length
 *
 * @return struct near_ndef_uri_record * Record on Success
 *                                       NULL   on Failure
 */

static struct near_ndef_uri_record *parse_uri_record(uint8_t *ndef_data,
				size_t ndef_length, size_t offset,
				uint32_t payload_length)
{
	struct near_ndef_uri_record *uri_record = NULL;
	uint32_t index;

	DBG("");

	if (ndef_data == NULL || ((offset + payload_length) > ndef_length))
		return NULL;

	uri_record = g_try_malloc0(sizeof(struct near_ndef_uri_record));
	if (uri_record == NULL)
		return NULL;

	uri_record->identifier = ndef_data[offset];
	offset++;

	uri_record->field_length = payload_length - 1;

	if (uri_record->field_length > 0) {
		uri_record->field = g_try_malloc0(uri_record->field_length);
		if (uri_record->field == NULL)
			goto fail;

		memcpy(uri_record->field, ndef_data + offset,
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
 * @brief Parse the smart poster record.
 *
 * Parse the smart poster record and cache the
 * data in respective fields of smart poster structure.
 *
 * @note Caller responsibility to free the memory.
 *
 * @param[in] ndef_data      NDEF raw data pointer
 * @param[in] ndef_length    NDEF raw data length
 * @param[in] offset         Sp record payload offset
 *
 * @return struct near_ndef_sp_record * Record on Success
 *                                      NULL   on Failure
 */

static struct near_ndef_sp_record *parse_smart_poster_record(uint8_t *ndef_data,
					 size_t ndef_length, size_t offset,
					 uint32_t payload_length)
{
	struct near_ndef_sp_record *sp_record = NULL;
	uint8_t mb = 0, me = 0, i;
	size_t t_offset;
	GSList *titles = NULL, *temp;

	DBG("");

	if (ndef_data == NULL || offset >= ndef_length)
		return NULL;

	t_offset = offset;
	sp_record = g_try_malloc0(sizeof(struct near_ndef_sp_record));
	if (sp_record == NULL)
		return NULL;

	while (t_offset < (offset + payload_length)) {
		uint8_t t_mb, t_me, t_sr, t_il, t_tnf;
		uint8_t type_length, il_length = 0, r_type = 0xfe;
		uint8_t *type = NULL;
		uint32_t payload_length;

		DBG("Record header : 0x%x", ndef_data[t_offset]);

		t_mb = RECORD_MB_BIT(ndef_data[t_offset]);
		t_me = RECORD_ME_BIT(ndef_data[t_offset]);
		t_sr = RECORD_SR_BIT(ndef_data[t_offset]);
		t_il = RECORD_IL_BIT(ndef_data[t_offset]);
		t_tnf = RECORD_TNF_BIT(ndef_data[t_offset]);

		if (validate_record_begin_and_end_bits(&mb,
						&me, t_mb, t_me) != 0) {
			DBG("validate mb me failed");
			goto fail;
		}

		/*
		 * calculate ndef length is enough or not against id,
		 * typename and payload to extract Sp sub-records(eg: Uri,
		 * Title, Action, Size, Type and Other)
		 */
		t_offset++;
		type_length = ndef_data[t_offset];
		t_offset++;

		if (t_sr == 1) {
			payload_length = ndef_data[t_offset];
			t_offset++;
		} else {
			payload_length = *((uint32_t *)(ndef_data + t_offset));
			t_offset += 4;

			if (t_offset >= ndef_length)
				goto fail;
		}

		if (t_il == 1) {
			il_length = ndef_data[t_offset];
			t_offset++;

			if (t_offset >= ndef_length)
				goto fail;
		}

		if ((t_offset + type_length + il_length + payload_length)
				> ndef_length)
			goto fail;

		if (type_length > 0) {
			type = g_try_malloc0(type_length);
			if (type == NULL)
				goto fail;

			memcpy(type, ndef_data+t_offset, type_length);
		}

		r_type = get_record_type(t_tnf, type, type_length);

		t_offset += type_length + il_length;

		switch (r_type) {
		case RECORD_TYPE_WKT_HANDOVER_REQUEST:
		case RECORD_TYPE_WKT_HANDOVER_SELECT:
		case RECORD_TYPE_WKT_HANDOVER_CARRIER:
		case RECORD_TYPE_WKT_ALTERNATIVE_CARRIER:
		case RECORD_TYPE_WKT_COLLISION_RESOLUTION:
		case RECORD_TYPE_WKT_ERROR:
		case RECORD_TYPE_UNKNOWN:
		case RECORD_TYPE_ERROR:
			break;

		case RECORD_TYPE_WKT_URI:
			/* URI record should be only one. */
			if (sp_record->uri != NULL)
				goto fail;

			sp_record->uri = parse_uri_record(ndef_data,
							ndef_length, t_offset,
							payload_length);

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
			title = parse_text_record(ndef_data, ndef_length,
						t_offset, payload_length);

			if (title == NULL)
				goto fail;

			titles = g_slist_append(titles, title);
			}
			break;

		case RECORD_TYPE_WKT_SIZE:
			/*
			 * If paylaod length is not exactly 4 bytes
			 * then record is wrong.
			 */
			if (payload_length != 4)
				goto fail;

			sp_record->size = *((uint32_t *)(ndef_data + t_offset));
			break;

		case RECORD_TYPE_WKT_TYPE:

			if (payload_length > 0) {
				sp_record->type = g_try_malloc0(payload_length);
				if (sp_record->type == NULL)
					goto fail;

				sp_record->type = g_strndup(
						(char *) ndef_data + t_offset,
								payload_length);
			}

			break;

		case RECORD_TYPE_WKT_ACTION:
			/*
			 * If the action record exists, payload should be
			 * single byte, otherwise consider it as error.
			 */
			if (payload_length != 1)
				goto fail;

			sp_record->action = ndef_data[t_offset];
			break;
		}

		t_offset += payload_length;
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
	free_sp_record(sp_record);
	g_slist_free(titles);

	return NULL;
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

		switch (r_type) {
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
			record->text = parse_text_record(ndef_data, ndef_length,
								offset,
								payload_length);

			if (record->text == NULL) {
				err = EINVAL;
				goto fail;
			}

			break;

		case RECORD_TYPE_WKT_URI:
			record->uri = parse_uri_record(ndef_data, ndef_length,
								offset,
								payload_length);

			if (record->uri == NULL) {
				err = EINVAL;
				goto fail;
			}

			break;

		case RECORD_TYPE_WKT_SMART_POSTER:
			record->sp = parse_smart_poster_record(ndef_data,
							ndef_length, offset,
							payload_length);

			if (record->sp == NULL) {
				err = EINVAL;
				goto fail;
			}

			break;
		}

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

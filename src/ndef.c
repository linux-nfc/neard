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
#define NDEF_PAYLOAD_LENGTH_OFFSET 0x02

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

#define AC_CPS_MASK 0x03

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
	RECORD_TYPE_EXT_AAR                   =   0x0e,
	RECORD_TYPE_UNKNOWN                   =   0xfe,
	RECORD_TYPE_ERROR                     =   0xff
};

#define RECORD_TYPE_WKT "urn:nfc:wkt:"
#define RECORD_TYPE_EXTERNAL "urn:nfc:ext:"
#define AAR_STRING "android.com:pkg"

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
	uint8_t	type_len;
	enum record_type rec_type;
	char *type_name;
	uint32_t header_len;
};

struct near_ndef_text_payload {
	char *encoding;
	char *language_code;
	char *data;
};

struct near_ndef_uri_payload {
	uint8_t identifier;

	uint32_t  field_length;
	uint8_t  *field;
};

struct near_ndef_sp_payload {
	struct near_ndef_uri_payload *uri;

	uint8_t number_of_title_records;
	struct near_ndef_text_payload **title_records;

	uint32_t size; /* from Size record*/
	char *type;    /* from Type record*/
	char *action;
	/* TODO add icon and other records fields*/
};

struct near_ndef_mime_payload {
	char *type;

	struct {
		enum handover_carrier carrier_type;
		uint16_t properties;	/* e.g.: NO_PAIRING_KEY */
	} handover;
};

/* Handover record definitions */

/* alternative record (AC) length based on cdr length without adata */
#define AC_RECORD_PAYLOAD_LEN(cdr_len) (3 + cdr_len)

struct near_ndef_ac_payload {
	enum carrier_power_state cps;	/* carrier power state */

	uint8_t cdr_len;	/* carrier data reference length */
	uint8_t *cdr;		/* carrier data reference */
	uint8_t adata_refcount;	/* auxiliary data reference count */

	/* !: if adata_refcount == 0, then there's no data reference */
	uint16_t **adata;	/* auxiliary data reference */
};

/* Default Handover version */
#define HANDOVER_VERSION	0x12
#define HANDOVER_MAJOR(version) (((version) >> 4) & 0xf)
#define HANDOVER_MINOR(version) ((version) & 0xf)


/* General Handover Request/Select record */
struct near_ndef_ho_payload {
	uint8_t version;		/* version id */
	uint16_t collision_record;	/* collision record */

	uint8_t number_of_ac_payloads;	/* At least 1 ac is needed */
	struct near_ndef_ac_payload **ac_payloads;

	/* Optional records */
	uint16_t *err_record;	/* not NULL if present */

	uint8_t number_of_cfg_payloads;	/* extra NDEF records */
	struct near_ndef_mime_payload **cfg_payloads;
};

struct near_ndef_aar_payload {
	char *package;
};

struct near_ndef_record {
	char *path;

	struct near_ndef_record_header *header;

	/* specific payloads */
	struct near_ndef_text_payload *text;
	struct near_ndef_uri_payload  *uri;
	struct near_ndef_sp_payload   *sp;
	struct near_ndef_mime_payload *mime;
	struct near_ndef_ho_payload   *ho;	/* handover payload */
	struct near_ndef_aar_payload  *aar;

	char *type;

	uint8_t *data;
	size_t data_len;
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

char *__near_ndef_record_get_type(struct near_ndef_record *record)
{
	return record->type;
}

uint8_t *__near_ndef_record_get_data(struct near_ndef_record *record,
								size_t *len)
{
	*len = record->data_len;

	return record->data;
}

uint8_t *__near_ndef_record_get_payload(struct near_ndef_record *record,
								size_t *len)
{
	*len = record->header->payload_len;

	return record->data + record->header->header_len;
}

void __near_ndef_append_records(DBusMessageIter *iter, GList *records)
{
	GList *list;

	DBG("");

	for (list = records; list; list = list->next) {
		struct near_ndef_record *record = list->data;
		uint8_t *data;
		size_t data_len;

		data = __near_ndef_record_get_data(record, &data_len);
		if (!data)
			continue;

		dbus_message_iter_append_fixed_array(iter, DBUS_TYPE_BYTE,
							&data, data_len);
	}
}

static const char *uri_prefixes[NFC_MAX_URI_ID + 1] = {
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

	return uri_prefixes[id];
}

static gboolean property_get_type(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_ndef_record *record = user_data;
	const char *type;

	DBG("");

	switch (record->header->rec_type) {
	case RECORD_TYPE_WKT_SIZE:
	case RECORD_TYPE_WKT_TYPE:
	case RECORD_TYPE_WKT_ACTION:
	case RECORD_TYPE_WKT_ALTERNATIVE_CARRIER:
	case RECORD_TYPE_WKT_COLLISION_RESOLUTION:
	case RECORD_TYPE_WKT_ERROR:
	case RECORD_TYPE_UNKNOWN:
	case RECORD_TYPE_ERROR:
		type = NULL;
		break;

	case RECORD_TYPE_WKT_TEXT:
		type = "Text";
		break;

	case RECORD_TYPE_WKT_URI:
		type = "URI";
		break;

	case RECORD_TYPE_WKT_SMART_POSTER:
		type = "SmartPoster";
		break;

	case RECORD_TYPE_WKT_HANDOVER_REQUEST:
		type = "HandoverRequest";
		break;

	case RECORD_TYPE_WKT_HANDOVER_SELECT:
		type = "HandoverSelect";
		break;

	case RECORD_TYPE_WKT_HANDOVER_CARRIER:
		type = "HandoverCarrier";
		break;

	case RECORD_TYPE_MIME_TYPE:
		type = "MIME";
		break;

	case RECORD_TYPE_EXT_AAR:
		type = "AAR";
		break;
	}
	
	if (!type)
		return FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &type);

	return TRUE;
}

static gboolean text_exists(const GDBusPropertyTable *property, void *data)
{
	struct near_ndef_record *record = data;

	DBG("");

	if (record->text)
		return TRUE;

	if (record->sp && record->sp->title_records)
		return TRUE;

	DBG("No text");

	return FALSE;
}

static const char *get_text_payload(const GDBusPropertyTable *property,
					struct near_ndef_text_payload *text)
{
	if (!strcmp(property->name, "Encoding"))
		return text->encoding;
	else if (!strcmp(property->name, "Language"))
		return text->language_code;
	else if (!strcmp(property->name, "Representation"))
		return text->data;
	else
		return NULL;
}

static gboolean property_get_text(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_ndef_record *record = user_data;
	const char *text;

	DBG("");

	if (record->text) {
		text = get_text_payload(property, record->text);
		if (!text)
			return FALSE;

		DBG("text %s", text);

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &text);

		return TRUE;
	}

	if (record->sp && record->sp->title_records) {
		int i;

		for (i = 0; i < record->sp->number_of_title_records; i++) {
			text = get_text_payload(property,
						record->sp->title_records[i]);
			if (!text)
				continue;

			dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
									&text);
		}

		return TRUE;
	}

	return FALSE;
}

static gboolean uri_exists(const GDBusPropertyTable *property, void *data)
{
	struct near_ndef_record *record = data;

	DBG("");

	if (record->uri)
		return TRUE;

	if (record->sp && record->sp->uri)
		return TRUE;

	DBG("No URI");

	return FALSE;
}

static gboolean property_get_uri(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_ndef_record *record = user_data;
	struct near_ndef_uri_payload *uri;
	char *value;
	const char *prefix = NULL;

	DBG("");

	if (record->uri)
		uri = record->uri;
	else if (record->sp && record->sp->uri)
		uri = record->sp->uri;
	else
		return FALSE;

	if (uri->identifier > NFC_MAX_URI_ID) {
		near_error("Invalid URI identifier 0x%x", uri->identifier);
		return FALSE;
	}

	prefix = uri_prefixes[uri->identifier];

	DBG("URI prefix %s", prefix);

	value = g_strdup_printf("%s%.*s", prefix, uri->field_length,
							 uri->field);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &value);

	g_free(value);

	return TRUE;
}

static gboolean sp_action_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct near_ndef_record *record = data;

	DBG("");

	if (record->sp && record->sp->action)
		return TRUE;

	DBG("No SmartPoster action");

	return FALSE;
}

static gboolean sp_mime_exists(const GDBusPropertyTable *property, void *data)
{
	struct near_ndef_record *record = data;

	DBG("");

	if (record->sp && record->sp->type)
		return TRUE;

	DBG("No SmartPoster MIME type");

	return FALSE;
}

static gboolean sp_size_exists(const GDBusPropertyTable *property, void *data)
{
	struct near_ndef_record *record = data;

	DBG("");

	if (record->sp && record->sp->size)
		return TRUE;

	DBG("No SmartPoster size");

	return FALSE;
}

static gboolean property_get_action(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_ndef_record *record = user_data;

	DBG("%s", record->sp->action);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &record->sp->action);

	return TRUE;
}

static gboolean property_get_mime_type(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_ndef_record *record = user_data;

	DBG("%s", record->sp->type);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &record->sp->type);

	return TRUE;
}

static gboolean property_get_size(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_ndef_record *record = user_data;

	DBG("%d", record->sp->size);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &record->sp->size);

	return TRUE;
}

static gboolean mime_exists(const GDBusPropertyTable *property, void *data)
{
	struct near_ndef_record *record = data;

	DBG("");

	if (record->mime)
		return TRUE;

	DBG("No MIME");

	return FALSE;
}

static gboolean property_get_mime(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_ndef_record *record = user_data;

	DBG("");

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &record->mime->type);

	return TRUE;
}

static gboolean aar_exists(const GDBusPropertyTable *property, void *data)
{
	struct near_ndef_record *record = data;

	DBG("");

	if (record->aar)
		return TRUE;

	DBG("No AAR");

	return FALSE;
}

static gboolean property_get_aar(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct near_ndef_record *record = user_data;

	DBG("");

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &record->aar->package);

	return TRUE;
}

static const GDBusPropertyTable record_properties[] = {

	{ "Type", "s", property_get_type },
	{ "Encoding", "s", property_get_text, NULL, text_exists },
	{ "Language", "s", property_get_text, NULL, text_exists },
	{ "Representation", "s", property_get_text, NULL, text_exists},
	{ "URI", "s", property_get_uri, NULL, uri_exists },
	{ "Action", "s", property_get_action, NULL, sp_action_exists },
	{ "MIMEType", "s", property_get_mime_type, NULL, sp_mime_exists },
	{ "Size", "u", property_get_size, NULL, sp_size_exists },
	{ "MIME", "s", property_get_mime, NULL, mime_exists },
	{ "AAR", "s", property_get_aar, NULL, aar_exists },
	{ }
};

static void free_text_payload(struct near_ndef_text_payload *text)
{
	if (!text)
		return;

	g_free(text->encoding);
	g_free(text->language_code);
	g_free(text->data);
	g_free(text);
}

static void free_uri_payload(struct near_ndef_uri_payload *uri)
{
	if (!uri)
		return;

	g_free(uri->field);
	g_free(uri);
}

static void free_sp_payload(struct near_ndef_sp_payload *sp)
{
	uint8_t i;

	if (!sp)
		return;

	free_uri_payload(sp->uri);

	if (sp->title_records) {
		for (i = 0; i < sp->number_of_title_records; i++)
			free_text_payload(sp->title_records[i]);
	}

	g_free(sp->title_records);
	g_free(sp->type);
	g_free(sp->action);
	g_free(sp);
}

static void free_mime_payload(struct near_ndef_mime_payload *mime)
{
	if (!mime)
		return;

	g_free(mime->type);
	g_free(mime);
}

static void free_ac_payload(struct near_ndef_ac_payload *ac)
{
	if (!ac)
		return;

	g_free(ac->cdr);
	g_free(ac->adata);
	g_free(ac);
}

static void free_ho_payload(struct near_ndef_ho_payload *ho)
{
	int i;

	if (!ho)
		return;

	if (ho->ac_payloads) {
		for (i = 0; i < ho->number_of_ac_payloads; i++)
			free_ac_payload(ho->ac_payloads[i]);
	}

	g_free(ho->ac_payloads);
	g_free(ho);
}

static void free_aar_payload(struct near_ndef_aar_payload *aar)
{
	if (!aar)
		return;

	g_free(aar->package);
	g_free(aar);
}

static void free_ndef_record(struct near_ndef_record *record)
{
	if (!record)
		return;

	g_free(record->path);

	if (record->header) {

		switch (record->header->rec_type) {
		case RECORD_TYPE_WKT_SIZE:
		case RECORD_TYPE_WKT_TYPE:
		case RECORD_TYPE_WKT_ACTION:
		case RECORD_TYPE_WKT_HANDOVER_CARRIER:
		case RECORD_TYPE_WKT_ALTERNATIVE_CARRIER:
		case RECORD_TYPE_WKT_COLLISION_RESOLUTION:
		case RECORD_TYPE_WKT_ERROR:
		case RECORD_TYPE_UNKNOWN:
		case RECORD_TYPE_ERROR:
			break;

		case RECORD_TYPE_WKT_HANDOVER_REQUEST:
		case RECORD_TYPE_WKT_HANDOVER_SELECT:
			free_ho_payload(record->ho);
			break;

		case RECORD_TYPE_WKT_TEXT:
			free_text_payload(record->text);
			break;

		case RECORD_TYPE_WKT_URI:
			free_uri_payload(record->uri);
			break;

		case RECORD_TYPE_WKT_SMART_POSTER:
			free_sp_payload(record->sp);
			break;

		case RECORD_TYPE_MIME_TYPE:
			free_mime_payload(record->mime);
			break;

		case RECORD_TYPE_EXT_AAR:
			free_aar_payload(record->aar);
			break;
		}

		g_free(record->header->il_field);
		g_free(record->header->type_name);
	}

	g_free(record->header);
	g_free(record->type);
	g_free(record->data);
	g_free(record);
}

static void free_ndef_message(struct near_ndef_message *msg)
{
	if (!msg)
		return;

	g_free(msg->data);
	g_free(msg);
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

static enum record_type get_external_record_type(uint8_t *type,
						size_t type_length)
{
	DBG("");

	if (strncmp((char *) type, BT_MIME_STRING_2_0,
					sizeof(BT_MIME_STRING_2_0) - 1) == 0)
		return RECORD_TYPE_MIME_TYPE;
	else if (strncmp((char *) type, AAR_STRING,
					sizeof(AAR_STRING) - 1) == 0)
		return RECORD_TYPE_EXT_AAR;
	else
		return RECORD_TYPE_UNKNOWN;
}

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

static int build_record_type_string(struct near_ndef_record *rec)
{
	uint8_t tnf;

	DBG("");

	if (!rec || !rec->header)
		return -EINVAL;

	tnf = rec->header->tnf;

	if (rec->header->rec_type == RECORD_TYPE_WKT_SMART_POSTER) {
		rec->type = g_strdup_printf(RECORD_TYPE_WKT "U");
		return 0;
	}

	switch (tnf) {
	case RECORD_TNF_EMPTY:
	case RECORD_TNF_UNKNOWN:
	case RECORD_TNF_UNCHANGED:
		return -EINVAL;

	case RECORD_TNF_URI:
	case RECORD_TNF_MIME:
		rec->type = g_strndup(rec->header->type_name,
				      rec->header->type_len);
		break;

	case RECORD_TNF_WELLKNOWN:
		rec->type = g_strdup_printf(RECORD_TYPE_WKT "%s",
				      rec->header->type_name);
		break;

	case RECORD_TNF_EXTERNAL:
		rec->type = g_strdup_printf(RECORD_TYPE_EXTERNAL "%s",
				      rec->header->type_name);
		break;
	}

	return 0;
}

static uint8_t validate_record_begin_and_end_bits(uint8_t *msg_mb,
					uint8_t *msg_me, uint8_t rec_mb,
					uint8_t rec_me)
{
	DBG("");

	if (!msg_mb || !msg_me)
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

/*
 * Parse the ndef record header and cache the begin, end, chunkflag,
 * short-record and type-name-format bits. ID length and field, record
 * type, payload length and offset (where payload byte starts in input
 * parameter). Validate offset for every step forward against total
 * available length.
 */
static struct near_ndef_record_header *parse_record_header(uint8_t *rec,
					uint32_t offset, uint32_t length)
{
	struct near_ndef_record_header *rec_header = NULL;
	uint8_t *type = NULL;
	uint32_t header_len = 0;

	DBG("length %d", length);

	if (!rec || offset >= length)
		return NULL;

	/* This check is for empty record. */
	if ((length - offset) < NDEF_MSG_MIN_LENGTH)
		return NULL;

	rec_header = g_try_malloc0(sizeof(struct near_ndef_record_header));
	if (!rec_header)
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
	rec_header->type_len = rec[offset++];
	header_len = 2; /* type length + header bits */

	if (rec_header->sr == 1) {
		rec_header->payload_len = rec[offset++];
		header_len++;
	} else {
		rec_header->payload_len = near_get_be32(rec + offset);
		offset += 4;
		header_len += 4;

		if ((offset + rec_header->payload_len) > length)
			goto fail;
	}

	DBG("payload length %d", rec_header->payload_len);

	if (rec_header->il == 1) {
		rec_header->il_length = rec[offset++];
		header_len++;

		if ((offset + rec_header->payload_len) > length)
			goto fail;
	}

	if (rec_header->type_len > 0) {
		if ((offset + rec_header->type_len) > length)
			goto fail;

		type = g_try_malloc0(rec_header->type_len);
		if (!type)
			goto fail;

		memcpy(type, rec + offset, rec_header->type_len);
		offset += rec_header->type_len;
		header_len += rec_header->type_len;

		if ((offset + rec_header->payload_len) > length)
			goto fail;
	}

	if (rec_header->il_length > 0) {
		if ((offset + rec_header->il_length) > length)
			goto fail;

		rec_header->il_field = g_try_malloc0(rec_header->il_length);
		if (!rec_header->il_field)
			goto fail;

		memcpy(rec_header->il_field, rec + offset,
					rec_header->il_length);
		offset += rec_header->il_length;
		header_len += rec_header->il_length;

		if ((offset + rec_header->payload_len) > length)
			goto fail;
	}

	rec_header->rec_type = get_record_type(rec_header->tnf, type,
							rec_header->type_len);
	rec_header->offset = offset;
	rec_header->header_len = header_len;
	rec_header->type_name = g_strndup((char *) type, rec_header->type_len);

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

static struct near_ndef_text_payload *
parse_text_payload(uint8_t *payload, uint32_t length)
{
	struct near_ndef_text_payload *text_payload = NULL;
	uint8_t status, lang_length;
	uint32_t offset;

	DBG("");

	if (!payload)
		return NULL;

	offset = 0;
	text_payload = g_try_malloc0(sizeof(struct near_ndef_text_payload));
	if (!text_payload)
		return NULL;

	/* 0x80 is used to get 7th bit value (0th bit is LSB) */
	status = ((payload[offset] & 0x80) >> 7);

	text_payload->encoding = (status == 0) ?
					g_strdup("UTF-8") : g_strdup("UTF-16");

	/* 0x3F is used to get 5th-0th bits value (0th bit is LSB) */
	lang_length = (payload[offset] & 0x3F);
	offset++;

	if (lang_length > 0) {
		if ((offset + lang_length) >= length)
			goto fail;

		text_payload->language_code = g_strndup(
						(char *)(payload + offset),
						lang_length);
	} else {
		text_payload->language_code = NULL;
	}

	offset += lang_length;

	if ((length - lang_length - 1) > 0) {
		text_payload->data = g_strndup((char *)(payload + offset),
					length - lang_length - 1);
	} else {
		text_payload->data = NULL;
	}

	if (offset >= length)
		goto fail;

	DBG("Encoding  '%s'", text_payload->encoding);
	DBG("Language Code  '%s'", text_payload->language_code);
	DBG("Data  '%s'", text_payload->data);

	return text_payload;

fail:
	near_error("text payload parsing failed");
	free_text_payload(text_payload);

	return NULL;
}

static struct near_ndef_uri_payload *
parse_uri_payload(uint8_t *payload, uint32_t length)
{
	struct near_ndef_uri_payload *uri_payload = NULL;
	uint32_t index, offset;

	DBG("");

	if (!payload)
		return NULL;

	offset = 0;
	uri_payload = g_try_malloc0(sizeof(struct near_ndef_uri_payload));
	if (!uri_payload)
		return NULL;

	uri_payload->identifier = payload[offset];
	offset++;

	uri_payload->field_length = length - 1;

	if (uri_payload->field_length > 0) {
		uri_payload->field = g_try_malloc0(uri_payload->field_length);
		if (!uri_payload->field)
			goto fail;

		memcpy(uri_payload->field, payload + offset,
				uri_payload->field_length);

		for (index = 0; index < uri_payload->field_length; index++) {
			/* URI Record Type Definition 1.0 [3.2.3]
			 * Any character value within the URI between
			 * (and including) 0 and 31 SHALL be recorded as
			 * an error, and the URI record to be discarded */
			if (uri_payload->field[index] <= 31)
				goto fail;
		}

	}

	DBG("Identifier  '0X%X'", uri_payload->identifier);
	DBG("Field  '%.*s'", uri_payload->field_length, uri_payload->field);

	return uri_payload;

fail:
	near_error("uri payload parsing failed");
	free_uri_payload(uri_payload);

	return NULL;
}

/*
 * Validate titles records language code in Smartposter.
 * There must not be two or more records with the same language identifier.
 */
static int8_t validate_language_code_in_sp_record(GSList *titles)
{
	uint8_t i, j, length;
	struct near_ndef_text_payload *title1, *title2;

	DBG("");

	if (!titles)
		return -EINVAL;

	length = g_slist_length(titles);

	for (i = 0; i < length; i++) {
		title1 = g_slist_nth_data(titles, i);

		for (j = i + 1; j < length; j++) {
			title2 = g_slist_nth_data(titles, j);

			if ((!title1->language_code) &&
					(!title2->language_code))
				continue;

			if (g_strcmp0(title1->language_code,
					title2->language_code) == 0)
				return -EINVAL;
		}
	}

	return 0;
}

static struct near_ndef_sp_payload *
parse_sp_payload(uint8_t *payload, uint32_t length)
{
	struct near_ndef_sp_payload *sp_payload = NULL;
	struct near_ndef_record_header *rec_header = NULL;
	uint8_t mb = 0, me = 0, i;
	uint32_t offset;
	GSList *titles = NULL, *temp;

	DBG("");

	if (!payload)
		return NULL;

	offset = 0;
	sp_payload = g_try_malloc0(sizeof(struct near_ndef_sp_payload));
	if (!sp_payload)
		return NULL;

	while (offset < length) {

		DBG("Record header : 0x%x", payload[offset]);

		rec_header = parse_record_header(payload, offset, length);
		if (!rec_header)
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
		case RECORD_TYPE_EXT_AAR:
		case RECORD_TYPE_UNKNOWN:
		case RECORD_TYPE_ERROR:
			break;

		case RECORD_TYPE_WKT_URI:
			/* URI record should be only one. */
			if (sp_payload->uri)
				goto fail;

			sp_payload->uri = parse_uri_payload(payload + offset,
						rec_header->payload_len);
			if (!sp_payload->uri)
				goto fail;

			break;

		case RECORD_TYPE_WKT_TEXT:
			/*
			 * Title records can zero or more. First fill the
			 * records in list and validate language identifier
			 * and then cache them into sp record structure.
			 */
			{
			struct near_ndef_text_payload *title;
			title = parse_text_payload(payload + offset,
						rec_header->payload_len);
			if (!title)
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

			sp_payload->size = near_get_be32(payload + offset);
			break;

		case RECORD_TYPE_WKT_TYPE:

			if (rec_header->payload_len > 0) {
				sp_payload->type = g_try_malloc0(
						rec_header->payload_len);
				if (!sp_payload->type)
					goto fail;

				sp_payload->type = g_strndup(
						(char *) payload + offset,
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

			sp_payload->action =
				g_strdup(action_to_string(payload[offset]));

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
	if (!titles)
		return sp_payload;

	if (validate_language_code_in_sp_record(titles) != 0) {
		DBG("language code validation failed");
		goto fail;
	}

	temp = titles;
	sp_payload->number_of_title_records = g_slist_length(temp);
	sp_payload->title_records = g_try_malloc0(
				sp_payload->number_of_title_records *
				 sizeof(struct near_ndef_text_payload *));
	if (!sp_payload->title_records)
		goto fail;

	for (i = 0; i < sp_payload->number_of_title_records; i++) {
		sp_payload->title_records[i] = temp->data;
		temp = temp->next;
	}

	g_slist_free(titles);
	titles = NULL;

	return sp_payload;

fail:
	near_error("smart poster payload parsing failed");

	if (rec_header) {
		g_free(rec_header->type_name);
		g_free(rec_header->il_field);
		g_free(rec_header);
	}

	free_sp_payload(sp_payload);
	g_slist_free(titles);

	return NULL;
}

static void correct_eir_len(struct carrier_data *data)
{
	/*
	 * Android 4.1 BUG - OOB EIR length should be in LE, but is in BE.
	 * Fortunately payload length is 1 byte so this can be detected and
	 * corrected before sending it to handover agent.
	 */
	if (data->data[0] == 0) {
		DBG("EIR length in BE");
		data->data[0] = data->data[1];
		data->data[1] = 0;
	}

	/*
	 * Some Nokia BH-505 report total OOB block length without length field
	 * size.
	 */
	if (data->data[0] == data->size - 2) {
		DBG("EIR length without length field size");
		data->data[0] += 2;
	}
}

static int process_mime_type(struct near_ndef_mime_payload *mime,
					struct carrier_data *c_data)
{
	int err = -EINVAL;

	DBG("");

	if (!mime || !c_data)
		return -EINVAL;

	switch (mime->handover.carrier_type) {
	case NEAR_CARRIER_BLUETOOTH:
		err = __near_agent_handover_push_data(HO_AGENT_BT, c_data);
		if (err == -ESRCH)
			err = __near_bluetooth_parse_oob_record(c_data,
					&mime->handover.properties, true);
		break;

	case NEAR_CARRIER_WIFI:
		err = __near_agent_handover_push_data(HO_AGENT_WIFI, c_data);
		break;

	case NEAR_CARRIER_EMPTY:
	case NEAR_CARRIER_UNKNOWN:
		break;
	}

	return err;
}

static struct near_ndef_mime_payload *parse_mime_type(
			struct near_ndef_record *record, uint8_t *ndef_data,
			size_t ndef_length, size_t offset,
			uint32_t payload_length, struct carrier_data **c_data)
{
	struct near_ndef_mime_payload *mime;
	struct carrier_data *c_temp;

	DBG("");

	if (!c_data || !ndef_data ||
			((offset + payload_length) > ndef_length))
		return NULL;

	mime = g_try_malloc0(sizeof(struct near_ndef_mime_payload));
	if (!mime)
		return NULL;

	c_temp = g_try_malloc0(sizeof(struct carrier_data));
	if (!c_temp) {
		g_free(mime);
		return NULL;
	}

	mime->type = g_strdup(record->header->type_name);

	DBG("MIME Type '%s'", mime->type);
	if (strcmp(mime->type, BT_MIME_STRING_2_1) == 0) {
		mime->handover.carrier_type = NEAR_CARRIER_BLUETOOTH;
		c_temp->type = BT_MIME_V2_1;
		c_temp->size = record->header->payload_len;
		memcpy(c_temp->data, ndef_data + offset, c_temp->size);
		correct_eir_len(c_temp);
	} else if (strcmp(mime->type, BT_MIME_STRING_2_0) == 0) {
		mime->handover.carrier_type = NEAR_CARRIER_BLUETOOTH;
		c_temp->type = BT_MIME_V2_0;
		c_temp->size = record->header->payload_len;
		memcpy(c_temp->data, ndef_data + offset, c_temp->size);
	} else if (strcmp(mime->type, WIFI_WSC_MIME_STRING) == 0) {
		mime->handover.carrier_type = NEAR_CARRIER_WIFI;
		c_temp->type = WIFI_WSC_MIME;
		c_temp->size = record->header->payload_len;
		memcpy(c_temp->data, ndef_data + offset, c_temp->size);
	} else {
		g_free(c_temp);
		c_temp = NULL;
		*c_data = NULL;
		return mime;
	}

	*c_data = c_temp;

	return mime;
}

/* Set the MB bit in message header */
static uint8_t near_ndef_set_mb(uint8_t *hdr, bool first_rec)
{
	/* Reset bits 0x40 */
	*hdr &= (0xFF & (~RECORD_MB));

	/* Set if needed */
	if (first_rec)
		*hdr |= RECORD_MB;

	return *hdr;
}

/* Set the MB/ME bit in message header */
static uint8_t near_ndef_set_me(uint8_t *hdr, bool last_rec)
{
	/* Reset bits 0x80 */
	*hdr &= (0xFF & (~RECORD_ME));

	/* Set if needed */
	if (last_rec)
		*hdr |= RECORD_ME;

	return *hdr;
}

/* Set the MB/ME bit in message header */
static uint8_t near_ndef_set_mb_me(uint8_t *hdr, bool first_rec,
						bool last_rec)
{
	near_ndef_set_mb(hdr, first_rec);
	return near_ndef_set_me(hdr, last_rec);
}

/* Caller should put own payload starting from offset value */
static struct near_ndef_message *ndef_message_alloc_complete(char *type_name,
		uint32_t payload_len,
		char *payload_id,
		uint8_t payload_id_len,
		enum record_tnf tnf,
		bool first_rec,
		bool last_rec)
{
	struct near_ndef_message *msg;
	uint8_t hdr = 0, type_len, sr_bit, il_bit, id_len;

	msg = g_try_malloc0(sizeof(struct near_ndef_message));
	if (!msg)
		return NULL;

	msg->length = 0;
	msg->offset = 0;
	msg->length++; /* record header*/
	msg->length++; /* type name length byte*/

	type_len = (type_name) ? strlen(type_name) : 0;
	id_len = (payload_id) ? payload_id_len : 0;
	sr_bit =  (payload_len <= NDEF_MSG_SHORT_RECORD_MAX_LENGTH)
					? TRUE : FALSE;

	il_bit = (payload_id) ? TRUE : FALSE;

	msg->length += (sr_bit) ? 1 : 4;
	msg->length += (il_bit) ? 1 : 0;
	msg->length += type_len;
	msg->length += payload_len;
	msg->length += id_len;

	msg->data = g_try_malloc0(msg->length);
	if (!msg->data)
		goto fail;

	/* Set MB ME bits */
	hdr = near_ndef_set_mb_me(&hdr, first_rec, last_rec);

	if (sr_bit)
		hdr |= RECORD_SR;

	hdr = RECORD_TNF_WKT_SET(hdr);
	if (il_bit)
		hdr |= RECORD_IL;

	switch (tnf) {
	case RECORD_TNF_EMPTY:
		hdr = RECORD_TNF_EMPTY_SET(hdr);
		break;

	case RECORD_TNF_URI:
		hdr = RECORD_TNF_URI_SET(hdr);
		break;

	case RECORD_TNF_EXTERNAL:
		hdr = RECORD_TNF_EXTERNAL_SET(hdr);
		break;
	case RECORD_TNF_UNKNOWN:
		hdr = RECORD_TNF_UKNOWN_SET(hdr);
		break;

	case RECORD_TNF_UNCHANGED:
		hdr = RECORD_TNF_UNCHANGED_SET(hdr);
		break;

	case RECORD_TNF_WELLKNOWN:
		hdr = RECORD_TNF_WKT_SET(hdr);
		break;

	case RECORD_TNF_MIME:
		hdr = RECORD_TNF_MIME_SET(hdr);
		break;
	}

	msg->data[msg->offset++] = hdr;
	msg->data[msg->offset++] = type_len;

	if (sr_bit) {
		msg->data[msg->offset++] = payload_len;
	} else {
		fillb32((msg->data + msg->offset), payload_len);
		msg->offset += 4;
	}

	if (il_bit)
		msg->data[msg->offset++] = payload_id_len;

	if (type_name) {
		memcpy(msg->data + msg->offset, type_name, type_len);
		msg->offset += type_len;
	}

	if (il_bit) {
		memcpy(msg->data + msg->offset, payload_id, payload_id_len);
		msg->offset += payload_id_len;
	}

	return msg;

fail:
	near_error("ndef message struct allocation failed");
	free_ndef_message(msg);

	return NULL;
}

/*
 *  This is a wrapper to ndef_message_alloc, as, in most cases,
 *  there's no payload id, and MB=TRUE and ME=TRUE. Default type name format
 *  is also set to RECORD_TNF_WELLKNOWN
 *
 */
static struct near_ndef_message *ndef_message_alloc(char *type_name,
							uint32_t payload_len)
{
	return ndef_message_alloc_complete(type_name, payload_len,
			NULL, 0,
			RECORD_TNF_WELLKNOWN,
			true, true);
}

static enum carrier_power_state get_cps(uint8_t data)
{
	/* enum carrier_power_state values match binary format */
	return data & AC_CPS_MASK;
}

static struct near_ndef_ac_payload *parse_ac_payload(uint8_t *payload,
						uint32_t length)
{
	struct near_ndef_ac_payload *ac_payload = NULL;
	uint32_t offset;

	DBG("");

	if (!payload)
		return NULL;

	offset = 0;
	ac_payload = g_try_malloc0(sizeof(struct near_ndef_ac_payload));
	if (!ac_payload)
		goto fail;

	/* Carrier flag */
	ac_payload->cps = get_cps(payload[offset]);
	offset++;

	/* Carrier data reference length */
	ac_payload->cdr_len = payload[offset];
	offset++;

	if (ac_payload->cdr_len == 0)
		goto fail;

	/* Carrier data reference */
	ac_payload->cdr = g_try_malloc0(ac_payload->cdr_len + 1);
	if (!ac_payload->cdr)
		goto fail;

	memcpy(ac_payload->cdr, payload + offset, ac_payload->cdr_len);
	offset = offset + ac_payload->cdr_len;

	/* Auxiliary data reference count */
	ac_payload->adata_refcount = payload[offset];
	offset++;

	if (ac_payload->adata_refcount == 0)
		return ac_payload;

	/* save the auxiliary data reference */
	ac_payload->adata = g_try_malloc0(
			ac_payload->adata_refcount * sizeof(uint16_t));
	if (!ac_payload->adata)
		goto fail;

	memcpy(ac_payload->adata, payload + offset,
			ac_payload->adata_refcount * sizeof(uint16_t));

	/* and leave */
	return ac_payload;

fail:
	near_error("ac payload parsing failed");
	free_ac_payload(ac_payload);

	return NULL;
}

/* carrier power state & carrier reference */
static struct near_ndef_message *near_ndef_prepare_ac_message(uint8_t cps,
								char *cdr,
								uint8_t cdr_len)
{
	struct near_ndef_message *ac_msg;

	/* alloc "ac" message minus adata*/
	ac_msg = ndef_message_alloc_complete("ac",
						AC_RECORD_PAYLOAD_LEN(cdr_len),
						NULL, 0,
						RECORD_TNF_WELLKNOWN,
						true, true);
	if (!ac_msg)
		return NULL;

	/* Prepare ac message */
	ac_msg->data[ac_msg->offset++] = cps;

	ac_msg->data[ac_msg->offset++] = cdr_len;
	memcpy(ac_msg->data + ac_msg->offset, cdr, cdr_len); /* cdr */
	ac_msg->offset += cdr_len;

	ac_msg->data[ac_msg->offset] = 0; /* adata ref count */

	/* Check if we want an empty record */
	if (*cdr == 0x00)
		ac_msg->length = 0;

	return ac_msg;
}

/* Collision Record message */
static struct near_ndef_message *near_ndef_prepare_cr_message(uint16_t cr_id)
{
	struct near_ndef_message *cr_msg;

	cr_msg = ndef_message_alloc_complete("cr", sizeof(uint16_t),
						NULL, 0,
						RECORD_TNF_WELLKNOWN,
						true, true);
	if (!cr_msg)
		return NULL;

	/* Prepare ac message */
	near_put_be16(cr_id, cr_msg->data + cr_msg->offset);

	return cr_msg;
}

static struct near_ndef_message *near_ndef_prepare_cfg_message(char *mime_type,
					uint8_t *data, int data_len,
					char *cdr, uint8_t cdr_len)
{
	struct near_ndef_message *msg = NULL;

	DBG(" %s", mime_type);

	if (!mime_type)
		return NULL;

	msg = ndef_message_alloc_complete(mime_type, data_len, cdr, cdr_len,
						RECORD_TNF_MIME, true, true);
	if (!msg)
		return NULL;

	/* store data */
	if (data)
		memcpy(msg->data + msg->offset, data, data_len);

	return msg;
}

/*
 * Prepare alternative carrier and configuration records
 * (e.g. bluetooth or wifi or Hc)
 */
static int near_ndef_prepare_ac_and_cfg_records(enum record_type type,
					enum handover_carrier carrier,
					struct near_ndef_message **ac,
					struct near_ndef_message **cfg,
					struct near_ndef_mime_payload *mime,
					struct carrier_data *remote_carrier)
{
	struct carrier_data *local_carrier;
	char cdr;
	char *mime_type, *carrier_string;
	uint16_t prop;

	DBG("");

	if (!ac || !cfg)
		return -EINVAL;

	switch (carrier) {
	case NEAR_CARRIER_BLUETOOTH:
		cdr = '0';
		carrier_string = "Bluetooth";
		mime_type = BT_MIME_STRING_2_1;
		local_carrier = __near_agent_handover_request_data(
					HO_AGENT_BT, remote_carrier);
		if (local_carrier)
			break;

		prop = (mime) ? mime->handover.properties :
							OOB_PROPS_EMPTY;
		local_carrier = __near_bluetooth_local_get_properties(prop);

		break;

	case NEAR_CARRIER_WIFI:
		cdr = '1';
		carrier_string = "WiFi-WSC";
		mime_type = WIFI_WSC_MIME_STRING;
		local_carrier = __near_agent_handover_request_data(
						HO_AGENT_WIFI, remote_carrier);
		break;

	case NEAR_CARRIER_EMPTY:
	case NEAR_CARRIER_UNKNOWN:
	default:
		return -EINVAL;
	}

	/*
	 * WiFi has to be handled a bit differently when we're trying
	 * to send the first Hr or Hs (i.e. remote_carrier == NULL).
	 * There are 2 invalid combinations:
	 *	a) AP mode and sending an Hr, as we won't be able to
	 *	   initiate the association.
	 *	b) STA mode and sending an Hs, as the AP won't be able
	 *	   initiate the association.
	 *
	 * a) is detected when local_carrier != NULL and record_type is
	 * Handover Request.
	 * b) is detected when local_carrier == NULL and record_type is
	 * Handover Select.
	 * In those 2 cases we return an error.
	 */
	if (carrier == NEAR_CARRIER_WIFI && !remote_carrier) {
		if (local_carrier &&
				type == RECORD_TYPE_WKT_HANDOVER_REQUEST) {
			g_free(local_carrier);
			return -EINVAL;
		}

		if (!local_carrier &&
				type == RECORD_TYPE_WKT_HANDOVER_SELECT)
			return -EINVAL;

		if (!local_carrier &&
				type == RECORD_TYPE_WKT_HANDOVER_REQUEST) {
			*cfg = near_ndef_prepare_cfg_message(mime_type,
							NULL, 0,
							&cdr, sizeof(cdr));
			*ac = near_ndef_prepare_ac_message(CPS_UNKNOWN, &cdr,
								sizeof(cdr));

			return 0;
		}
	}

	if (!local_carrier) {
		DBG("Unable to retrieve local carrier %s data", carrier_string);
		return -ESRCH;
	}

	*cfg = near_ndef_prepare_cfg_message(mime_type, local_carrier->data,
							local_carrier->size,
							&cdr, sizeof(cdr));
	*ac = near_ndef_prepare_ac_message(local_carrier->state,
							&cdr, sizeof(cdr));

	g_free(local_carrier);

	if (!*cfg || !*ac) {
		free_ndef_message(*ac);
		free_ndef_message(*cfg);

		return -ENOMEM;
	}

	return 0;
}

static void free_ndef_list(gpointer data)
{
	struct near_ndef_message *msg = data;

	free_ndef_message(msg);
}

static struct near_ndef_message *prepare_handover_message_header(char *type,
					uint32_t msg_len, uint32_t payload_len)
{
	struct near_ndef_message *ho_msg;

	ho_msg = ndef_message_alloc(type, msg_len);
	if (!ho_msg)
		return NULL;

	/*
	 * The handover payload length is not the *real* length.
	 * The PL refers to the NDEF record, not the extra ones.
	 * So, we have to fix the payload length in the header.
	 */
	ho_msg->data[NDEF_PAYLOAD_LENGTH_OFFSET] = payload_len;
	near_ndef_set_mb_me(ho_msg->data, true, false);

	/* Add version */
	ho_msg->data[ho_msg->offset++] = HANDOVER_VERSION;

	return ho_msg;
}

static uint32_t ndef_message_list_length(GList *list)
{
	struct near_ndef_message *msg;
	uint32_t length = 0;

	if (!list)
		return 0;

	while (list) {
		msg = list->data;
		length += msg->length;
		list = list->next;
	}

	return length;
}

static void copy_ac_records(struct near_ndef_message *ho, GList *acs)
{
	GList *temp = acs;
	struct near_ndef_message *ac;

	if (!ho || !temp)
		return;

	while (temp) {
		ac = temp->data;
		memcpy(ho->data + ho->offset, ac->data, ac->length);
		/*
		 * AC records are part of handover message payload,
		 * so modifying offset.
		 */
		ho->offset += ac->length;
		temp = temp->next;
	}
}

static void copy_cfg_records(struct near_ndef_message *ho, GList *cfgs)
{
	GList *temp = cfgs;
	struct near_ndef_message *cfg;
	uint32_t offset;

	if (!ho || !temp)
		return;

	offset = ho->offset;

	while (temp) {
		cfg = temp->data;
		memcpy(ho->data + offset, cfg->data, cfg->length);
		/*
		 * Configuration records (e.g. bt or wifi) records are not part
		 * of handover payload, they are consecutive ndef msgs. So
		 * here we are not modifying ho->offset.
		 */
		offset += cfg->length;
		temp = temp->next;
	}
}

static void set_mb_me_to_false(gpointer data, gpointer user_data)
{
	struct near_ndef_message *msg = data;

	near_ndef_set_mb_me(msg->data, false, false);
}

static struct near_ndef_message *near_ndef_prepare_empty_hs_message(void)
{
	struct near_ndef_message *hs_msg;
	struct near_ndef_message *ac_msg;
	char cdr = 0x00;
	uint32_t hs_length;

	DBG("");

	ac_msg = near_ndef_prepare_ac_message(CPS_UNKNOWN, &cdr, sizeof(cdr));
	if (!ac_msg)
		return NULL;

	hs_length = 1;
	hs_length += ac_msg->length;

	hs_msg = prepare_handover_message_header("Hs", hs_length, hs_length);
	if (!hs_msg)
		goto fail;

	near_ndef_set_mb_me(hs_msg->data, true, true);
	memcpy(hs_msg->data + hs_msg->offset, ac_msg->data, ac_msg->length);
	hs_msg->offset += ac_msg->length;

	if (hs_msg->offset > hs_msg->length)
		goto fail;

	free_ndef_message(ac_msg);

	return hs_msg;

fail:
	free_ndef_message(ac_msg);
	free_ndef_message(hs_msg);

	return NULL;
}

static struct near_ndef_message *near_ndef_prepare_hs_reply(
					GSList *remote_mimes,
					GSList *remote_cfgs)
{
	struct near_ndef_message *hs_msg = NULL;
	struct near_ndef_message *ac_msg;
	struct near_ndef_message *cfg_msg;
	struct near_ndef_mime_payload *remote_mime;
	struct carrier_data *remote_cfg;
	GList *ac_msgs = NULL, *cfg_msgs = NULL, *temp;
	GSList *mime_iter, *cfg_iter;
	uint8_t hs_length, hs_pl_length, num_of_carriers;
	int ret = -EINVAL;

	DBG("");

	/*
	 * Preparing empty Hs message in case remote devices has zero
	 * alternative carries or unknown mime types or unknown
	 * configuration data.
	 */
	if ((!remote_mimes || !remote_cfgs))
		return near_ndef_prepare_empty_hs_message();

	mime_iter = remote_mimes;
	cfg_iter  = remote_cfgs;

	while (mime_iter) {
		remote_mime = mime_iter->data;
		remote_cfg  = cfg_iter->data;
		if (!remote_mime || !remote_cfg)
			goto fail;

		ret = near_ndef_prepare_ac_and_cfg_records(
					RECORD_TYPE_WKT_HANDOVER_SELECT,
					remote_mime->handover.carrier_type,
					&ac_msg, &cfg_msg,
					remote_mime, remote_cfg);
		if (ret == 0) {
			ac_msgs  = g_list_append(ac_msgs, ac_msg);
			cfg_msgs = g_list_append(cfg_msgs, cfg_msg);
		}

		mime_iter = mime_iter->next;
		cfg_iter  = cfg_iter->next;
	}

	if (g_list_length(ac_msgs) == 0) {
		DBG("no alternative carriers, so preparing empty Hs message");
		return near_ndef_prepare_empty_hs_message();
	}

	/* Prepare Hs message */
	hs_pl_length = 1;
	/* Alternative carriers are part of handover record payload length */
	hs_pl_length += ndef_message_list_length(ac_msgs);

	hs_length = hs_pl_length;
	/* Configuration records are part of handover message length */
	hs_length += ndef_message_list_length(cfg_msgs);

	hs_msg = prepare_handover_message_header("Hs", hs_length, hs_pl_length);
	if (!hs_msg)
		goto fail;

	num_of_carriers = g_list_length(ac_msgs);

	if (num_of_carriers == 1) {
		/* only one message */
		ac_msg = ac_msgs->data;
		near_ndef_set_mb_me(ac_msg->data, true, true);
	} else if (num_of_carriers > 1) {
		g_list_foreach(ac_msgs, set_mb_me_to_false, NULL);
		/* first message */
		temp = g_list_first(ac_msgs);
		ac_msg = temp->data;
		near_ndef_set_mb_me(ac_msg->data, true, false);
		/* last message */
		temp = g_list_last(ac_msgs);
		ac_msg = temp->data;
		near_ndef_set_mb_me(ac_msg->data, false, true);
	}

	g_list_foreach(cfg_msgs, set_mb_me_to_false, NULL);
	temp = g_list_last(cfg_msgs);
	cfg_msg = temp->data;
	near_ndef_set_mb_me(cfg_msg->data, false, true);

	/* copy acs */
	copy_ac_records(hs_msg, ac_msgs);
	if (hs_msg->offset > hs_msg->length)
		goto fail;

	/*
	 * copy cfgs, cfg (associated to the ac) records length
	 * (bt or wifi) is not part of Hs initial size.
	 */
	copy_cfg_records(hs_msg, cfg_msgs);

	DBG("Hs message preparation is done");

	g_list_free_full(ac_msgs, free_ndef_list);
	g_list_free_full(cfg_msgs, free_ndef_list);

	return hs_msg;

fail:
	near_error("handover Hs message preparation failed");

	g_list_free_full(ac_msgs, free_ndef_list);
	g_list_free_full(cfg_msgs, free_ndef_list);

	free_ndef_message(hs_msg);

	return NULL;
}

static enum handover_carrier string2carrier(char *carrier)
{
	if (strcasecmp(carrier, NEAR_HANDOVER_AGENT_BLUETOOTH) == 0)
		return NEAR_CARRIER_BLUETOOTH;

	if (strcasecmp(carrier, NEAR_HANDOVER_AGENT_WIFI) == 0)
		return NEAR_CARRIER_WIFI;

	return NEAR_CARRIER_UNKNOWN;
}

static struct near_ndef_message *
near_ndef_prepare_ho_message(enum record_type type, GSList *carriers)
{
	struct near_ndef_message *ho_msg = NULL;
	struct near_ndef_message *cr_msg = NULL;
	struct near_ndef_message *ac_msg;
	struct near_ndef_message *cfg_msg;
	GList *ac_msgs = NULL, *cfg_msgs = NULL, *temp;
	uint16_t collision;
	uint8_t ho_length, ho_pl_length;
	int ret = -EINVAL;
	char *str_type;

	DBG("");

	switch (type) {
	case RECORD_TYPE_WKT_HANDOVER_REQUEST:
		str_type = "Hr";
		break;

	case RECORD_TYPE_WKT_HANDOVER_SELECT:
		str_type = "Hs";
		break;

	default:
		return NULL;
	}

	/* Hr message should have at least one carrier */
	while (carriers) {
		ret = near_ndef_prepare_ac_and_cfg_records(
				type,
				string2carrier(carriers->data),
				&ac_msg, &cfg_msg, NULL, NULL);
		if (ret == 0) {
			ac_msgs  = g_list_append(ac_msgs, ac_msg);
			cfg_msgs = g_list_append(cfg_msgs, cfg_msg);
		}

		carriers = carriers->next;
	}

	if (g_list_length(ac_msgs) == 0) {
		DBG("no alternative carriers to prepare Hr message");
		goto fail;
	}

	/* Prepare Hr message */
	ho_pl_length = 1;

	/* Prepare collision resolution record MB=1 ME=0, only for Hr */
	if (type == RECORD_TYPE_WKT_HANDOVER_REQUEST) {
		collision = GUINT16_TO_BE(g_random_int_range(0, G_MAXUINT16 + 1));
		cr_msg = near_ndef_prepare_cr_message(collision);
		if (!cr_msg)
			goto fail;

		near_ndef_set_mb_me(cr_msg->data, true, false);

		ho_pl_length += cr_msg->length;
	}

	/* Alternative carriers are part of handover record payload length */
	ho_pl_length += ndef_message_list_length(ac_msgs);

	ho_length = ho_pl_length;
	/* Configuration records are part of handover message length */
	ho_length += ndef_message_list_length(cfg_msgs);

	ho_msg = prepare_handover_message_header(str_type,
						ho_length, ho_pl_length);
	if (!ho_msg)
		goto fail;

	g_list_foreach(ac_msgs, set_mb_me_to_false, NULL);
	/* last message */
	temp = g_list_last(ac_msgs);
	ac_msg = temp->data;
	near_ndef_set_mb_me(ac_msg->data, false, true);

	/*
	 * Hs record payloads do not have collision recore, the first record
	 * will be the first ac record.
	 */
	if (type == RECORD_TYPE_WKT_HANDOVER_SELECT) {
		temp = g_list_first(ac_msgs);
		ac_msg = temp->data;
		near_ndef_set_mb_me(ac_msg->data, true, false);
	}

	g_list_foreach(cfg_msgs, set_mb_me_to_false, NULL);
	temp = g_list_last(cfg_msgs);
	cfg_msg = temp->data;
	near_ndef_set_mb_me(cfg_msg->data, false, true);

	if (type == RECORD_TYPE_WKT_HANDOVER_REQUEST) {
		/* copy cr */
		memcpy(ho_msg->data + ho_msg->offset,
				cr_msg->data, cr_msg->length);
		ho_msg->offset += cr_msg->length;

		if (ho_msg->offset > ho_msg->length)
			goto fail;
	}

	/* copy acs */
	copy_ac_records(ho_msg, ac_msgs);
	if (ho_msg->offset > ho_msg->length)
		goto fail;

	/*
	 * copy cfgs, cfg (associated to the ac) records length
	 * (bt or wifi) is not part of Hr initial size.
	 */
	copy_cfg_records(ho_msg, cfg_msgs);

	DBG("Handover message preparation is done");

	free_ndef_message(cr_msg);
	g_list_free_full(ac_msgs, free_ndef_list);
	g_list_free_full(cfg_msgs, free_ndef_list);

	return ho_msg;

fail:
	near_error("handover record preparation failed");

	g_list_free_full(ac_msgs, free_ndef_list);
	g_list_free_full(cfg_msgs, free_ndef_list);
	free_ndef_message(cr_msg);
	free_ndef_message(ho_msg);

	return NULL;
}

/* Code to fill hr record structure from acs and mimes lists */
static int near_fill_ho_payload(struct near_ndef_ho_payload *ho,
					GSList *acs, GSList *mimes)
{
	int rec_count;
	int i;
	GSList *temp;

	rec_count = g_slist_length(acs);
	ho->ac_payloads = g_try_malloc0(rec_count *
			sizeof(struct near_ndef_ac_payload *));
	if (!ho->ac_payloads)
		goto fail;
	temp = acs;
	for (i = 0; i < rec_count; i++) {
		ho->ac_payloads[i] = temp->data;
		temp = temp->next;
	}
	ho->number_of_ac_payloads = rec_count;
	g_slist_free(acs);

	/* Same process for cfg mimes */
	rec_count = g_slist_length(mimes);
	ho->cfg_payloads = g_try_malloc0(rec_count *
			sizeof(struct near_ndef_mime_payload *));
	if (!ho->cfg_payloads)
		goto fail;
	temp = mimes;
	for (i = 0; i < rec_count; i++) {
		ho->cfg_payloads[i] = temp->data;
		temp = temp->next;
	}

	ho->number_of_cfg_payloads = rec_count;
	g_slist_free(mimes);

	return 0;
fail:
	g_free(ho->ac_payloads);
	g_free(ho->cfg_payloads);
	ho->ac_payloads = NULL;
	ho->cfg_payloads = NULL;
	return -ENOMEM;
}

/*
 * This function will parse an handover record payload, retrieving sub records
 * like (ac, cr, er) but it  will also get the associated ndefs
 * (eg: handover carrier record, mime type for BT)
 * In a handover frame, only the following types are expected:
 *     RECORD_TYPE_WKT_HANDOVER_CARRIER:
 *     RECORD_TYPE_WKT_COLLISION_RESOLUTION
 *     RECORD_TYPE_MIME_TYPE
 *     RECORD_TYPE_WKT_ALTERNATIVE_CARRIER
 */
static struct near_ndef_ho_payload *parse_ho_payload(enum record_type rec_type,
		uint8_t *payload, uint32_t ho_length, size_t frame_length,
		uint8_t ho_mb, uint8_t ho_me, struct near_ndef_message **reply)
{
	struct near_ndef_ho_payload *ho_payload = NULL;
	struct near_ndef_ac_payload *ac = NULL;
	struct near_ndef_mime_payload *mime = NULL;
	struct carrier_data *c_data;
	struct near_ndef_record *trec = NULL;
	GSList *acs = NULL, *mimes = NULL, *c_datas = NULL;
	uint8_t mb = 0, me = 0, i;
	uint32_t offset;
	int16_t count_ac = 0;
	bool action = false, status;

	DBG("");

	if (!payload)
		return NULL;
	offset = 0;

	/* Create the handover record payload */
	ho_payload = g_try_malloc0(sizeof(struct near_ndef_ho_payload));
	if (!ho_payload)
		return NULL;

	/* Version is the first mandatory field of hr payload */
	ho_payload->version = payload[offset];

	/* If major is different, reply with an empty Hs */
	if (HANDOVER_MAJOR(ho_payload->version) !=
	    HANDOVER_MAJOR(HANDOVER_VERSION)) {
		near_error("Unsupported version (%d)", ho_payload->version);
		/* Skip parsing and return an empty record */
		if (reply)
			*reply = near_ndef_prepare_empty_hs_message();

		return ho_payload;
	}

	offset = offset + 1;

	/* We should work on the whole frame */
	ho_length = frame_length;

	while (offset < ho_length) {
		/* Create local record for mime parsing */
		trec = g_try_malloc0(sizeof(struct near_ndef_record));
		if (!trec)
			return NULL;

		trec->header = parse_record_header(payload, offset, ho_length);

		if (!trec->header)
			goto fail;

		offset = trec->header->offset;

		switch (trec->header->rec_type) {
		case RECORD_TYPE_WKT_SMART_POSTER:
		case RECORD_TYPE_WKT_SIZE:
		case RECORD_TYPE_WKT_TEXT:
		case RECORD_TYPE_WKT_TYPE:
		case RECORD_TYPE_WKT_ACTION:
		case RECORD_TYPE_WKT_URI:
		case RECORD_TYPE_WKT_HANDOVER_REQUEST:
		case RECORD_TYPE_WKT_HANDOVER_SELECT:
		case RECORD_TYPE_WKT_ERROR:
		case RECORD_TYPE_EXT_AAR:
		case RECORD_TYPE_UNKNOWN:
		case RECORD_TYPE_ERROR:
			break;

		case RECORD_TYPE_WKT_HANDOVER_CARRIER:
			DBG("HANDOVER_CARRIER");
			/*
			 * TODO process Hc record too !!!
			 * Used for Wifi session
			 */
			break;

		case RECORD_TYPE_MIME_TYPE:
			DBG("TYPE_MIME_TYPE");

			/* check mb/me bits */
			if (validate_record_begin_and_end_bits(&ho_mb, &ho_me,
				trec->header->mb, trec->header->me) != 0) {
				DBG("validate mb me failed");
				goto fail;
			}

			/*
			 * In Handover, the mime type gives bluetooth handover
			 * or WiFi configuration data.
			 * If we initiated the session, the received Hs frame
			 * is the signal to launch the pairing.
			 */
			if (rec_type == RECORD_TYPE_WKT_HANDOVER_SELECT)
				action = true;
			else
				action = false;

			/* HO payload for reply creation */
			trec->ho = ho_payload;

			mime = parse_mime_type(trec, payload, frame_length,
					offset, trec->header->payload_len,
					&c_data);
			trec->ho = NULL;

			if (!mime || !c_data)
				goto fail;

			/* add the mime to the list */
			mimes = g_slist_append(mimes, mime);
			/* add the carrier data to the list */
			c_datas = g_slist_append(c_datas, c_data);

			count_ac--;
			if (count_ac == 0)
				offset = ho_length;
			break;

		case RECORD_TYPE_WKT_COLLISION_RESOLUTION:
			DBG("COLLISION_RESOLUTION");

			/* check nested mb/me bits */
			if (validate_record_begin_and_end_bits(&mb, &me,
				trec->header->mb, trec->header->me) != 0) {
				DBG("validate mb me failed");
				goto fail;
			}

			ho_payload->collision_record =
					near_get_be16(payload + offset);

			break;

		case RECORD_TYPE_WKT_ALTERNATIVE_CARRIER:
			DBG("ALTERNATIVE_CARRIER");

			/* check nested mb/me bits */
			if (validate_record_begin_and_end_bits(&mb, &me,
				trec->header->mb, trec->header->me) != 0) {
				DBG("validate mb me failed");
				goto fail;
			}

			ac = parse_ac_payload(payload + offset,
					trec->header->payload_len);
			if (!ac)
				goto fail;

			acs = g_slist_append(acs, ac);

			/* TODO check if adata are present */
			count_ac++;
			break;
		}

		offset += trec->header->payload_len;
		g_free(trec->header->il_field);
		g_free(trec->header->type_name);
		g_free(trec->header);
		trec->header = NULL;

		g_free(trec);
		trec = NULL;
	}

	/*
	 * In case of multiple carriers, handover with any carrier
	 * gets done then leave the loop.
	 */
	if (action) {
		status = false;
		count_ac = g_slist_length(mimes);

		for (i = 0; i < count_ac; i++) {
			if (process_mime_type(g_slist_nth_data(mimes, i),
					g_slist_nth_data(c_datas, i)) == 0) {
				status = true;
				break;
			}
		}

		if (!status) {
			DBG("could not process alternative carriers");
			goto fail;
		}
	} else if (reply) {
		/* This is a Hs with no cfg and no Ac: No reply and fail */
		if (rec_type == RECORD_TYPE_WKT_HANDOVER_SELECT &&
					g_slist_length(acs) == 0) {
			*reply = NULL;
			goto fail;
		}

		/* Prepare Hs, it depends upon Hr message carrier types */
		*reply = near_ndef_prepare_hs_reply(mimes, c_datas);
		if (!*reply) {
			DBG("error in preparing in HS record");
			goto fail;
		}
	}

	if ((!acs) || (!mimes))
		return ho_payload;

	/* Save the records */
	if (near_fill_ho_payload(ho_payload, acs, mimes) < 0)
		goto fail;

	DBG("handover payload parsing complete");

	g_slist_free_full(c_datas, g_free);

	return ho_payload;

fail:
	near_error("handover payload parsing failed");

	if (trec) {
		if (trec->header) {
			g_free(trec->header->type_name);
			g_free(trec->header->il_field);
			g_free(trec->header);
		}
		g_free(trec);
	}

	g_slist_free_full(c_datas, g_free);
	free_ho_payload(ho_payload);

	return NULL;
}

static struct near_ndef_aar_payload *
parse_aar_payload(uint8_t *payload, uint32_t length)
{
	struct near_ndef_aar_payload *aar_payload = NULL;

	DBG("");

	if (!payload)
		return NULL;

	aar_payload = g_try_malloc0(sizeof(struct near_ndef_uri_payload));
	if (!aar_payload)
		return NULL;

	aar_payload->package = g_strndup((char *)payload, length);
	if (!aar_payload->package) {
		near_error("AAR payload parsing failed");
		free_aar_payload(aar_payload);
		return NULL;
	}

	DBG("AAR package %s", aar_payload->package);

	return aar_payload;
}

int __near_ndef_record_register(struct near_ndef_record *record, char *path)
{
	record->path = path;

	g_dbus_register_interface(connection, record->path,
						NFC_RECORD_INTERFACE,
						NULL, NULL, record_properties,
						record, NULL);

	return 0;
}

/*
 * These functions parse a specific type record (id or mime) to find the
 * associated string.
 */
bool near_ndef_record_cmp_id(struct near_ndef_record *rec1,
						struct near_ndef_record *rec2)
{
	DBG("");

	if ((!rec1) || (!rec2))
		return false;

	if ((!rec1->header) || (!rec2->header))
		return false;

	/* usual checks */
	if ((!rec1->header->il_field) ||
			(!rec2->header->il_field))
		return false;

	if (memcmp(rec1->header->il_field, rec2->header->il_field,
		(rec1->header->il_length) > (rec2->header->il_length)
					? (rec1->header->il_length) :
					(rec2->header->il_length)) != 0)
		return false;

	return true;
}

bool near_ndef_record_cmp_mime(struct near_ndef_record *rec1,
					struct near_ndef_record *rec2)
{

	DBG("");

	if ((!rec1) || (!rec2))
		return false;

	if ((!rec1->header) || (!rec2->header))
		return false;
	/* usual checks */
	if ((!rec1->mime) || (!rec2->mime))
		return false;

	if ((!rec1->mime->type) || (!rec2->mime->type))
		return false;

	if (strlen(rec1->mime->type) != strlen(rec2->mime->type))
		return false;

	if ((g_strcmp0(rec1->mime->type, rec2->mime->type) != 0))
		return false;

	return true;
}

/* helper to get the record data length */
size_t near_ndef_data_length(struct near_ndef_record *rec)
{
	if (!rec)
		return 0;
	else
		return rec->data_len;
}

/* helper to get the record data pointer */
uint8_t *near_ndef_data_ptr(struct near_ndef_record *rec)
{
	if (!rec)
		return NULL;
	else
		return rec->data;
}

GList *near_ndef_parse_msg(uint8_t *ndef_data, size_t ndef_length,
				struct near_ndef_message **reply)
{
	GList *records;
	uint8_t p_mb = 0, p_me = 0, *record_start;
	size_t offset = 0;
	struct near_ndef_record *record = NULL;
	struct carrier_data *c_data;

	DBG("");

	records = NULL;

	if (!ndef_data ||
		ndef_length < NDEF_MSG_MIN_LENGTH)
			goto fail;

	while (offset < ndef_length) {

		DBG("Record Header : 0x%X", ndef_data[offset]);

		record = g_try_malloc0(sizeof(struct near_ndef_record));
		if (!record)
			goto fail;

		record->header = parse_record_header(ndef_data, offset,
							ndef_length);
		if (!record->header)
			goto fail;

		if (validate_record_begin_and_end_bits(&p_mb, &p_me,
					record->header->mb,
					record->header->me) != 0) {
			DBG("validate mb me failed");
			goto fail;
		}

		record_start = ndef_data + offset;
		offset = record->header->offset;

		switch (record->header->rec_type) {
		case RECORD_TYPE_WKT_SIZE:
		case RECORD_TYPE_WKT_TYPE:
		case RECORD_TYPE_WKT_ACTION:
		case RECORD_TYPE_WKT_HANDOVER_CARRIER:
		case RECORD_TYPE_WKT_ALTERNATIVE_CARRIER:
		case RECORD_TYPE_WKT_COLLISION_RESOLUTION:
		case RECORD_TYPE_WKT_ERROR:
		case RECORD_TYPE_UNKNOWN:
		case RECORD_TYPE_ERROR:
			break;

		case RECORD_TYPE_WKT_HANDOVER_REQUEST:
		case RECORD_TYPE_WKT_HANDOVER_SELECT:
			/*
			 * Handover frame are a little bit special as the NDEF
			 * length (specified in the header) is not the real
			 * frame size. The complete frame includes extra NDEF
			 * following the initial handover NDEF
			 */
			record->ho = parse_ho_payload(record->header->rec_type,
					ndef_data + offset,
					record->header->payload_len,
					ndef_length - offset,
					record->header->mb, record->header->me,
					reply);
			if (!record->ho)
				goto fail;

			/* the complete frame is processed, break the loop */
			record->header->payload_len = ndef_length;
			break;

		case RECORD_TYPE_WKT_TEXT:
			record->text = parse_text_payload(ndef_data + offset,
						record->header->payload_len);

			if (!record->text)
				goto fail;

			break;

		case RECORD_TYPE_WKT_URI:
			record->uri = parse_uri_payload(ndef_data + offset,
						record->header->payload_len);

			if (!record->uri)
				goto fail;

			break;

		case RECORD_TYPE_WKT_SMART_POSTER:
			record->sp = parse_sp_payload(
						ndef_data + offset,
						record->header->payload_len);

			if (!record->sp)
				goto fail;

			break;

		case RECORD_TYPE_MIME_TYPE:
			record->mime = parse_mime_type(record, ndef_data,
						ndef_length, offset,
						record->header->payload_len,
						&c_data);
			if (!record->mime)
				goto fail;

			/* No carrier data, move on */
			if (!c_data)
				break;

			if (process_mime_type(record->mime, c_data) < 0) {
				g_free(c_data);
				c_data = NULL;
				goto fail;
			}

			g_free(c_data);
			c_data = NULL;
			break;

		case RECORD_TYPE_EXT_AAR:
			record->aar = parse_aar_payload(ndef_data + offset,
						record->header->payload_len);

			if (!record->aar)
				goto fail;

			break;
		}

		record->data_len = record->header->header_len +
					record->header->payload_len;

		record->data = g_try_malloc0(record->data_len);
		if (!record->data)
			goto fail;

		memcpy(record->data, record_start, record->data_len);

		records = g_list_append(records, record);

		build_record_type_string(record);

		offset += record->header->payload_len;
	}

	return records;

fail:
	near_error("ndef parsing failed");
	free_ndef_record(record);

	return records;
}

void near_ndef_records_free(GList *records)
{
	GList *list;

	for (list = records; list; list = list->next) {
		struct near_ndef_record *record = list->data;

		__near_ndef_record_free(record);
	}

	g_list_free(records);
}

/*
 * Compute ndef records length, even though the submitted frame is incomplete.
 * This code is used in the handover read function, as we have to "guess" the
 * final frame size.
 *
 * Message size for SR=1 is:
 *  1 : ndef rec header (offset 0)
 *  x : record type length (offset 1)
 *  y : payload length (offset 2) 1 byte ONLY if SR=1
 *	if SR=0: (4bytes) 32 bits
 *  z : payload id length (offset 3) ONLY if il_length=1
 * */
int near_ndef_record_length(uint8_t *ndef_in, size_t ndef_in_length)
{
	int ndef_size;	 /* default size for NDEF hdr + rec typ len + payl */
	size_t offset;
	uint8_t hdr;

	DBG("");

	if (ndef_in_length < 3)
		return -EINVAL;

	ndef_size = 3;
	offset = 0;

	/* save header byte */
	hdr = ndef_in[offset];
	offset++;

	/* header->type_len */
	ndef_size += ndef_in[offset++];

	/* header->payload_len */
	if (RECORD_SR_BIT(hdr) == 1) {
		ndef_size += ndef_in[offset++];
	} else {
		ndef_size += near_get_be32(ndef_in + offset);
		offset += 4;

		if (offset >= ndef_in_length)
			return -ERANGE;
	}

	/* header->il */
	ndef_size += RECORD_IL_BIT(hdr);

	/* header->il_length */
	if (RECORD_IL_BIT(hdr) == 1)
		ndef_size += ndef_in[offset++];

	DBG("near_ndef_message_length is %d", ndef_size);

	return ndef_size;
}

int near_ndef_count_records(uint8_t *ndef_in, size_t ndef_in_length,
			uint8_t record_type)
{
	uint8_t p_mb = 0, p_me = 0;
	int err;
	size_t offset;
	struct near_ndef_record *record = NULL;
	int counted_records = 0 ;

	DBG("");

	offset = 0;

	if (!ndef_in ||	ndef_in_length < NDEF_MSG_MIN_LENGTH) {
		err = -EINVAL;
		goto fail;
	}

	while (offset < ndef_in_length) {
		record = g_try_malloc0(sizeof(struct near_ndef_record));
		if (!record) {
			err = -ENOMEM;
			goto fail;
		}

		/* Create a record */
		record->header = parse_record_header(ndef_in, offset,
							ndef_in_length);
		if (!record->header) {
			err = -EINVAL;
			goto fail;
		}

		/* Validate MB ME */
		if (validate_record_begin_and_end_bits(&p_mb, &p_me,
					record->header->mb,
					record->header->me) != 0) {
			DBG("validate mb me failed");
			err = -EINVAL;
			goto fail;
		}

		/* Is this what we want ? */
		if (record->header->rec_type == record_type)
			counted_records++;

		/* Jump to the next record */
		offset = record->header->offset + record->header->payload_len;

		free_ndef_record(record);
	}

	DBG("Type %d Records found: %d", record_type, counted_records);

	return counted_records;

fail:
	near_error("ndef counting failed");
	free_ndef_record(record);
	return err;
}

/* Possible encoding "UTF-8" or "UTF-16" */
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
		 (!language_code) ||
		 (!text)) {
		return NULL;
	}

	code_len = strlen(language_code);
	text_len = strlen(text);
	payload_length = 1 + code_len + text_len;

	msg = ndef_message_alloc("T", payload_length);
	if (!msg)
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
	free_ndef_message(msg);

	return NULL;
}

struct near_ndef_message *near_ndef_prepare_uri_record(uint8_t identifier,
					uint32_t field_length, uint8_t *field)
{
	struct near_ndef_message *msg = NULL;
	uint32_t payload_length;

	DBG("");

	/* Validate input parameters*/
	if ((field_length == 0 && field) ||
		(field_length != 0 && !field)) {
		return NULL;
	}

	payload_length = field_length + 1;

	msg = ndef_message_alloc("U", payload_length);
	if (!msg)
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
	free_ndef_message(msg);

	return NULL;
}

struct near_ndef_message *
near_ndef_prepare_smartposter_record(uint8_t uri_identifier,
					uint32_t uri_field_length,
					uint8_t *uri_field)
{
	struct near_ndef_message *msg = NULL, *uri = NULL;

	/* URI is mandatory in Smartposter */
	uri = near_ndef_prepare_uri_record(uri_identifier, uri_field_length,
								uri_field);
	if (!uri)
		goto fail;

	/* URI record length is equal to payload length of Sp record */
	msg = ndef_message_alloc("Sp", uri->length);
	if (!msg)
		goto fail;

	memcpy(msg->data + msg->offset, uri->data, uri->length);
	msg->offset += uri->length;

	if (msg->offset > msg->length)
		goto fail;

	free_ndef_message(uri);

	return msg;

fail:
	near_error("smartposter record preparation failed");

	free_ndef_message(uri);
	free_ndef_message(msg);

	return NULL;
}

static char *get_text_field(DBusMessage *msg, char *text)
{
	DBusMessageIter iter, arr_iter;
	char *uri = NULL;

	DBG("");

	if (!text)
		return NULL;

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
			if (g_strcmp0(key, text) == 0)
				dbus_message_iter_get_basic(&var_iter, &uri);

			break;
		}

		dbus_message_iter_next(&arr_iter);
	}

	return uri;
}

static inline char *get_uri_field(DBusMessage *msg)
{
	return get_text_field(msg, "URI");
}

static GSList *get_carrier_field(DBusMessage *msg)
{
	char *carrier;
	char **arr;
	GSList *carriers = NULL;
	uint8_t num_of_carriers, i;

	DBG("");

	carrier = get_text_field(msg, "Carrier");
	if (!carrier)
		return NULL;

	arr = g_strsplit(carrier, ",", NEAR_CARRIER_MAX);
	num_of_carriers = g_strv_length(arr);

	for (i = 0; i < num_of_carriers; i++)
		carriers = g_slist_append(carriers, g_strdup(arr[i]));

	g_strfreev(arr);

	return carriers;
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
	uint8_t id_len, i, id;
	uint32_t uri_len;

	DBG("");

	uri = get_uri_field(msg);
	if (!uri)
		return NULL;

	id = 0;
	id_len = 0;

	for (i = 1; i <= NFC_MAX_URI_ID; i++) {
		uri_prefix = __near_ndef_get_uri_prefix(i);

		if (uri_prefix &&
		    g_str_has_prefix(uri, uri_prefix)) {
			id = i;
			id_len = strlen(uri_prefix);
			break;
		}
	}

	DBG("%d %d\n", i, id_len);

	uri_len = strlen(uri) - id_len;
	return near_ndef_prepare_uri_record(id, uri_len,
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
	 * Currently this function supports only mandatory URI record,
	 * TODO: Other records support.
	 */
	uri = get_uri_field(msg);
	if (!uri)
		return NULL;

	for (i = 1; i <= NFC_MAX_URI_ID; i++) {
		uri_prefix = __near_ndef_get_uri_prefix(i);

		if (uri_prefix &&
				g_str_has_prefix(uri, uri_prefix))
			break;
	}

	if (!uri_prefix) {
		i = 0;
		id_len = 0;
	} else
		id_len = strlen(uri_prefix);

	uri_len = strlen(uri) - id_len;
	return near_ndef_prepare_smartposter_record(i, uri_len,
						(uint8_t *)(uri + id_len));
}

static struct near_ndef_message *build_ho_record(enum record_type type,
							DBusMessage *msg)
{
	struct near_ndef_message *ho;
	GSList *carriers;

	DBG("");

	carriers = get_carrier_field(msg);
	ho = near_ndef_prepare_ho_message(type, carriers);
	g_slist_free_full(carriers, g_free);

	return ho;
}

static int fill_wifi_wsc_data(uint8_t *tlv, uint16_t id,
				uint16_t data_len, uint8_t *data)
{
	int offset = 0;

	if (!tlv || !data)
		return 0;

	fillb16(tlv, id);
	offset += WIFI_WSC_ID_LENGTH;

	fillb16(tlv + offset, data_len);
	offset += WIFI_WSC_ID_DATA_LENGTH;

	memcpy(tlv + offset, data, data_len);
	offset += data_len;

	return offset;
}

static void get_wsc_data(DBusMessageIter iter, char **ssid, char **pass)
{
	DBG("");

	*ssid = NULL;
	*pass = NULL;

	while (dbus_message_iter_get_arg_type(&iter) !=
					DBUS_TYPE_INVALID) {
		const char *key;
		DBusMessageIter ent_iter;
		DBusMessageIter var_iter;

		dbus_message_iter_recurse(&iter, &ent_iter);
		dbus_message_iter_get_basic(&ent_iter, &key);
		dbus_message_iter_next(&ent_iter);
		dbus_message_iter_recurse(&ent_iter, &var_iter);

		switch (dbus_message_iter_get_arg_type(&var_iter)) {
		case DBUS_TYPE_STRING:
			if (g_strcmp0(key, "SSID") == 0)
				dbus_message_iter_get_basic(&var_iter, ssid);
			else if (g_strcmp0(key, "Passphrase") == 0)
				dbus_message_iter_get_basic(&var_iter, pass);

			break;
		}

		dbus_message_iter_next(&iter);
	}
}

struct near_ndef_message *near_ndef_prepare_wsc_record(char *ssid,
							char *passphrase)
{
	uint16_t ssid_len, pass_len, key_type;
	uint8_t temp_key[2];
	uint8_t *tlv;
	uint32_t tlv_len, offset;
	struct near_ndef_message *mime;

	/* At least SSID is required in case of open network */
	if (!ssid)
		return NULL;

	DBG("SSID %s Passphrase %s", ssid, passphrase);

	/* Prepare TLV from ssid and passphrasse */
	ssid_len = strlen(ssid);

	if (passphrase) {
		pass_len = strlen(passphrase);
		key_type = WIFI_WSC_KEY_PSK;
	} else {
		pass_len = 0;
		key_type = WIFI_WSC_KEY_OPEN;
	}

	/* add ssid length */
	tlv_len = WIFI_WSC_ID_LENGTH + WIFI_WSC_ID_DATA_LENGTH + ssid_len;
	/* add authentication type length */
	tlv_len += WIFI_WSC_ID_LENGTH + WIFI_WSC_ID_DATA_LENGTH + 2;
	/* add network key length */
	if (passphrase)
		tlv_len += WIFI_WSC_ID_LENGTH +
				WIFI_WSC_ID_DATA_LENGTH + pass_len;

	tlv = g_try_malloc0(tlv_len);
	if (!tlv)
		return NULL;

	offset = 0;
	/* copy SSID */
	offset += fill_wifi_wsc_data(tlv, WIFI_WSC_ID_SSID,
					ssid_len, (uint8_t *) ssid);

	/*
	 * copy authentication type
	 * copy key type to temp key array to maintain endianess
	 * and fill wsc data
	 */
	fillb16(temp_key, key_type);
	offset += fill_wifi_wsc_data(tlv + offset, WIFI_WSC_ID_AUTH_TYPE,
						WIFI_WSC_ID_DATA_LENGTH,
						(uint8_t *) temp_key);

	/* copy Network Key */
	if (passphrase)
		offset += fill_wifi_wsc_data(tlv + offset, WIFI_WSC_ID_KEY,
						pass_len,
						(uint8_t *) passphrase);

	mime = ndef_message_alloc_complete(WIFI_WSC_MIME_STRING, tlv_len, NULL,
						0, RECORD_TNF_MIME, true,
					   true);
	if (!mime) {
		g_free(tlv);
		return NULL;
	}

	memcpy(mime->data + mime->offset, tlv, tlv_len);
	g_free(tlv);

	return mime;
}

static char *get_mime_payload_data(DBusMessageIter iter,
				char **payload, int *payload_len)
{
	DBG("");

	if (!payload || !payload_len) {
		near_error("Payload %p payload_len %p", payload, payload_len);
		return NULL;
	}

	while (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INVALID) {
		const char *key;
		DBusMessageIter ent_iter;
		DBusMessageIter var_iter;
		DBusMessageIter arr_iter;

		dbus_message_iter_recurse(&iter, &ent_iter);
		dbus_message_iter_get_basic(&ent_iter, &key);
		dbus_message_iter_next(&ent_iter);
		dbus_message_iter_recurse(&ent_iter, &var_iter);

		if (g_strcmp0(key, "Payload") == 0) {
			if (dbus_message_iter_get_arg_type(&var_iter) ==
							DBUS_TYPE_ARRAY &&
			    dbus_message_iter_get_element_type(&var_iter) ==
							DBUS_TYPE_BYTE) {
					dbus_message_iter_recurse(&var_iter,
								 &arr_iter);
					dbus_message_iter_get_fixed_array(
							&arr_iter, payload,
							payload_len);
			} else {
				near_error("Unexpected payload type");
				return NULL;
			}
		}
		dbus_message_iter_next(&iter);
	}

	return *payload;
}

static struct near_ndef_message *near_ndef_prepare_mime_payload_record(
				char *type, char *payload, int payload_len)
{
	struct near_ndef_message *mime;

	DBG("Payload %*s", payload_len, payload);
	mime = ndef_message_alloc_complete(type, payload_len, NULL, 0,
						RECORD_TNF_MIME, true, true);
	if (!mime) {
		near_error("Failed to alloc NDEF message");
		return NULL;
	}

	memcpy(mime->data + mime->offset, payload, payload_len);

	return mime;
}

static struct near_ndef_message *build_mime_record(DBusMessage *msg)
{
	DBusMessageIter iter, arr_iter;
	char *key, *mime_str, *ssid, *passphrase;

	DBG("");

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &arr_iter);

	while (dbus_message_iter_get_arg_type(&arr_iter) !=
					DBUS_TYPE_INVALID) {
		DBusMessageIter ent_iter;
		DBusMessageIter var_iter;

		dbus_message_iter_recurse(&arr_iter, &ent_iter);
		dbus_message_iter_get_basic(&ent_iter, &key);

		if (g_strcmp0(key, "MIME") == 0) {
			dbus_message_iter_next(&ent_iter);
			dbus_message_iter_recurse(&ent_iter, &var_iter);
			dbus_message_iter_get_basic(&var_iter, &mime_str);

			if (g_strcmp0(mime_str, WIFI_WSC_MIME_STRING) == 0) {
				struct near_ndef_message *mime;
				struct carrier_data *carrier;

				get_wsc_data(arr_iter, &ssid, &passphrase);
				if (ssid)
					return near_ndef_prepare_wsc_record(
							ssid, passphrase);

				/*
				 * If we did not get an SSID and optionally
				 * a passphrase from the DBus message, then
				 * we try to get one from the WiFi-WSC agent.
				 */
				carrier = __near_agent_handover_request_data(
							HO_AGENT_WIFI, NULL);
				if (!carrier)
					return NULL;

				mime = ndef_message_alloc_complete(
					WIFI_WSC_MIME_STRING, carrier->size,
					NULL, 0, RECORD_TNF_MIME, true, true);
				if (!mime) {
					g_free(carrier);
					return NULL;
				}

				memcpy(mime->data + mime->offset,
					carrier->data, carrier->size);

				g_free(carrier);

				return mime;
			} else {
				/*
				 * Expect data is set in the Payload field of
				 * message.
				 */
				DBusMessageIter payload_iter;
				char *payload;
				int payload_len;

				DBG("mime string %s", mime_str);
				dbus_message_iter_recurse(&iter, &payload_iter);
				if (!get_mime_payload_data(payload_iter,
							&payload, &payload_len))
					return NULL;

				return near_ndef_prepare_mime_payload_record(
					mime_str, payload, payload_len);
			}
		}

		dbus_message_iter_next(&arr_iter);
	}

	return NULL;
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
			} else if (g_strcmp0(value, "Handover") == 0) {
				ndef = build_ho_record(
					RECORD_TYPE_WKT_HANDOVER_REQUEST, msg);
				break;
			} else if (g_strcmp0(value, "StaticHandover") == 0) {
				ndef = build_ho_record(
					RECORD_TYPE_WKT_HANDOVER_SELECT, msg);
				break;
			} else if (g_strcmp0(value, "MIME") == 0) {
				ndef = build_mime_record(msg);
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

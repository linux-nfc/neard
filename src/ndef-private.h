// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2011-2016  Intel Corporation. All rights reserved.
 * Copyright (c) 2021 Canonical Ltd.
 */

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
	uint8_t *payload;
	uint32_t payload_len;
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

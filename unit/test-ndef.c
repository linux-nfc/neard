/*
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "near.h"
#include "ndef.h"

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
	uint8_t	type_len;
	enum record_type rec_type;
	char *type_name;
	uint32_t header_len;
};

struct near_ndef_uri_payload {
	uint8_t identifier;

	uint32_t  field_length;
	uint8_t  *field;
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

	char *type;

	uint8_t *data;
	size_t data_len;
};

/* http://www.intel.com URI NDEF */
static uint8_t uri[] = {0xd1, 0x1, 0xa, 0x55,
			0x1, 0x69, 0x6e, 0x74,
			0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d};

static void test_ndef_free_record(struct near_ndef_record *record)
{
	g_free(record->header);
	g_free(record->type);
	g_free(record->data);
	g_free(record);

}

static void test_ndef_uri(void)
{
	GList *records;
	struct near_ndef_record *record;

	records = near_ndef_parse_msg(uri, sizeof(uri), NULL);

	g_assert(records);
	g_assert(g_list_length(records) == 1);

	record = (struct near_ndef_record *)(records->data);

	g_assert(record->header->rec_type == RECORD_TYPE_WKT_URI);
	g_assert(record->header->mb == 1);
	g_assert(record->header->me == 1);

	g_assert(record->uri);
	g_assert(strcmp((char *)record->uri->field, "intel.com") == 0);

	g_print("NDEF URI field: %s\n", record->uri->field);

	g_free(record->uri->field);
	g_free(record->uri);
	test_ndef_free_record(record);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/testndef/Test URI NDEF", test_ndef_uri);

	return g_test_run();
}

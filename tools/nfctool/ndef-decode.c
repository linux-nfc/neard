/*
 *
 *  Near Field Communication nfctool
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

#include <stdio.h>
#include <glib.h>
#include <errno.h>
#include <string.h>

#include "nfctool.h"
#include "sniffer.h"
#include "ndef-decode.h"

#define bool_str(b) (b) ? "True" : "False"

#define ndef_printf_header(fmt, ...) print_indent(NDEF_HEADER_INDENT, \
						NDEF_COLOR, fmt, ## __VA_ARGS__)

#define ndef_printf_msg(fmt, ...) print_indent(NDEF_MSG_INDENT, NDEF_COLOR, \
						fmt, ## __VA_ARGS__)

#define ndef_printf_error(fmt, ...) print_indent(NDEF_MSG_INDENT, COLOR_ERROR, \
						fmt, ## __VA_ARGS__)
enum record_tnf {
	RECORD_TNF_EMPTY     = 0x00,
	RECORD_TNF_WELLKNOWN = 0x01,
	RECORD_TNF_MIME      = 0x02,
	RECORD_TNF_URI       = 0x03,
	RECORD_TNF_EXTERNAL  = 0x04,
	RECORD_TNF_UNKNOWN   = 0x05,
	RECORD_TNF_UNCHANGED = 0x06,
};

static gchar *tnf_str[] = {
	"Empty (0x00)",
	"NFC Forum well-known type [NFC RTD] (0x01)",
	"Media-type as defined in RFC 2046 [RFC 2046] (0x02)",
	"Absolute URI as defined in RFC 3986 [RFC 3986] (0x03)",
	"NFC Forum external type [NFC RTD] (0x04)",
	"Unknown (0x05)",
	"Unchanged (0x06)",
	"Reserved (0x07)"
};

int ndef_print_records(guint8 *data, guint32 data_len)
{
	gboolean mb, me, cf, sr, il;
	enum record_tnf tnf;
	char *mime_string;
	guint8 type_len;
	guint8 *type;
	guint32 payload_len;
	guint8 *payload;
	guint8 id_len;
	guint8 *id;
	guint32 ndef_offset, record_offset;
	guint8 *record;
	int err = 0;

#define CHECK_OFFSET(s)							\
	do {								\
		if (data_len - ndef_offset < (s)) {			\
			ndef_printf_error("Malformed NDEF record");	\
			sniffer_print_hexdump(stdout, data, data_len,	\
					      NDEF_HEX_INDENT, TRUE);	\
			err = -EINVAL;					\
			goto exit;					\
		}							\
	} while (0)

	ndef_offset = 0;

	while (ndef_offset < data_len) {

		ndef_printf_header("NDEF Record");

		record = data + ndef_offset;
		record_offset = 0;
		id_len = 0;
		type = NULL;
		id = NULL;
		payload = NULL;

		CHECK_OFFSET(2);

		mb  = (record[0] & 0x80) != 0;
		me  = (record[0] & 0x40) != 0;
		cf  = (record[0] & 0x20) != 0;
		sr  = (record[0] & 0x10) != 0;
		il  = (record[0] & 0x08) != 0;
		tnf = (record[0] & 0x07);

		type_len = record[1];

		record_offset += 2;

		if (sr) {
			CHECK_OFFSET(1);

			payload_len = record[record_offset];

			record_offset++;
		} else {
			CHECK_OFFSET(4);

			memcpy(&payload_len, record + record_offset, 4);

			payload_len = GUINT_FROM_BE(payload_len);

			record_offset += 4;
		}

		if (il) {
			CHECK_OFFSET(1);

			id_len = record[record_offset];

			record_offset++;
		}

		if (type_len > 0) {
			CHECK_OFFSET(type_len);

			type = record + record_offset;

			record_offset += type_len;
		}

		if (id_len > 0) {
			CHECK_OFFSET(id_len);

			id = record + record_offset;

			record_offset += id_len;
		}

		if (payload_len) {
			CHECK_OFFSET(payload_len);

			payload = record + record_offset;

			record_offset += payload_len;
		}

		ndef_printf_msg("Message Begin: %s",     bool_str(mb));
		ndef_printf_msg("Message End: %s",       bool_str(me));
		ndef_printf_msg("Chunk Flag: %s",        bool_str(cf));
		ndef_printf_msg("Short Record: %s",      bool_str(sr));
		ndef_printf_msg("ID Length present: %s", bool_str(il));
		ndef_printf_msg("Type Name Format: %s",  tnf_str[tnf]);
		ndef_printf_msg("Type Length: %u",       type_len);
		ndef_printf_msg("Payload Length: %u",    payload_len);

		if (il)
			ndef_printf_msg("ID Length: %u", id_len);

		if (type) {
			switch (tnf) {
			case RECORD_TNF_MIME:
				mime_string = g_try_malloc(type_len + 1);
				if (mime_string != NULL) {
					g_snprintf(mime_string,
						type_len + 1, "%s", type);

					ndef_printf_msg("Type: %s", mime_string);
					g_free(mime_string);
					break;
				}

			default:
				ndef_printf_msg("Type:");
				sniffer_print_hexdump(stdout, type, type_len,
							NDEF_HEX_INDENT, FALSE);

				break;
			}
		}

		if (id) {
			ndef_printf_msg("ID:");

			sniffer_print_hexdump(stdout, id, id_len,
					      NDEF_HEX_INDENT, FALSE);
		}

		if (payload) {
			ndef_printf_msg("Payload:");

			sniffer_print_hexdump(stdout, payload, payload_len,
					      NDEF_HEX_INDENT, FALSE);
		}

		ndef_offset += record_offset;
	}

exit:
	return err;

#undef CHECK_OFFSET
}

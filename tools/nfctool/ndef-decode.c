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
#include <stdint.h>
#include <glib.h>
#include <errno.h>
#include <string.h>

#include <near/types.h>

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

#define ndef_printf_buffer(prefix, buf, buf_len) \
do { \
	int i; \
	printf("%*c%s%s", NDEF_MSG_INDENT, ' ', 		\
	       use_color() ? NDEF_COLOR : "", (prefix));	\
	for (i = 0; i < (buf_len); i++)				\
		printf("%02X ", (buf)[i]);			\
	printf("\n"); \
} while(0)

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

/* BT EIR list */
#define EIR_UUID128_ALL		0x07 /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT		0x08 /* shortened local name */
#define EIR_NAME_COMPLETE	0x09 /* complete local name */

/* Specific OOB EIRs */
#define EIR_CLASS_OF_DEVICE	0x0D  /* class of device */
#define EIR_SP_HASH		0x0E  /* simple pairing hash C */
#define EIR_SP_RANDOMIZER	0x0F  /* simple pairing randomizer R */
/* Optional EIRs */
#define EIR_DEVICE_ID		0x10  /* device ID */
#define EIR_SECURITY_MGR_FLAGS	0x11  /* security manager flags */

static void ndef_print_bt_oob(guint8 *oob_data, guint32 oob_length)
{
	guint32 offset = 0;
	guint16 length = near_get_le16(oob_data);
	guint8 *bdaddr, eir_length, eir_type;
	char *local_name;

	if (length != oob_length) {
		ndef_printf_error("Malformed Bluetooth OOB data");
		return;
	}

	bdaddr = oob_data + 2;
	offset = 8;

	ndef_printf_msg("Bluetooth OOB Length: %d", length);
	ndef_printf_msg("Bluetooth Address: %x:%x:%x:%x:%x:%x",
			bdaddr[5], bdaddr[4], bdaddr[3],
			bdaddr[2], bdaddr[1], bdaddr[0]);

	while (offset < length) {
		eir_length = oob_data[offset];
		eir_type = oob_data[offset + 1];

		if (eir_length + offset + 1 > length)
			break;

		switch (eir_type) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			local_name = g_try_malloc0(eir_length);
			if (!local_name)
				break;

			g_snprintf(local_name, eir_length,
					"%s", oob_data + offset + 2);

			ndef_printf_msg("Bluetooth local name: %s", local_name);
			g_free(local_name);
			break;

		case EIR_CLASS_OF_DEVICE:
			ndef_printf_msg("Bluetooth CoD: 0x%02x-0x%02x-0x%02x",
					oob_data[offset + 4],
					oob_data[offset + 3],
					oob_data[offset + 2]);
			break;

		case EIR_SP_HASH:
			ndef_printf_buffer("Bluetooth Hash: ",
					oob_data + offset + 2, eir_length - 1);
			break;

		case EIR_SP_RANDOMIZER:
			ndef_printf_buffer("Bluetooth Randomizer: ",
					oob_data + offset + 2, eir_length - 1);
			break;

		default:
			break;
		}

		offset += eir_length + 1;
	}
}

#define DE_AUTHENTICATION_TYPE 0x1003
#define DE_NETWORK_KEY 0x1027
#define DE_SSID 0x1045

static void ndef_print_wsc_oob(guint8 *oob_data, guint32 oob_length)
{
	guint32 offset = 0;
	guint16 de_length, de_type;
	guint16 auth_type;
	char *ssid, *passphrase;

	while (offset < oob_length) {
		de_type = near_get_be16(oob_data + offset);
		de_length = near_get_be16(oob_data + offset + 2);

		switch(de_type) {
		case DE_AUTHENTICATION_TYPE:
			auth_type = near_get_be16(oob_data + offset + 4);
			ndef_printf_msg("WSC Authentication Type: 0x%02x",
								auth_type);
			break;

		case DE_SSID:
			ssid = g_try_malloc0(de_length + 1);
			if (!ssid)
				break;

			g_snprintf(ssid, de_length + 1,
					"%s", oob_data + offset + 4);

			ndef_printf_msg("SSID: %s", ssid);
			g_free(ssid);
			break;

		case DE_NETWORK_KEY:
			passphrase = g_try_malloc0(de_length + 1);
			if (!passphrase)
				break;

			g_snprintf(passphrase, de_length + 1,
					"%s", oob_data + offset + 4);

			ndef_printf_msg("Passphrase: %s", passphrase);
			g_free(passphrase);
			break;

		default:
			ndef_printf_buffer("Unknown Data Element: ",
					oob_data + offset + 4, de_length);
			break;

		}

		offset += 4 + de_length;
	}
}

int ndef_print_records(guint8 *data, guint32 data_len)
{
	bool mb, me, cf, sr, il;
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
		if (data_len - (ndef_offset + record_offset) < (s)) {	\
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
		mime_string = NULL;

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
				if (mime_string) {
					g_snprintf(mime_string,
						type_len + 1, "%s", type);

					ndef_printf_msg("Type: %s", mime_string);
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
			if (mime_string) {
				if (strcmp(mime_string,
				"application/vnd.bluetooth.ep.oob") == 0)
					ndef_print_bt_oob(payload, payload_len);
				else if (strcmp(mime_string,
						"application/vnd.wfa.wsc") == 0)
					ndef_print_wsc_oob(payload, payload_len);

				g_free(mime_string);
			} else {
				ndef_printf_msg("Payload:");

				sniffer_print_hexdump(stdout, payload,
					payload_len, NDEF_HEX_INDENT, FALSE);
			}
		}

		ndef_offset += record_offset;
	}

exit:
	return err;

#undef CHECK_OFFSET
}

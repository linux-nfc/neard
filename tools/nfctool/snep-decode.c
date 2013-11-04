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
#include <netdb.h>
#include <sys/time.h>

#include <near/nfc_copy.h>

#include "nfctool.h"
#include "sniffer.h"
#include "ndef-decode.h"
#include "snep-decode.h"

#define SNEP_HEADER_LEN 6

#define SNEP_REQUEST_CONTINUE	0x00
#define SNEP_REQUEST_GET	0x01
#define SNEP_REQUEST_PUT	0x02
#define SNEP_REQUEST_REJECT	0x7f

#define SNEP_RESPONSE_CONTINUE		0x80
#define SNEP_RESPONSE_SUCCESS		0x81
#define SNEP_RESPONSE_NOT_FOUND		0xc0
#define SNEP_RESPONSE_EXCESS_DATA	0xc1
#define SNEP_RESPONSE_BAD_REQUEST	0xc2
#define SNEP_RESPONSE_NOT_IMPLEMENTED	0xe0
#define SNEP_RESPONSE_UNSUPPORTED	0xe1
#define SNEP_RESPONSE_REJECT		0xff

#define snep_make_frag_index(idx, dir, lsap, rsap) \
				((((idx) << 24) & 0xFF000000) |	\
				(((dir)  << 16) & 0x00FF0000) |	\
				(((lsap) << 8)  & 0x0000FF00) |	\
				((rsap)         & 0x000000FF))

#define snep_get_frag_index(p)	\
		snep_make_frag_index((p)->adapter_idx, (p)->direction, \
				     (p)->llcp.local_sap, (p)->llcp.remote_sap)

#define snep_printf_header(fmt, ...) print_indent(SNEP_HEADER_INDENT, \
					       SNEP_COLOR, fmt, ## __VA_ARGS__)

#define snep_printf_msg(fmt, ...) print_indent(SNEP_MSG_INDENT, \
					       SNEP_COLOR, fmt, ## __VA_ARGS__)

#define snep_printf_error(fmt, ...) print_indent(SNEP_MSG_INDENT, COLOR_ERROR, \
						 fmt, ## __VA_ARGS__)

struct snep_frag {
	guint32 index;
	guint16 count;
	guint32 received;
	guint32 buffer_size;
	guint8 *buffer;
};

static GHashTable *snep_frag_hash = NULL;

static void snep_frag_free(struct snep_frag *frag)
{
	g_free(frag->buffer);
	g_free(frag);
}

static void snep_frag_delete(guint32 frag_index)
{
	DBG("Deleting frag with index 0x%x", frag_index);

	g_hash_table_remove(snep_frag_hash, GINT_TO_POINTER(frag_index));
}

static void snep_frag_rejected(struct sniffer_packet *packet)
{
	guint32 index;
	guint8 direction;

	/* reverse direction to delete the corresponding fragment */
	if (packet->direction == NFC_LLCP_DIRECTION_RX)
		direction = NFC_LLCP_DIRECTION_TX;
	else
		direction = NFC_LLCP_DIRECTION_RX;

	index = snep_make_frag_index(packet->adapter_idx,
				     direction,
				     packet->llcp.local_sap,
				     packet->llcp.remote_sap);

	snep_frag_delete(index);
}

static int snep_frag_append(struct snep_frag *frag,
			    struct sniffer_packet *packet)
{
	int err = 0;

	snep_printf_msg("Ongoing fragmented message");

	if (frag->received + packet->llcp.data_len > frag->buffer_size) {
		snep_printf_error("Too many bytes received");
		return -EINVAL;
	}

	memcpy(frag->buffer + frag->received, packet->llcp.data,
	       packet->llcp.data_len);

	frag->received += packet->llcp.data_len;

	frag->count++;

	snep_printf_msg("%s fragment #%hu of %u bytes (total %u/%u)",
			packet->direction == NFC_LLCP_DIRECTION_RX ? "Received" : "Sent",
		    frag->count, packet->llcp.data_len,
		    frag->received, frag->buffer_size);

	if (frag->received == frag->buffer_size) {
		snep_printf_msg("End of fragmented message");

		err = ndef_print_records(packet->snep.data,
					 packet->snep.data_len);

		snep_frag_delete(frag->index);
	}

	return err;
}

static int snep_decode_info(struct sniffer_packet *packet)
{
	struct snep_frag *frag;
	int err;

	if (packet->snep.data_len <= packet->snep.real_len) {
		/* Message is not fragmented */
		err = ndef_print_records(packet->snep.data,
					 packet->snep.data_len);

		return err;
	}

	frag = g_malloc(sizeof(struct snep_frag));
	if (!frag)
		return -ENOMEM;

	frag->count = 1;

	frag->buffer_size = packet->snep.data_len;

	frag->received = packet->snep.real_len;

	frag->buffer = g_malloc0(frag->buffer_size);
	if (!frag->buffer)
		return -ENOMEM;

	memcpy(frag->buffer, packet->snep.data, packet->snep.real_len);

	frag->index = snep_get_frag_index(packet);

	snep_printf_msg("Start %s fragmented message of %u bytes",
			packet->direction == NFC_LLCP_DIRECTION_RX ? "Receiving" : "Sending",
			frag->buffer_size);

	snep_printf_msg("%s fragment #%hu of %u bytes",
			packet->direction == NFC_LLCP_DIRECTION_RX ? "Received" : "Sent",
			frag->count, frag->received);

	DBG("Adding frag with index 0x%x", frag->index);

	g_hash_table_replace(snep_frag_hash, GINT_TO_POINTER(frag->index),
			     frag);

	return 0;
}

static int snep_decode_req_get(struct sniffer_packet *packet)
{
	guint32 acceptable_len;

	if (packet->snep.real_len < 4)
		return -EINVAL;

	memcpy(&acceptable_len, packet->snep.data, 4);
	packet->snep.acceptable_len = GUINT_FROM_BE(acceptable_len);

	packet->snep.data += 4;
	packet->snep.data_len -= 4;
	packet->snep.real_len -= 4;

	return 0;
}

static int snep_decode_header(struct sniffer_packet *packet)
{
	guint32 data_len;
	guint8 *data = packet->llcp.data;

	if (packet->llcp.data_len < SNEP_HEADER_LEN)
		return -EINVAL;

	packet->snep.version = data[0];

	packet->snep.rcode = data[1];

	memcpy(&data_len, data + 2, 4);

	packet->snep.data_len = GUINT_FROM_BE(data_len);

	packet->snep.real_len = packet->llcp.data_len - SNEP_HEADER_LEN;

	if (packet->snep.data_len != 0)
		packet->snep.data = data + SNEP_HEADER_LEN;

	return 0;
}

static void snep_print_version(struct sniffer_packet *packet)
{
	snep_printf_msg("Version: %d.%d", (packet->snep.version & 0xF0) >> 4,
		    packet->snep.version & 0x0F);
}

static void print_request(struct sniffer_packet *packet, gchar *msg)
{
	snep_print_version(packet);

	snep_printf_msg("Request: %s", msg);
}

static void snep_print_response(struct sniffer_packet *packet, gchar *msg)
{
	snep_print_version(packet);

	snep_printf_msg("Response: %s", msg);
}

int snep_print_pdu(struct sniffer_packet *packet)
{
	int err = 0;
	guint32 frag_index;
	struct snep_frag *frag;

	snep_printf_header("Simple NDEF Exchange Protocol (SNEP)");

	frag_index = snep_get_frag_index(packet);

	frag = g_hash_table_lookup(snep_frag_hash, GINT_TO_POINTER(frag_index));

	if (frag) {
		/* Incoming or outgoing fragmented message */
		err = snep_frag_append(frag, packet);

		if (err != 0) {
			snep_printf_error("Error receiving fragmented message");

			snep_frag_delete(frag_index);
		}

		goto exit;
	}

	err = snep_decode_header(packet);
	if (err != 0) {
		snep_printf_error("Error decoding message header");

		goto exit;
	}

	switch (packet->snep.rcode) {
	/* Requests */
	case SNEP_REQUEST_CONTINUE:
		print_request(packet, "Continue");
		break;

	case SNEP_REQUEST_GET:
		print_request(packet, "Get");

		err = snep_decode_req_get(packet);
		if (err != 0)
			goto exit;

		snep_printf_msg("Acceptable length: %u",
			    packet->snep.acceptable_len);

		snep_decode_info(packet);
		break;

	case SNEP_REQUEST_PUT:
		print_request(packet, "Put");

		snep_decode_info(packet);
		break;

	case SNEP_REQUEST_REJECT:
		print_request(packet, "Reject");

		snep_frag_rejected(packet);
		break;

	/* Responses */
	case SNEP_RESPONSE_CONTINUE:
		snep_print_response(packet, "Continue");
		break;

	case SNEP_RESPONSE_SUCCESS:
		snep_print_response(packet, "Success");

		if (packet->snep.data_len > 0)
			snep_decode_info(packet);
		break;

	case SNEP_RESPONSE_NOT_FOUND:
		snep_print_response(packet, "Not Found");
		break;

	case SNEP_RESPONSE_EXCESS_DATA:
		snep_print_response(packet, "Excess Data");
		break;

	case SNEP_RESPONSE_BAD_REQUEST:
		snep_print_response(packet, "Bad Request");
		break;

	case SNEP_RESPONSE_NOT_IMPLEMENTED:
		snep_print_response(packet, "Not Implemented");
		break;

	case SNEP_RESPONSE_UNSUPPORTED:
		snep_print_response(packet, "Unsupported");
		break;

	case SNEP_RESPONSE_REJECT:
		snep_print_response(packet, "Reject");

		snep_frag_rejected(packet);
		break;

	default:
		snep_printf_error("Invalid request or response code: %d",
			    packet->snep.rcode);
		break;
	}

exit:
	return err;
}

void snep_decode_cleanup(void)
{
	if (snep_frag_hash)
		g_hash_table_destroy(snep_frag_hash);
}

int snep_decode_init(void)
{
	snep_frag_hash =
		g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
				      (GDestroyNotify)snep_frag_free);

	return 0;
}

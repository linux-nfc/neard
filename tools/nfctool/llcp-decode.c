/*
 *
 *  Near Field Communication nfctool
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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
#include "llcp-decode.h"

/* Raw socket + LLCP headers */
#define RAW_LLCP_HEADERS_SIZE 4

#define LLCP_PTYPE_SYMM		0
#define LLCP_PTYPE_PAX		1
#define LLCP_PTYPE_AGF		2
#define LLCP_PTYPE_UI		3
#define LLCP_PTYPE_CONNECT	4
#define LLCP_PTYPE_DISC		5
#define LLCP_PTYPE_CC		6
#define LLCP_PTYPE_DM		7
#define LLCP_PTYPE_FRMR		8
#define LLCP_PTYPE_SNL		9
#define LLCP_PTYPE_I		12
#define LLCP_PTYPE_RR		13
#define LLCP_PTYPE_RNR		14

#define LLCP_DM_NORMAL			0x00
#define LLCP_DM_NO_ACTIVE_CONN		0x01
#define LLCP_DM_NOT_BOUND		0x02
#define LLCP_DM_REJECTED		0x03
#define LLCP_DM_PERM_SAP_FAILURE	0x10
#define LLCP_DM_PERM_ALL_SAP_FAILURE	0x11
#define LLCP_DM_TMP_SAP_FAILURE		0x20
#define LLCP_DM_TMP_ALL_SAP_FAILURE	0x21

enum llcp_param_t {
	LLCP_PARAM_VERSION = 1,
	LLCP_PARAM_MIUX,
	LLCP_PARAM_WKS,
	LLCP_PARAM_LTO,
	LLCP_PARAM_RW,
	LLCP_PARAM_SN,
	LLCP_PARAM_OPT,
	LLCP_PARAM_SDREQ,
	LLCP_PARAM_SDRES,

	LLCP_PARAM_MIN = LLCP_PARAM_VERSION,
	LLCP_PARAM_MAX = LLCP_PARAM_SDRES
};

static guint8 llcp_param_length[] = {
	0,
	1,
	2,
	2,
	1,
	1,
	0,
	1,
	0,
	2
};

static char *llcp_ptype_str[] = {
	"Symmetry (SYMM)",
	"Parameter Exchange (PAX)",
	"Aggregated Frame (AGF)",
	"Unnumbered Information (UI)",
	"Connect (CONNECT)",
	"Disconnect (DISC)",
	"Connection Complete (CC)",
	"Disconnected Mode (DM)",
	"Frame Reject (FRMR)",
	"Service Name Lookup (SNL)",
	"reserved",
	"reserved",
	"Information (I)",
	"Receive Ready (RR)",
	"Receive Not Ready (RNR)",
	"reserved",
	"Unknown"
};

static char *llcp_ptype_short_str[] = {
	"SYMM",
	"PAX",
	"AGF",
	"UI",
	"CONNECT",
	"DISC",
	"CC",
	"DM",
	"FRMR",
	"SNL",
	NULL,
	NULL,
	"I",
	"RR",
	"RNR",
	NULL,
	"Unknown"
};

static const gchar *llcp_param_str[] = {
	"",
	"Version Number",
	"Maximum Information Unit Extensions",
	"Well-Known Service List",
	"Link Timeout",
	"Receive Window Size",
	"Service Name",
	"Option",
	"Service Discovery Request",
	"Service Discovery Response"
};

#define llcp_printf_header(prefix, color, fmt, ...) \
				print_indent_prefix( LLCP_HEADER_INDENT,\
				color, prefix, \
				LLCP_COLOR, fmt, ## __VA_ARGS__)

#define llcp_printf_msg(fmt, ...) print_indent(LLCP_MSG_INDENT, \
						LLCP_COLOR, fmt, ## __VA_ARGS__)

#define llcp_printf_error(fmt, ...) print_indent(LLCP_MSG_INDENT, \
						COLOR_ERROR, fmt, ## __VA_ARGS__)

#define llcp_get_param_str(param_type) llcp_param_str[param_type]

#define llcp_get_param_len(param_type) llcp_param_length[param_type]

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

static struct timeval start_timestamp;

static GHashTable *connection_hash;

/* We associate an SN from a CONNECT to its sender */
static void llcp_add_connection_sn(struct sniffer_packet *packet, gchar *sn)
{
	guint8 ssap;

	if (packet->llcp.ptype != LLCP_PTYPE_CONNECT)
		return;

	/* If we're sending the CONNECT, we use our local SAP*/
	if (packet->llcp.local_sap != 0x1)
		ssap = packet->llcp.local_sap;
	else
		ssap = packet->llcp.remote_sap;

	g_hash_table_replace(connection_hash,
			    GINT_TO_POINTER(ssap), g_strdup(sn));
}

/* Check if there's a pending SN for this dsap */
static void llcp_check_cc(struct sniffer_packet *packet)
{
	guint8 dsap;
	gchar *sn;

	if (packet->llcp.ptype != LLCP_PTYPE_CC)
		return;

	/* Find the real destination SAP for this CC */
	if (packet->direction == NFC_LLCP_DIRECTION_RX)
		dsap = packet->llcp.local_sap;
	else
		dsap = packet->llcp.remote_sap;

	/* Do we have a CONNECT pending for this SAP ?*/
	sn = g_hash_table_lookup(connection_hash,
					GINT_TO_POINTER(dsap));
	if (!sn)
		return;

	if (strcmp(sn, "urn:nfc:sn:handover") == 0)
		opts.handover_sap = dsap;
}

static void free_connection(gpointer data)
{
	gchar *sn = data;

	g_free(sn);
}

static void llcp_print_params(struct sniffer_packet *packet)
{
	guint8 major, minor;
	guint16 miux, wks, tid;
	guint32 offset = 0;
	guint32 rmng;
	guint8 *param;
	guint8 param_len;
	gchar *sn, param_str[64];

	while (packet->llcp.data_len - offset >= 3) {
		param = packet->llcp.data + offset;
		rmng = packet->llcp.data_len - offset;

		if (param[0] < LLCP_PARAM_MIN || param[0] > LLCP_PARAM_MAX) {
			llcp_printf_error("Error decoding params");
			return;
		}

		param_len = llcp_get_param_len(param[0]);

		if (param_len == 0)
			param_len = param[1];

		if (param_len != param[1] || rmng < 2u + param_len) {
			llcp_printf_error("Error decoding params");
			return;
		}

		switch ((enum llcp_param_t)param[0]) {
		case LLCP_PARAM_VERSION:
			major = (param[2] & 0xF0) >> 4;
			minor = param[2] & 0x0F;
			sprintf(param_str, "%d.%d", major, minor);
			break;

		case LLCP_PARAM_MIUX:
			miux = ((param[2] & 0x07) << 8) | param[3];
			sprintf(param_str, "%d", miux);
			break;

		case LLCP_PARAM_WKS:
			wks = (param[2] << 8) | param[3];
			sprintf(param_str, "0x%02hX", wks);
			break;

		case LLCP_PARAM_LTO:
			sprintf(param_str, "%d", param[2]);
			break;

		case LLCP_PARAM_RW:
			sprintf(param_str, "%d", param[2] & 0x0F);
			break;

		case LLCP_PARAM_SN:
			sn = g_strndup((gchar *)param + 2, param_len);
			llcp_add_connection_sn(packet, sn);
			snprintf(param_str, 64, "%s", sn);
			g_free(sn);
			break;

		case LLCP_PARAM_OPT:
			sprintf(param_str, "0x%X", param[2] & 0x03);
			break;

		case LLCP_PARAM_SDREQ:
			tid = param[2];
			sn = g_strndup((gchar *)param + 3, param_len - 1);
			snprintf(param_str, 64, "TID:%d, SN:%s", tid, sn);
			g_free(sn);
			break;

		case LLCP_PARAM_SDRES:
			sprintf(param_str, "TID:%d, SAP:%d", param[2], param[3] & 0x3F);
			break;
		}

		llcp_printf_msg("%s: %s", llcp_get_param_str(param[0]),
				param_str);

		offset += 2 + param_len;
	}
}

static int llcp_decode_packet(guint8 *data, guint32 data_len,
			      struct sniffer_packet *packet)
{
	if (data_len < RAW_LLCP_HEADERS_SIZE)
		return -EINVAL;

	memset(packet, 0, sizeof(struct sniffer_packet));

	/* LLCP raw socket header */
	packet->adapter_idx = data[0];
	packet->direction = data[1] & 0x01;

	/* LLCP header */
	if (packet->direction == NFC_LLCP_DIRECTION_TX) {
		packet->llcp.remote_sap = (data[2] & 0xFC) >> 2;
		packet->llcp.local_sap = data[3] & 0x3F;
	} else {
		packet->llcp.remote_sap = data[3] & 0x3F;
		packet->llcp.local_sap = (data[2] & 0xFC) >> 2;
	}

	packet->llcp.ptype = ((data[2] & 0x03) << 2) | ((data[3] & 0xC0) >> 6);

	if (packet->llcp.ptype >= ARRAY_SIZE(llcp_ptype_str))
		return -EINVAL;

	packet->llcp.data = data + RAW_LLCP_HEADERS_SIZE;
	packet->llcp.data_len = data_len - RAW_LLCP_HEADERS_SIZE;

	/* Sequence field */
	if (packet->llcp.ptype >= LLCP_PTYPE_I) {
		if (packet->llcp.data_len == 0)
			return -EINVAL;

		packet->llcp.send_seq = ((packet->llcp.data[0] & 0xF0) >> 4);
		packet->llcp.recv_seq = packet->llcp.data[0] & 0x0F;

		packet->llcp.data++;
		packet->llcp.data_len--;
	}

	return 0;
}

static void llcp_print_sequence(struct sniffer_packet *packet)
{
	llcp_printf_msg("N(S):%d N(R):%d",
			packet->llcp.send_seq, packet->llcp.recv_seq);
}

static int llcp_print_agf(struct sniffer_packet *packet,
			  struct timeval *timestamp)
{
	guint8 *pdu;
	gsize pdu_size;
	gsize size;
	guint16 offset;
	guint16 count;
	int err;

	if (packet->llcp.data_len < 2) {
		llcp_printf_error("Error parsing AGF PDU");
		return -EINVAL;
	}

	printf("\n");

	pdu = NULL;
	pdu_size = 0;
	offset = 0;
	count = 0;

	while (offset < packet->llcp.data_len - 2) {
		size = (packet->llcp.data[offset] << 8) |
			packet->llcp.data[offset + 1];

		offset += 2;

		if (size == 0 || offset + size > packet->llcp.data_len) {
			llcp_printf_error("Error parsing AGF PDU");
			err = -EINVAL;
			goto exit;
		}

		if (size + NFC_LLCP_RAW_HEADER_SIZE > pdu_size) {
			pdu_size = size + NFC_LLCP_RAW_HEADER_SIZE;
			pdu = g_realloc(pdu, pdu_size);

			pdu[0] = packet->adapter_idx;
			pdu[1] = packet->direction;
		}

		memcpy(pdu + NFC_LLCP_RAW_HEADER_SIZE,
			packet->llcp.data + offset, size);

		llcp_printf_msg("-- AGF LLC PDU %02u:", count++);

		llcp_print_pdu(pdu, size + NFC_LLCP_RAW_HEADER_SIZE, timestamp);

		offset += size;
	}

	llcp_printf_msg("-- End of AGF LLC PDUs");

	err = 0;
exit:
	g_free(pdu);

	return err;
}

static int llcp_print_dm(struct sniffer_packet *packet)
{
	gchar *reason;

	if (packet->llcp.data_len != 1)
		return -EINVAL;

	switch (packet->llcp.data[0]) {
	case LLCP_DM_NORMAL:
	default:
		reason = "Normal disconnect";
		break;

	case LLCP_DM_NO_ACTIVE_CONN:
		reason =
		      "No active connection for connection-oriented PDU at SAP";
		break;

	case LLCP_DM_NOT_BOUND:
		reason = "No service bound to target SAP";
		break;

	case LLCP_DM_REJECTED:
		reason = "CONNECT PDU rejected by service layer";
		break;

	case LLCP_DM_PERM_SAP_FAILURE:
		reason = "Permanent failure for target SAP";
		break;

	case LLCP_DM_PERM_ALL_SAP_FAILURE:
		reason = "Permanent failure for any target SAP";
		break;

	case LLCP_DM_TMP_SAP_FAILURE:
		reason = "Temporary failure for target SAP";
		break;

	case LLCP_DM_TMP_ALL_SAP_FAILURE:
		reason = "Temporary failure for any target SAP";
		break;
	}

	llcp_printf_msg("Reason: %d (%s)", packet->llcp.data[0], reason);

	return 0;
}

static int llcp_print_i(struct sniffer_packet *packet)
{
	llcp_print_sequence(packet);

	if (packet->llcp.local_sap == opts.snep_sap ||
	    packet->llcp.remote_sap == opts.snep_sap) {
		int err;

		err = snep_print_pdu(packet);
		if (err != 0)
			llcp_printf_error("Error decoding SNEP frame");

		return err;
	} else 	if (packet->llcp.local_sap == opts.handover_sap ||
			packet->llcp.remote_sap == opts.handover_sap) {
		int err;

		err = ndef_print_records(packet->llcp.data,
					 packet->llcp.data_len);
		if (err != 0)
			llcp_printf_error("Error decoding Handover frame");
		return err;
	}

	sniffer_print_hexdump(stdout, packet->llcp.data,  packet->llcp.data_len,
				LLCP_MSG_INDENT, TRUE);

	return 0;
}

static int llcp_print_frmr(struct sniffer_packet *packet)
{
	guint8 info, ptype;

	if (packet->llcp.data_len != 4)
		return -EINVAL;

	info = packet->llcp.data[0];
	ptype = info & 0x0F;
	if (ptype >= ARRAY_SIZE(llcp_ptype_str))
		ptype = ARRAY_SIZE(llcp_ptype_str) - 1;

	llcp_printf_msg("W:%d I:%d R:%d S:%d PTYPE:%s SEQ: %d V(S):"
			" %d V(R): %d V(SA): %d V(RA): %d",
			(info & 0x80) >> 7, (info & 0x40) >> 6,
			(info & 0x20) >> 5, (info & 0x10) >> 4,
			llcp_ptype_short_str[ptype], packet->llcp.data[1],
			(packet->llcp.data[2] & 0xF0) >> 4,
			packet->llcp.data[2] & 0x0F,
			(packet->llcp.data[3] & 0xF0) >> 4,
			packet->llcp.data[3] & 0x0F);

	return 0;
}

int llcp_print_pdu(guint8 *data, guint32 data_len, struct timeval *timestamp)
{
	struct timeval msg_timestamp;
	struct sniffer_packet packet;
	gchar *direction_str, time_str[32];
	gchar *direction_color;
	int err;

	if (!timestamp)
		return -EINVAL;

	if (!timerisset(&start_timestamp))
		start_timestamp = *timestamp;

	err = llcp_decode_packet(data, data_len, &packet);
	if (err)
		goto exit;

	if (!opts.dump_symm && packet.llcp.ptype == LLCP_PTYPE_SYMM)
		return 0;

	if (packet.direction == NFC_LLCP_DIRECTION_RX) {
		direction_str = ">>";
		direction_color = COLOR_RED;
	} else {
		direction_str = "<<";
		direction_color = COLOR_GREEN;
	}

	time_str[0] = 0;

	if (opts.show_timestamp != SNIFFER_SHOW_TIMESTAMP_NONE) {
		char prefix = ' ';

		if (opts.show_timestamp == SNIFFER_SHOW_TIMESTAMP_ABS) {
			msg_timestamp = *timestamp;
		} else {
			timersub(timestamp, &start_timestamp, &msg_timestamp);
			prefix = '+';
		}

		sprintf(time_str,  "%c%lu.%06lus", prefix, msg_timestamp.tv_sec,
							msg_timestamp.tv_usec);
	}

	llcp_printf_header(direction_str, direction_color,
				" nfc%d: local:0x%02x remote:0x%02x %s",
				packet.adapter_idx, packet.llcp.local_sap,
				packet.llcp.remote_sap, time_str);

	llcp_printf_msg("%s", llcp_ptype_str[packet.llcp.ptype]);

	switch (packet.llcp.ptype) {
	case LLCP_PTYPE_AGF:
		llcp_print_agf(&packet, timestamp);
		break;

	case LLCP_PTYPE_I:
		llcp_print_i(&packet);
		break;

	case LLCP_PTYPE_RR:
	case LLCP_PTYPE_RNR:
		llcp_print_sequence(&packet);
		break;

	case LLCP_PTYPE_PAX:
	case LLCP_PTYPE_CONNECT:
	case LLCP_PTYPE_CC:
	case LLCP_PTYPE_SNL:
		llcp_check_cc(&packet);
		llcp_print_params(&packet);
		break;

	case LLCP_PTYPE_DM:
		llcp_print_dm(&packet);
		break;

	case LLCP_PTYPE_FRMR:
		llcp_print_frmr(&packet);
		break;

	default:
		sniffer_print_hexdump(stdout, packet.llcp.data,
					packet.llcp.data_len,
					LLCP_MSG_INDENT, TRUE);
		break;
	}

	printf("\n");

	err = 0;

exit:
	return err;
}

void llcp_decode_cleanup(void)
{
	timerclear(&start_timestamp);

	snep_decode_cleanup();

	if (connection_hash)
		g_hash_table_destroy(connection_hash);
}

int llcp_decode_init(void)
{
	int err;

	timerclear(&start_timestamp);

	connection_hash = g_hash_table_new_full(g_direct_hash,
						g_direct_equal, NULL,
						free_connection);

	err = snep_decode_init();

	return err;
}

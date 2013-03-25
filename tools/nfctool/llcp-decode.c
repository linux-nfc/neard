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
#include "llcp-decode.h"

#define LLCP_MIN_HEADER_SIZE 2

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

struct llcp_info {
	guint8 ptype;
	guint8 ssap;
	guint8 dsap;

	guint8 *data;
	guint32 data_len;
};

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

#define llcp_get_param_str(param_type) llcp_param_str[param_type]

#define llcp_get_param_len(param_type) llcp_param_length[param_type]

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

static struct timeval start_timestamp;

static void llcp_print_params(guint8 *params, guint32 len)
{
	guint8 major, minor;
	guint16 miux, wks, tid;
	guint32 offset = 0;
	guint32 rmng;
	guint8 *param;
	guint8 param_len;
	gchar *sn;

	while (len - offset >= 3) {
		param = params + offset;
		rmng = len - offset;

		if (param[0] < LLCP_PARAM_MIN || param[0] > LLCP_PARAM_MAX) {
			print_error("Error decoding params");
			return;
		}

		param_len = llcp_get_param_len(param[0]);

		if (param_len == 0)
			param_len = param[1];

		if (param_len != param[1] || rmng < 2u + param_len) {
			print_error("Error decoding params");
			return;
		}

		printf("    %s: ", llcp_get_param_str(param[0]));

		switch ((enum llcp_param_t)param[0]) {
		case LLCP_PARAM_VERSION:
			major = (param[2] & 0xF0) >> 4;
			minor = param[2] & 0x0F;
			printf("%d.%d", major, minor);
			break;

		case LLCP_PARAM_MIUX:
			miux = ((param[2] & 0x07) << 8) | param[3];
			printf("%d", miux);
			break;

		case LLCP_PARAM_WKS:
			wks = (param[2] << 8) | param[3];
			printf("0x%02hX", wks);
			break;

		case LLCP_PARAM_LTO:
			printf("%d", param[2]);
			break;

		case LLCP_PARAM_RW:
			printf("%d", param[2] & 0x0F);
			break;

		case LLCP_PARAM_SN:
			sn = g_strndup((gchar *)param + 2, param_len);
			printf("%s", sn);
			g_free(sn);
			break;

		case LLCP_PARAM_OPT:
			printf("0x%X", param[2] & 0x03);
			break;

		case LLCP_PARAM_SDREQ:
			tid = param[2];
			sn = g_strndup((gchar *)param + 3, param_len - 1);
			printf("TID:%d, SN:%s", tid, sn);
			g_free(sn);
			break;

		case LLCP_PARAM_SDRES:
			printf("TID:%d, SAP:%d", param[2], param[3] & 0x3F);
			break;
		}

		printf("\n");

		offset += 2 + param_len;
	}
}

static int llcp_decode_header(guint8 *data, guint32 data_len,
			      struct llcp_info *llcp)
{
	if (data_len < LLCP_MIN_HEADER_SIZE)
		return -EINVAL;

	memset(llcp, 0, sizeof(struct llcp_info));

	llcp->dsap = (data[0] & 0xFC) >> 2;
	llcp->ssap = data[1] & 0x3F;
	llcp->ptype = ((data[0] & 0x03) << 2) | ((data[1] & 0xC0) >> 6);

	if (llcp->ptype >= ARRAY_SIZE(llcp_ptype_str))
		return -EINVAL;

	llcp->data = data + 2;
	llcp->data_len = data_len - 2;

	return 0;
}

static int llcp_print_sequence(guint8 *data, guint32 data_len)
{
	guint8 send_seq;
	guint8 recv_seq;

	if (data_len < 1)
		return -EINVAL;

	send_seq = ((data[0] & 0xF0) >> 4);
	recv_seq = data[0] & 0x0F;

	printf("    N(S):%d N(R):%d\n", send_seq, recv_seq);

	return 0;
}

static int llcp_print_agf(guint8 *data, guint32 data_len, guint adapter_idx,
			  guint8 direction, struct timeval *timestamp)
{
	guint8 *pdu;
	gsize pdu_size;
	gsize size;
	guint16 offset;
	guint16 count;
	int err;

	if (data_len < 2) {
		print_error("Error parsing AGF PDU");
		return -EINVAL;
	}

	printf("\n");

	pdu = NULL;
	pdu_size = 0;
	offset = 0;
	count = 0;

	while (offset < data_len - 2) {
		size = (data[offset] << 8) | data[offset + 1];

		offset += 2;

		if (size == 0 || offset + size > data_len) {
			print_error("Error parsing AGF PDU");
			err = -EINVAL;
			goto exit;
		}

		if (size + NFC_LLCP_RAW_HEADER_SIZE > pdu_size) {
			pdu_size = size + NFC_LLCP_RAW_HEADER_SIZE;
			pdu = g_realloc(pdu, pdu_size);

			pdu[0] = adapter_idx;
			pdu[1] = direction;
		}

		memcpy(pdu + NFC_LLCP_RAW_HEADER_SIZE, data + offset, size);

		printf("-- AGF LLC PDU %02u:\n", count++);

		llcp_print_pdu(pdu, size + NFC_LLCP_RAW_HEADER_SIZE, timestamp);

		offset += size;
	}

	printf("-- End of AGF LLC PDUs\n");

	err = 0;
exit:
	g_free(pdu);

	return err;
}

static int llcp_print_dm(guint8 *data, guint32 data_len)
{
	gchar *reason;

	if (data_len != 1)
		return -EINVAL;

	switch (data[0]) {
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

	printf("    Reason: %d (%s)\n", data[0], reason);

	return 0;
}

static int llcp_print_i(guint8 *data, guint32 data_len)
{
	if (llcp_print_sequence(data, data_len))
		return -EINVAL;

	sniffer_print_hexdump(stdout, data + 1, data_len - 1, "  ", TRUE);

	return 0;
}

static int llcp_print_frmr(guint8 *data, guint32 data_len)
{
	guint8 val;

	if (data_len != 4)
		return -EINVAL;

	val = data[0];
	printf("W:%d ", (val & 0x80) >> 7);
	printf("I:%d ", (val & 0x40) >> 6);
	printf("R:%d ", (val & 0x20) >> 5);
	printf("S:%d ", (val & 0x10) >> 4);
	val = val & 0x0F;
	if (val >= ARRAY_SIZE(llcp_ptype_str))
		val = ARRAY_SIZE(llcp_ptype_str) - 1;
	printf("PTYPE:%s ", llcp_ptype_short_str[val]);
	printf("SEQ: %d ", data[1]);
	printf("V(S): %d ", (data[2] & 0xF0) >> 4);
	printf("V(R): %d ", data[2] & 0x0F);
	printf("V(SA): %d ", (data[3] & 0xF0) >> 4);
	printf("V(RA): %d\n", data[3] & 0x0F);

	return 0;
}

int llcp_print_pdu(guint8 *data, guint32 data_len, struct timeval *timestamp)
{
	struct timeval msg_timestamp;
	struct llcp_info llcp;
	guint8 adapter_idx, direction;
	gchar *direction_str;
	int err;

	if (data_len < NFC_LLCP_RAW_HEADER_SIZE || timestamp == NULL)
		return -EINVAL;

	if (!timerisset(&start_timestamp))
		start_timestamp = *timestamp;

	/* LLCP raw socket pseudo-header */
	adapter_idx = data[0];
	direction = data[1] & 0x01;

	err = llcp_decode_header(data + 2, data_len - 2, &llcp);
	if (err)
		goto exit;

	if (!opts.dump_symm && llcp.ptype == LLCP_PTYPE_SYMM)
		return 0;

	/* LLCP header */
	if (direction == NFC_LLCP_DIRECTION_RX)
		direction_str = ">>";
	else
		direction_str = "<<";

	printf("%s nfc%d: local:0x%02x remote:0x%02x",
			direction_str, adapter_idx, llcp.ssap, llcp.dsap);

	if (opts.show_timestamp != SNIFFER_SHOW_TIMESTAMP_NONE) {
		printf(" time: ");

		if (opts.show_timestamp == SNIFFER_SHOW_TIMESTAMP_ABS) {
			msg_timestamp = *timestamp;
		} else {
			timersub(timestamp, &start_timestamp, &msg_timestamp);
			printf("+");
		}

		printf("%lu.%06lu", msg_timestamp.tv_sec,
							msg_timestamp.tv_usec);
	}

	printf("\n");

	printf("  %s\n", llcp_ptype_str[llcp.ptype]);

	switch (llcp.ptype) {
	case LLCP_PTYPE_AGF:
		llcp_print_agf(llcp.data, llcp.data_len,
			       adapter_idx, direction, timestamp);
		break;

	case LLCP_PTYPE_I:
		llcp_print_i(llcp.data, llcp.data_len);
		break;

	case LLCP_PTYPE_RR:
	case LLCP_PTYPE_RNR:
		llcp_print_sequence(llcp.data, llcp.data_len);
		break;

	case LLCP_PTYPE_PAX:
	case LLCP_PTYPE_CONNECT:
	case LLCP_PTYPE_CC:
	case LLCP_PTYPE_SNL:
		llcp_print_params(llcp.data, llcp.data_len);
		break;

	case LLCP_PTYPE_DM:
		llcp_print_dm(llcp.data, llcp.data_len);
		break;

	case LLCP_PTYPE_FRMR:
		llcp_print_frmr(llcp.data, llcp.data_len);
		break;

	default:
		sniffer_print_hexdump(stdout, llcp.data, llcp.data_len, "  ",
				      TRUE);
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
}

int llcp_decode_init(void)
{
	timerclear(&start_timestamp);

	return 0;
}

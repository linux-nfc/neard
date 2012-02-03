/*
 *
 *  neard - Near Field Communication manager
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/socket.h>
#include <linux/nfc.h>

#include <near/plugin.h>
#include <near/log.h>
#include <near/types.h>
#include <near/adapter.h>
#include <near/target.h>
#include <near/tag.h>
#include <near/ndef.h>
#include <near/tlv.h>

#include "p2p.h"

/* Request codes */
#define SNEP_REQ_CONTINUE 0x00
#define SNEP_REQ_GET      0x01
#define SNEP_REQ_PUT      0x02
#define SNEP_REQ_REJECT   0x7f

/* Response codes */
#define SNEP_RESP_CONTINUE  0x80
#define SNEP_RESP_SUCCESS   0x81
#define SNEP_RESP_NOT_FOUND 0x80
#define SNEP_RESP_EXCESS    0x80
#define SNEP_RESP_BAD_REQ   0x80
#define SNEP_RESP_NOT_IMPL  0x80
#define SNEP_RESP_VERSION   0x80
#define SNEP_RESP_REJECT    0x80

struct p2p_snep_data {
	uint8_t *nfc_data;
	uint32_t nfc_data_length;
	uint32_t nfc_data_current_length;
	uint8_t *nfc_data_ptr;
};

struct p2p_snep_req_frame {
	uint8_t version;
	uint8_t request;
	uint32_t length;
	uint8_t ndef[];
} __attribute__((packed));

struct p2p_snep_resp_frame {
	uint8_t version;
	uint8_t response;
	uint32_t length;
	uint8_t info[];
} __attribute__((packed));

static struct p2p_snep_data snep_data;

static void snep_response_noinfo(int client_fd, uint8_t response)
{
	struct p2p_snep_resp_frame resp;

	DBG("Response 0x%x", response);

	resp.response = response;
	resp.length = 0;

	send(client_fd, &resp, sizeof(resp), 0);
}

static void snep_read_ndef(int client_fd,
		uint32_t adapter_idx, uint32_t target_idx,
		near_tag_io_cb cb, int ndef_length, near_bool_t allocate)
{
	int bytes_recv, remaining_bytes;

	DBG("");

	if (allocate == TRUE) {
		g_free(snep_data.nfc_data);

		snep_data.nfc_data = g_try_malloc0(ndef_length + TLV_SIZE);
		if (snep_data.nfc_data == NULL)
			return;

		snep_data.nfc_data[0] = TLV_NDEF;
		snep_data.nfc_data[1] = ndef_length;

		snep_data.nfc_data_length = ndef_length + TLV_SIZE;
		snep_data.nfc_data_current_length = TLV_SIZE;
		snep_data.nfc_data_ptr = snep_data.nfc_data + TLV_SIZE;
	}

	remaining_bytes = snep_data.nfc_data_length - snep_data.nfc_data_current_length;
	bytes_recv = recv(client_fd, snep_data.nfc_data_ptr, remaining_bytes, 0);
	if (bytes_recv < 0) {
		near_error("Could not read SNEP NDEF buffer %d", bytes_recv);
		return;
	}

	DBG("Received %d bytes", bytes_recv);

	snep_data.nfc_data_current_length += bytes_recv;

	if (snep_data.nfc_data_length == snep_data.nfc_data_current_length) {
		struct near_tag *tag;
		size_t tag_length;
		uint8_t *nfc_data;

		snep_data.nfc_data_current_length = 0;
		snep_response_noinfo(client_fd, SNEP_RESP_SUCCESS);
		tag = near_target_add_tag(adapter_idx, target_idx,
					snep_data.nfc_data_length);
		if (tag == NULL) {
			g_free(snep_data.nfc_data);
			return;
		}

		nfc_data = near_tag_get_data(tag, &tag_length);
		memcpy(nfc_data, snep_data.nfc_data, tag_length);

		near_tlv_parse(tag, cb, nfc_data, tag_length);
		g_free(snep_data.nfc_data);
	} else {
		snep_response_noinfo(client_fd, SNEP_RESP_CONTINUE);
	}
}

static int snep_read(int client_fd, uint32_t adapter_idx, uint32_t target_idx,
		near_tag_io_cb cb)
{
	struct p2p_snep_req_frame frame;
	int bytes_recv;
	uint32_t ndef_length;

	DBG("");

	/* If current length is not 0, we're waiting for a fragment */
	if (snep_data.nfc_data_current_length > 0) {
		snep_read_ndef(client_fd, adapter_idx, target_idx, cb,
								0, FALSE);
		return 0;
	}

	bytes_recv = recv(client_fd, &frame, sizeof(frame), 0);
	if (bytes_recv < 0) {
		near_error("Could not read SNEP frame %d", bytes_recv);
		return bytes_recv;
	}

	DBG("Request 0x%x", frame.request);

	switch (frame.request) {
	case SNEP_REQ_CONTINUE:
	case SNEP_REQ_GET:
		near_error("Unsupported SNEP request code");
		snep_response_noinfo(client_fd, SNEP_RESP_NOT_IMPL);
		return -EOPNOTSUPP;
	case SNEP_REQ_PUT:
		ndef_length = GINT_FROM_BE(frame.length);
		snep_read_ndef(client_fd, adapter_idx, target_idx, cb,
				ndef_length, TRUE);
		break;
	}

	return 0;
}

struct near_p2p_driver snep_driver = {
	.name = "SNEP",
	.service_name = "urn:nfc:sn:snep",
	.read = snep_read,
};

int snep_init(void)
{
	return near_p2p_register(&snep_driver);
}

void snep_exit(void)
{
	near_p2p_unregister(&snep_driver);
}

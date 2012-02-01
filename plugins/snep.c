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

#define SNEP_SN "urn:nfc:sn:snep"

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

struct p2p_snep_channel {
	near_tag_io_cb cb;
	uint32_t adapter_idx;
	uint32_t target_idx;
	int fd;
	guint watch;
	GIOChannel *channel;
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

static struct p2p_snep_channel snep_server;

static void snep_response_noinfo(int client_fd, uint8_t response)
{
	struct p2p_snep_resp_frame resp;

	DBG("Response 0x%x", response);

	resp.response = response;
	resp.length = 0;

	send(client_fd, &resp, sizeof(resp), 0);
}

static void snep_read_ndef(int client_fd, int ndef_length,
					near_bool_t allocate)
{
	int bytes_recv, remaining_bytes;

	DBG("");

	if (allocate == TRUE) {
		g_free(snep_server.nfc_data);

		snep_server.nfc_data = g_try_malloc0(ndef_length + TLV_SIZE);
		if (snep_server.nfc_data == NULL)
			return;

		snep_server.nfc_data[0] = TLV_NDEF;
		snep_server.nfc_data[1] = ndef_length;

		snep_server.nfc_data_length = ndef_length + TLV_SIZE;
		snep_server.nfc_data_current_length = TLV_SIZE;
		snep_server.nfc_data_ptr = snep_server.nfc_data + TLV_SIZE;
	}

	remaining_bytes = snep_server.nfc_data_length - snep_server.nfc_data_current_length;
	bytes_recv = recv(client_fd, snep_server.nfc_data_ptr, remaining_bytes, 0);
	if (bytes_recv < 0) {
		near_error("Could not read SNEP NDEF buffer %d", bytes_recv);
		return;
	}

	DBG("Received %d bytes", bytes_recv);

	snep_server.nfc_data_current_length += bytes_recv;

	if (snep_server.nfc_data_length == snep_server.nfc_data_current_length) {
		struct near_tag *tag;
		size_t tag_length;
		uint8_t *nfc_data;

		snep_server.nfc_data_current_length = 0;
		snep_response_noinfo(client_fd, SNEP_RESP_SUCCESS);
		tag = near_target_add_tag(snep_server.adapter_idx,
					snep_server.target_idx,
					snep_server.nfc_data_length);
		if (tag == NULL) {
			g_free(snep_server.nfc_data);
			return;
		}

		nfc_data = near_tag_get_data(tag, &tag_length);
		memcpy(nfc_data, snep_server.nfc_data, tag_length);

		near_tlv_parse(tag, snep_server.cb, nfc_data, tag_length);
		g_free(snep_server.nfc_data);
	} else {
		snep_response_noinfo(client_fd, SNEP_RESP_CONTINUE);
	}
}

static void snep_read(int client_fd)
{
	struct p2p_snep_req_frame frame;
	int bytes_recv;
	uint32_t ndef_length;

	DBG("");

	/* If current length is not 0, we're waiting for a fragment */
	if (snep_server.nfc_data_current_length > 0) {
		snep_read_ndef(client_fd, 0, FALSE);
		return;
	}

	bytes_recv = recv(client_fd, &frame, sizeof(frame), 0);
	if (bytes_recv < 0) {
		near_error("Could not read SNEP frame %d", bytes_recv);
		return;
	}

	DBG("Request 0x%x", frame.request);

	switch (frame.request) {
	case SNEP_REQ_CONTINUE:
	case SNEP_REQ_GET:
		near_error("Unsupported SNEP request code");
		snep_response_noinfo(client_fd, SNEP_RESP_NOT_IMPL);
		break;
	case SNEP_REQ_PUT:
		ndef_length = GINT_FROM_BE(frame.length);
		snep_read_ndef(client_fd, ndef_length, TRUE);
	}
}

static gboolean snep_listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct sockaddr_nfc_llcp client_addr;
	int server_fd, client_fd;
	socklen_t client_addr_len;

	DBG("condition 0x%x", condition);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		if (snep_server.watch > 0)
			g_source_remove(snep_server.watch);
		snep_server.watch = 0;

		near_error("Error with SNEP server channel");

		return FALSE;
	}

	if (condition & G_IO_IN) {
		server_fd = g_io_channel_unix_get_fd(channel);

		client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
							&client_addr_len);
		if (client_fd < 0) {
			near_error("SNEP accept failed %d", client_fd);

			close(server_fd);
			return FALSE;
		}

		DBG("client dsap %d ssap %d",
			client_addr.dsap, client_addr.ssap);

		snep_read(client_fd);

		close(client_fd);

		return FALSE;
	}

	return FALSE;
}

int snep_bind(uint32_t adapter_idx, uint32_t target_idx,
					near_tag_io_cb cb)
{
	int err;
	struct sockaddr_nfc_llcp addr;

	DBG("");

	snep_server.adapter_idx = adapter_idx;
	snep_server.target_idx = target_idx;
	snep_server.cb = cb;
	snep_server.fd = socket(AF_NFC, SOCK_STREAM, NFC_SOCKPROTO_LLCP);
	if (snep_server.fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(struct sockaddr_nfc_llcp));
	addr.sa_family = AF_NFC;
	addr.dev_idx = adapter_idx;
	addr.nfc_protocol = NFC_PROTO_NFC_DEP;
	addr.service_name_len = strlen(SNEP_SN);
	strcpy(addr.service_name, SNEP_SN);

	err = bind(snep_server.fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_nfc_llcp));
	if (err < 0) {
		near_error("SNEP bind failed %d", err);

		close(snep_server.fd);
		return err;
	}

	err = listen(snep_server.fd, 10);
	if (err < 0) {
		near_error("SNEP listen failed %d", err);

		close(snep_server.fd);
		return err;
	}

	snep_server.channel = g_io_channel_unix_new(snep_server.fd);
	g_io_channel_set_close_on_unref(snep_server.channel, TRUE);

	snep_server.watch = g_io_add_watch(snep_server.channel,
				G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
				snep_listener_event,
				(gpointer) &snep_server.channel);

	return 0;
}

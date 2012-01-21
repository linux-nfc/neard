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

#define NPP_SN "com.android.npp"

struct p2p_npp_channel {
	near_tag_io_cb cb;
	uint32_t adapter_idx;
	uint32_t target_idx;
	int fd;
	guint watch;
	GIOChannel *channel;
};

struct p2p_npp_ndef_entry {
	uint8_t action;
	uint32_t ndef_length;
	uint8_t ndef[];
} __attribute__((packed));

struct p2p_npp_frame {
	uint8_t version;
	uint32_t n_ndef;
	struct p2p_npp_ndef_entry ndefs[];
} __attribute__((packed));

static struct p2p_npp_channel npp_server;

static void npp_read_ndef(int client_fd)
{
	struct near_tag *tag;
	struct p2p_npp_frame frame;
	struct p2p_npp_ndef_entry entry;
	int bytes_recv, n_ndef, i, ndef_length, total_ndef_length;
	size_t tag_length;
	uint8_t *ndefs, *nfc_data, *current_ndef;

	ndefs = NULL;
	total_ndef_length = 0;

	bytes_recv = recv(client_fd, &frame, sizeof(frame), 0);
	if (bytes_recv < 0) {
		near_error("Could not read NPP frame %d", bytes_recv);
		return;
	}

	n_ndef = GINT_FROM_BE(frame.n_ndef);

	DBG("version %d %d NDEFs", frame.version, n_ndef);

	for (i = 0; i < n_ndef; i++) {
		bytes_recv = recv(client_fd, &entry, sizeof(entry), 0);
		if (bytes_recv < 0) {
			near_error("Could not read NPP NDEF entry %d",
								bytes_recv);
			break;
		}

		ndef_length = GINT_FROM_BE(entry.ndef_length);
		total_ndef_length += ndef_length + TLV_SIZE;
		DBG("NDEF %d length %d", i, ndef_length);

		ndefs = g_try_realloc(ndefs, total_ndef_length);
		if (ndefs == NULL) {
			near_error("Could not allocate NDEF buffer %d",
								bytes_recv);
			break;
		}

		current_ndef = ndefs + total_ndef_length
					- (ndef_length + TLV_SIZE);
		current_ndef[0] = TLV_NDEF;
		current_ndef[1] = ndef_length;

		bytes_recv = recv(client_fd, current_ndef + TLV_SIZE,
					ndef_length, 0);
		if (bytes_recv < 0) {
			near_error("Could not read NDEF entry %d",
							bytes_recv);
			break;
		}
	}

	if (total_ndef_length == 0)
		return;

	DBG("Total NDEF length %d", total_ndef_length);

	tag = near_target_add_tag(npp_server.adapter_idx,
					npp_server.target_idx,
					total_ndef_length);
	if (tag == NULL) {
		g_free(ndefs);
		return;
	}

	for (i = 0; i < total_ndef_length; i++)
		DBG("NDEF[%d] 0x%x", i, ndefs[i]);

	nfc_data = near_tag_get_data(tag, &tag_length);
	memcpy(nfc_data, ndefs, total_ndef_length);

	near_tlv_parse(tag, npp_server.cb, nfc_data, total_ndef_length);

	g_free(ndefs);
}

static gboolean npp_listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct sockaddr_nfc_llcp client_addr;
	int server_fd, client_fd;
	socklen_t client_addr_len;

	DBG("condition 0x%x", condition);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		DBG("ERROR");
	}

	if (condition & G_IO_IN) {
		server_fd = g_io_channel_unix_get_fd(channel);

		client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
		if (client_fd < 0) {
			DBG("accept failed %d", client_fd);

			close(server_fd);
			return FALSE;
		}

		DBG("client dsap %d ssap %d",
			client_addr.dsap, client_addr.ssap);

		npp_read_ndef(client_fd);

		close(client_fd);

		return FALSE;
	}

	return FALSE;
}

int npp_bind(uint32_t adapter_idx, uint32_t target_idx,
					near_tag_io_cb cb)
{
	int err;
	struct sockaddr_nfc_llcp addr;

	npp_server.adapter_idx = adapter_idx;
	npp_server.target_idx = target_idx;
	npp_server.cb = cb;
	npp_server.fd = socket(AF_NFC, SOCK_STREAM, NFC_SOCKPROTO_LLCP);
	if (npp_server.fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(struct sockaddr_nfc_llcp));
	addr.sa_family = AF_NFC;
	addr.dev_idx = adapter_idx;
	addr.nfc_protocol = NFC_PROTO_NFC_DEP;
	addr.service_name_len = strlen(NPP_SN);
	strcpy(addr.service_name, NPP_SN);

	err = bind(npp_server.fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_nfc_llcp));
	if (err < 0) {
		DBG("bind failed %d", err);

		close(npp_server.fd);
		return err;
	}

	err = listen(npp_server.fd, 10);
	if (err < 0) {
		DBG("listen failed %d", err);

		close(npp_server.fd);
		return err;
	}

	npp_server.channel = g_io_channel_unix_new(npp_server.fd);
	g_io_channel_set_close_on_unref(npp_server.channel, TRUE);

	npp_server.watch = g_io_add_watch(npp_server.channel,
				G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
				npp_listener_event,
				(gpointer) &npp_server.channel);

	return 0;
}

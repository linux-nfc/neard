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
#include <near/device.h>
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
#define SNEP_RESP_NOT_FOUND 0xc0
#define SNEP_RESP_EXCESS    0xc1
#define SNEP_RESP_BAD_REQ   0xc2
#define SNEP_RESP_NOT_IMPL  0xe0
#define SNEP_RESP_VERSION   0xe1
#define SNEP_RESP_REJECT    0xff

struct p2p_snep_data {
	uint8_t *nfc_data;
	uint32_t nfc_data_length;
	uint32_t nfc_data_current_length;
	uint8_t *nfc_data_ptr;
	uint32_t adapter_idx;
	uint32_t target_idx;
	near_tag_io_cb cb;
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

static GHashTable *snep_client_hash = NULL;

static void free_snep_client(gpointer data)
{
	struct p2p_snep_data *snep_data = data;

	g_free(snep_data->nfc_data);
	g_free(snep_data);
}

static void snep_response_noinfo(int client_fd, uint8_t response)
{
	struct p2p_snep_resp_frame resp;

	DBG("Response 0x%x", response);

	resp.response = response;
	resp.length = 0;

	send(client_fd, &resp, sizeof(resp), 0);
}

static void snep_close(int client_fd, int err)
{
	struct p2p_snep_data *snep_data;

	DBG("");

	snep_data = g_hash_table_lookup(snep_client_hash,
					GINT_TO_POINTER(client_fd));
	if (snep_data == NULL)
		return;

	snep_data->cb(snep_data->adapter_idx, snep_data->target_idx, err);

	g_hash_table_remove(snep_client_hash, GINT_TO_POINTER(client_fd));
}

static near_bool_t snep_read_ndef(int client_fd,
					struct p2p_snep_data *snep_data)
{
	int bytes_recv, remaining_bytes;
	struct near_device *device;
	GList *records;

	DBG("");

	remaining_bytes = snep_data->nfc_data_length -
				snep_data->nfc_data_current_length;

	DBG("Remaining bytes %d", remaining_bytes);

	bytes_recv = recv(client_fd, snep_data->nfc_data_ptr, remaining_bytes,
								MSG_DONTWAIT);
	if (bytes_recv < 0) {
		near_error("%d %s", bytes_recv, strerror(errno));

		/* Some more data should show up */
		if (errno == EAGAIN)
			return TRUE;

		goto out;
	}

	DBG("Received %d bytes", bytes_recv);

	snep_data->nfc_data_current_length += bytes_recv;
	snep_data->nfc_data_ptr += bytes_recv;

	if (snep_data->nfc_data_length != snep_data->nfc_data_current_length) {
		snep_response_noinfo(client_fd, SNEP_RESP_CONTINUE);

		DBG("Continue");

		return TRUE;
	}

	snep_response_noinfo(client_fd, SNEP_RESP_SUCCESS);
	if (near_device_add_data(snep_data->adapter_idx, snep_data->target_idx,
					snep_data->nfc_data,
					snep_data->nfc_data_length) < 0)
		goto out;

	device = near_device_get_device(snep_data->adapter_idx,
						snep_data->target_idx);
	if (device == NULL)
		goto out;

	records = near_tlv_parse(snep_data->nfc_data,
				snep_data->nfc_data_length);
	near_device_add_records(device, records, snep_data->cb, 0);

out:
	g_hash_table_remove(snep_client_hash, GINT_TO_POINTER(client_fd));

	return FALSE;
}

static near_bool_t snep_read(int client_fd,
				uint32_t adapter_idx, uint32_t target_idx,
				near_tag_io_cb cb)
{
	struct p2p_snep_data *snep_data;
	struct p2p_snep_req_frame frame;
	int bytes_recv;
	uint32_t ndef_length;

	DBG("");

	snep_data = g_hash_table_lookup(snep_client_hash,
					GINT_TO_POINTER(client_fd));

	/*
	 * We already got something from this client, we should try
	 * to continue reading.
	 */
	if (snep_data != NULL)
		return snep_read_ndef(client_fd, snep_data);

	/* TODO Try with PEEK */
	bytes_recv = recv(client_fd, &frame, sizeof(frame), 0);
	if (bytes_recv < 0) {
		near_error("Could not read SNEP frame %d", bytes_recv);
		return bytes_recv;
	}

	ndef_length = GINT_FROM_BE(frame.length);

	DBG("Allocating SNEP data %d", ndef_length);

	snep_data = g_try_malloc0(sizeof(struct p2p_snep_data));
	if (snep_data == NULL)
		return FALSE;

	snep_data->nfc_data = g_try_malloc0(ndef_length + TLV_SIZE);
	if (snep_data->nfc_data == NULL)
		return FALSE;

	snep_data->nfc_data[0] = TLV_NDEF;
	snep_data->nfc_data[1] = ndef_length;
	snep_data->nfc_data_length = ndef_length + TLV_SIZE;
	snep_data->nfc_data_current_length = TLV_SIZE;
	snep_data->nfc_data_ptr = snep_data->nfc_data + TLV_SIZE;
	snep_data->adapter_idx = adapter_idx;
	snep_data->target_idx = target_idx;
	snep_data->cb = cb;

	g_hash_table_insert(snep_client_hash,
					GINT_TO_POINTER(client_fd), snep_data);

	DBG("Request 0x%x", frame.request);

	switch (frame.request) {
	case SNEP_REQ_CONTINUE:
	case SNEP_REQ_GET:
		near_error("Unsupported SNEP request code");
		snep_response_noinfo(client_fd, SNEP_RESP_NOT_IMPL);
		return FALSE;
	case SNEP_REQ_PUT:
		return snep_read_ndef(client_fd, snep_data);
		break;
	}

	return FALSE;
}

struct near_p2p_driver snep_driver = {
	.name = "SNEP",
	.service_name = "urn:nfc:sn:snep",
	.read = snep_read,
	.close = snep_close,
};

int snep_init(void)
{
	snep_client_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_snep_client);

	return near_p2p_register(&snep_driver);
}

void snep_exit(void)
{
	near_p2p_unregister(&snep_driver);

	g_hash_table_destroy(snep_client_hash);
	snep_client_hash = NULL;
}

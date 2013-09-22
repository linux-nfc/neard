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
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/socket.h>

#include <near/nfc_copy.h>
#include <near/plugin.h>
#include <near/log.h>
#include <near/types.h>
#include <near/adapter.h>
#include <near/device.h>
#include <near/ndef.h>
#include <near/tlv.h>

#include "p2p.h"

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

#define NPP_MAJOR_VERSION (0x0 & 0xf)
#define NPP_MINOR_VERSION 0x1
#define NPP_VERSION ((NPP_MAJOR_VERSION << 4) | NPP_MINOR_VERSION)

#define NPP_DEFAULT_ACTION 0x1

static bool npp_read(int client_fd,
			uint32_t adapter_idx, uint32_t target_idx,
			near_tag_io_cb cb, gpointer data)
{
	struct near_device *device;
	struct p2p_npp_frame frame;
	struct p2p_npp_ndef_entry entry;
	int bytes_recv, n_ndef, i, ndef_length, total_ndef_length, err;
	uint8_t *ndefs, *new_ndefs, *current_ndef;
	GList *records;

	ndefs = NULL;
	total_ndef_length = 0;
	err = 0;

	bytes_recv = recv(client_fd, &frame, sizeof(frame), 0);
	if (bytes_recv < 0) {
		near_error("Could not read NPP frame %d", bytes_recv);
		return bytes_recv;
	}

	n_ndef = GINT_FROM_BE(frame.n_ndef);

	DBG("version %d %d NDEFs", frame.version, n_ndef);

	if (frame.version != NPP_VERSION) {
		near_error("Invalid NPP version 0x%x", frame.version);
		return false;
	}

	for (i = 0; i < n_ndef; i++) {
		bytes_recv = recv(client_fd, &entry, sizeof(entry), 0);
		if (bytes_recv < 0) {
			near_error("Could not read NPP NDEF entry %d",
								bytes_recv);
			err = bytes_recv;
			break;
		}

		ndef_length = GINT_FROM_BE(entry.ndef_length);
		total_ndef_length += ndef_length + TLV_SIZE;
		DBG("NDEF %d length %d", i, ndef_length);

		new_ndefs = g_try_realloc(ndefs, total_ndef_length);
		if (!new_ndefs) {
			near_error("Could not allocate NDEF buffer %d",
								bytes_recv);
			err = -ENOMEM;
			break;
		}
		ndefs = new_ndefs;

		current_ndef = ndefs + total_ndef_length
					- (ndef_length + TLV_SIZE);
		current_ndef[0] = TLV_NDEF;
		current_ndef[1] = ndef_length;

		bytes_recv = recv(client_fd, current_ndef + TLV_SIZE,
					ndef_length, 0);
		if (bytes_recv < 0) {
			near_error("Could not read NDEF entry %d",
							bytes_recv);
			err = bytes_recv;
			break;
		}
	}

	if (total_ndef_length == 0)
		return err;

	DBG("Total NDEF length %d", total_ndef_length);

	err = near_device_add_data(adapter_idx, target_idx,
					ndefs, total_ndef_length);
	if (err < 0)
		return false;

	device = near_device_get_device(adapter_idx, target_idx);
	if (!device) {
		g_free(ndefs);
		return -ENOMEM;
	}

	for (i = 0; i < total_ndef_length; i++)
		DBG("NDEF[%d] 0x%x", i, ndefs[i]);

	records = near_tlv_parse(ndefs, total_ndef_length);
	near_device_add_records(device, records, cb, 0);

	g_free(ndefs);

	return false;
}

static int npp_push(int fd, uint32_t adapter_idx, uint32_t target_idx,
			struct near_ndef_message *ndef,
			near_device_io_cb cb,
			gpointer data)
{
	struct p2p_npp_frame *frame;
	struct p2p_npp_ndef_entry *entry;
	size_t frame_length;
	int err;

	DBG("");

	frame_length = sizeof(struct p2p_npp_frame) +
					sizeof(struct p2p_npp_ndef_entry) +
					ndef->length;
	frame = g_try_malloc0(frame_length);
	if (!frame)
		return -ENOMEM;

	entry = &frame->ndefs[0];

	frame->version = NPP_VERSION;
	frame->n_ndef = GINT_TO_BE(1);

	entry->action = NPP_DEFAULT_ACTION;
	entry->ndef_length = GINT_TO_BE(ndef->length);
	memcpy(entry->ndef, ndef->data, ndef->length);

	DBG("Sending %zd bytes", frame_length);

	err = send(fd, frame, frame_length, MSG_DONTWAIT);

	g_free(frame);

	cb(adapter_idx, target_idx, err < 0 ? err : 0);

	close(fd);

	return err;
}

struct near_p2p_driver npp_driver = {
	.name = "NPP",
	.service_name = NEAR_DEVICE_SN_NPP,
	.fallback_service_name = NULL,
	.sock_type = SOCK_STREAM,
	.read = npp_read,
	.push = npp_push,
};

int npp_init(void)
{
	return near_p2p_register(&npp_driver);
}

void npp_exit(void)
{
	near_p2p_unregister(&npp_driver);
}

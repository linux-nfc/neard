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

static near_bool_t npp_read(int client_fd,
			uint32_t adapter_idx, uint32_t target_idx,
			near_tag_io_cb cb)
{
	struct near_device *device;
	struct p2p_npp_frame frame;
	struct p2p_npp_ndef_entry entry;
	int bytes_recv, n_ndef, i, ndef_length, total_ndef_length, err;
	uint8_t *ndefs, *current_ndef;
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

		ndefs = g_try_realloc(ndefs, total_ndef_length);
		if (ndefs == NULL) {
			near_error("Could not allocate NDEF buffer %d",
								bytes_recv);
			err = -ENOMEM;
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
			err = bytes_recv;
			break;
		}
	}

	if (total_ndef_length == 0)
		return err;

	DBG("Total NDEF length %d", total_ndef_length);

	err = near_tag_add_data(adapter_idx, target_idx,
					ndefs, total_ndef_length);
	if (err < 0)
		return FALSE;

	device = near_device_get_device(adapter_idx, target_idx);
	if (device == NULL) {
		g_free(ndefs);
		return -ENOMEM;
	}

	for (i = 0; i < total_ndef_length; i++)
		DBG("NDEF[%d] 0x%x", i, ndefs[i]);

	records = near_tlv_parse(ndefs, total_ndef_length);
	near_device_add_records(device, records, cb, 0);

	g_free(ndefs);

	return FALSE;
}

struct near_p2p_driver npp_driver = {
	.name = "NPP",
	.service_name = "com.android.npp",
	.read = npp_read,
};

int npp_init(void)
{
	return near_p2p_register(&npp_driver);
}

void npp_exit(void)
{
	near_p2p_unregister(&npp_driver);
}

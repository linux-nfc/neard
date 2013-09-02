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
#include <near/snep.h>

#include "p2p.h"

/*
 * This is the Default server REQ PUT function.
 * On REQ PUT, server should store the associated ndef as a record.
 *
 * TODO: check the nfc_data (simple NDEF or complete frame ?)
 *  */
static bool snep_default_server_req_put(int client_fd, void *data)
{
	struct p2p_snep_data *snep_data = data;
	struct near_device *device;
	GList *records;

	DBG("");

	/* The request is ok, so we notify the client */
	near_snep_core_response_noinfo(client_fd, NEAR_SNEP_RESP_SUCCESS);

	/* On PUT request, we add the data */
	if (near_device_add_data(snep_data->adapter_idx,
			snep_data->target_idx,
			snep_data->nfc_data,
			snep_data->nfc_data_length) < 0)
		return false;

	device = near_device_get_device(snep_data->adapter_idx,
			snep_data->target_idx);
	if (!device)
		return false;

	records = near_ndef_parse_msg(snep_data->nfc_data,
				snep_data->nfc_data_length, NULL);

	near_device_add_records(device, records, snep_data->cb, 0);

	snep_data->nfc_data_length = 0;
	snep_data->nfc_data = NULL;

	return true;
}

/*
 * This is the Default server REQ GET function.
 * On REQ GET, server should return NEAR_SNEP_RESP_NOT_IMPL.
 *
 * !!! We check if the incoming NDEF looks like a handover frame,
 * because of Android 4.1.1 ...
 *  */
static bool snep_default_server_req_get(int client_fd, void *data)
{
	struct p2p_snep_data *snep_data = data;

	DBG("");

	/*
	 * Check if this is a handover request or not ...
	 * snep_data->nfc_data points to the acceptable length field (4 bytes)
	 * and we check the 3 byte in the NDEF message
	 * */

	if (*(snep_data->nfc_data + NEAR_SNEP_REQ_ANDROID) != 'H') {
		near_snep_core_response_noinfo(client_fd, NEAR_SNEP_RESP_NOT_IMPL);
	} else {
		near_snep_core_parse_handover_record(client_fd, snep_data->nfc_data +
						NEAR_SNEP_ACC_LENGTH_SIZE,
						snep_data->nfc_data_length -
						NEAR_SNEP_ACC_LENGTH_SIZE);
	}

	return true;
}

/* This function is a wrapper to push post processing read functions */
static bool snep_default_read(int client_fd, uint32_t adapter_idx,
							uint32_t target_idx,
							near_tag_io_cb cb,
							gpointer data)
{
	DBG("");

	return near_snep_core_read(client_fd, adapter_idx, target_idx, cb,
						snep_default_server_req_get,
						snep_default_server_req_put,
						data);

}

struct near_p2p_driver snep_driver = {
	.name = "SNEP",
	.service_name = NEAR_DEVICE_SN_SNEP,
	.fallback_service_name = NEAR_DEVICE_SN_NPP,
	.sock_type = SOCK_STREAM,
	.read = snep_default_read,
	.push = near_snep_core_push,
	.close = near_snep_core_close,
};

int snep_init(void)
{
	return near_p2p_register(&snep_driver);
}

void snep_exit(void)
{
	near_p2p_unregister(&snep_driver);
}

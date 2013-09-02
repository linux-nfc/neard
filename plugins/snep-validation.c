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

/* Would store incoming ndefs per client */
static GHashTable *snep_validation_hash = NULL;

/* Callback: free validation data */
static void free_snep_validation_client(gpointer data)
{
	GList *old_ndefs = data;

	if (old_ndefs)
		g_list_free(old_ndefs);
}

/* Validation Server REQ_PUT function
 * The validation server shall accept PUT and GET requests. A PUT request shall
 * cause the server to store the ndef message transmitted with the request.
 * */
static bool snep_validation_server_req_put(int client_fd, void *data)
{
	struct p2p_snep_data *snep_data = data;
	GList *records;
	struct near_ndef_record *recd;
	GList *incoming_ndefs;

	DBG("");

	if (!snep_data->nfc_data)
		goto error;

	/*
	 * We received a ndef, parse it, check if there's only
	 * 1 record (a mime type !) with an ID
	 */
	records = near_ndef_parse_msg(snep_data->nfc_data,
					snep_data->nfc_data_length, NULL);

	if (g_list_length(records) != 1) {
		DBG("records number mismatch");
		goto error;
	}

	recd = records->data;

	if (!recd) {
		g_list_free(records);
		goto error;
	}

	/* Save the record but look if there are some incoming ndef stored */
	incoming_ndefs = g_hash_table_lookup(snep_validation_hash,
						GINT_TO_POINTER(client_fd));

	incoming_ndefs = g_list_append(incoming_ndefs, recd);

	/* remove existing one silently */
	g_hash_table_steal(snep_validation_hash, GINT_TO_POINTER(client_fd));
	/* push the new one */
	g_hash_table_insert(snep_validation_hash, GINT_TO_POINTER(client_fd),
							incoming_ndefs);


	near_snep_core_response_noinfo(client_fd, NEAR_SNEP_RESP_SUCCESS);

	return true;

error:
	near_snep_core_response_noinfo(client_fd, NEAR_SNEP_RESP_REJECT);

	return true;
}

/*
 * Validation Server REQ_GET function
 * The validation server shall accept PUT and GET requests. A GET request shall
 * cause the server to return a previously stored NDEF message of the same NDEF
 * message type and identifier as transmitted with the request.
 * */
static bool snep_validation_server_req_get(int client_fd, void *data)
{
	struct p2p_snep_data *snep_data = data;
	struct near_ndef_record *recd, *rec_store;
	uint32_t acceptable_length;
	GList *records;
	GList *iter;
	GList *incoming_ndefs;

	DBG("");

	/*
	 * We received a ndef, parse it, check if there's only
	 * 1 record (a mime type !) with an ID
	 */
	records = near_ndef_parse_msg(snep_data->nfc_data +
			NEAR_SNEP_ACC_LENGTH_SIZE,
			snep_data->nfc_data_length - NEAR_SNEP_ACC_LENGTH_SIZE,
			NULL);

	if (g_list_length(records) != 1) {
		DBG("records number mismatch");
		goto error;
	}

	recd = records->data;
	if (!recd) {
		g_list_free(records);
		goto error;
	}

	/* check if the acceptable length is higher than the data_len
	 * otherwise returns a NEAR_SNEP_RESP_EXCESS
	 */
	acceptable_length = near_get_be32(snep_data->nfc_data);

	/* Look if there are some incoming ndef stored */
	incoming_ndefs = g_hash_table_lookup(snep_validation_hash,
						GINT_TO_POINTER(client_fd));

	if (!incoming_ndefs)
		goto done;

	/* Now, loop to find the the associated record */
	for (iter = incoming_ndefs; iter; iter = iter->next) {

		rec_store = iter->data;
		/* Same mime type and same id ?*/

		if (!near_ndef_record_cmp_id(recd, rec_store))
			continue;

		if (!near_ndef_record_cmp_mime(recd, rec_store))
			continue;

		/* Found a record, check the length */
		if (acceptable_length >= near_ndef_data_length(rec_store)) {
			near_snep_core_response_with_info(client_fd,
					NEAR_SNEP_RESP_SUCCESS,
					near_ndef_data_ptr(rec_store),
					near_ndef_data_length(rec_store));

			incoming_ndefs = g_list_remove(incoming_ndefs,
								iter->data);
			/* remove existing one silently */
			g_hash_table_steal(snep_validation_hash,
						GINT_TO_POINTER(client_fd));
			/* push the new one */
			g_hash_table_insert(snep_validation_hash,
						GINT_TO_POINTER(client_fd),
							incoming_ndefs);

		} else
			near_snep_core_response_noinfo(client_fd, NEAR_SNEP_RESP_EXCESS);

		return true;
	}

done:
	/* If not found */
	near_snep_core_response_noinfo(client_fd, NEAR_SNEP_RESP_NOT_FOUND);
	return true;

error:
	 /* Not found */
	near_snep_core_response_noinfo(client_fd, NEAR_SNEP_RESP_REJECT);
	return false;
}

/* This function is a wrapper to push post processing read functions */
static bool snep_validation_read(int client_fd, uint32_t adapter_idx,
							uint32_t target_idx,
							near_tag_io_cb cb,
							gpointer data)
{
	DBG("");

	return near_snep_core_read(client_fd, adapter_idx, target_idx, cb,
						snep_validation_server_req_get,
						snep_validation_server_req_put,
						data);

}

static void snep_validation_close(int client_fd, int err, gpointer data)
{
	DBG("");

	g_hash_table_remove(snep_validation_hash, GINT_TO_POINTER(client_fd));

	/* Call core server close */
	near_snep_core_close(client_fd, err, data);
}

struct near_p2p_driver validation_snep_driver = {
	.name = "VALIDATION_SNEP",
	.service_name = "urn:nfc:xsn:nfc-forum.org:snep-validation",
	.fallback_service_name = NULL,
	.sock_type = SOCK_STREAM,
	.read = snep_validation_read,
	.push = near_snep_core_push,
	.close = snep_validation_close,
};

int snep_validation_init(void)
{
	/* Would store incoming ndefs per client */
	snep_validation_hash = g_hash_table_new_full(g_direct_hash,
						g_direct_equal, NULL,
						free_snep_validation_client);

	return near_p2p_register(&validation_snep_driver);
}

void snep_validation_exit(void)
{
	near_p2p_unregister(&validation_snep_driver);

	g_hash_table_destroy(snep_validation_hash);
	snep_validation_hash = NULL;
}

/*
 *
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#include <near/nfc_copy.h>

#include <near/plugin.h>
#include <near/log.h>
#include <near/types.h>
#include <near/adapter.h>
#include <near/device.h>
#include <near/ndef.h>
#include <near/tlv.h>

#include "p2p.h"

#define ECHO_DELAY		2000	/* 2 seconds */

struct co_cl_client_data {
	int fd;
	uint8_t buf_count;
	GList *sdu_list;

	int miu_len;
	uint8_t *miu_buffer;

	int sock_type;
	struct sockaddr_nfc_llcp cl_addr;
};

struct sdu {
	int len;
	uint8_t *data;
};

typedef bool (*near_incoming_cb) (struct co_cl_client_data *co_client);

static GHashTable *llcp_client_hash = NULL;

/* free one SDU */
static void free_one_sdu(gpointer data)
{
	struct sdu *i_sdu = data;

	if (!i_sdu)
		return;

	g_free(i_sdu->data);
	g_free(i_sdu);
}

/* Callback: free sdu data */
static void llcp_free_client(gpointer data)
{
	struct co_cl_client_data *co_data = data;

	DBG("");

	if (co_data) {
		g_list_free_full(co_data->sdu_list, free_one_sdu);
		g_free(co_data->miu_buffer);
	}

	g_free(co_data);
}

static void llcp_send_data(gpointer data, gpointer user_data)
{
	struct co_cl_client_data *clt = user_data;
	struct sdu *i_sdu = data;
	int err;

	if (!i_sdu)
		return;

	/* conn less or oriented ? */
	if (clt->sock_type == SOCK_DGRAM)
		err = sendto(clt->fd, i_sdu->data, i_sdu->len, 0,
				(struct sockaddr *) &clt->cl_addr,
				sizeof(clt->cl_addr));
	else
		err = send(clt->fd, i_sdu->data, i_sdu->len, 0);

	if (err < 0)
		near_error("Could not send data to client %d", err);

	/* free */
	clt->sdu_list = g_list_remove(clt->sdu_list, i_sdu);
	free_one_sdu(i_sdu);

	return;
}

/* Connexion oriented code */
static gboolean llcp_common_delay_cb(gpointer user_data)
{

	struct co_cl_client_data *clt = user_data;

	DBG("");

	/* process each sdu */
	g_list_foreach(clt->sdu_list, llcp_send_data, user_data);

	clt->buf_count = 0;

	return FALSE;
}

/*
 * Common function: add an incoming SDU to the glist.
 * If this is the first SDU, we start a 2 secs timer, and be ready for
 * another SDU
 */
static bool llcp_add_incoming_sdu(struct co_cl_client_data *clt, int len)
{
	struct sdu *i_sdu;

	i_sdu = g_try_malloc0(sizeof(struct sdu));
	if (!i_sdu)
		goto out_error;

	i_sdu->len = len;
	if (len > 0) {
		i_sdu->data = g_try_malloc0(len);
		if (!i_sdu->data)
			goto out_error;
		memcpy(i_sdu->data, clt->miu_buffer, len);
	}

	clt->sdu_list = g_list_append(clt->sdu_list, i_sdu);
	clt->buf_count++;

	/* on the first SDU, fire a 2 seconds timer */
	if (clt->buf_count == 1)
		g_timeout_add(ECHO_DELAY, llcp_common_delay_cb, clt);

	return true;

out_error:
	g_free(i_sdu);
	return false;
}

/*
 * Connection-less mode. We get a SDU and add it to the the list. We cannot
 * acceppt more than 2 SDUs, so we discard subsequent SDU.
 *
 * */
static bool llcp_cl_data_recv(struct co_cl_client_data *cl_client)
{
	socklen_t addr_len;
	int len;

	DBG("");

	/* retrieve sdu */
	addr_len = sizeof(struct sockaddr_nfc_llcp);
	len = recvfrom(cl_client->fd, cl_client->miu_buffer, cl_client->miu_len,
			0, (struct sockaddr *) &cl_client->cl_addr, &addr_len);

	if (len < 0) {
		near_error("Could not read data %d %s", len, strerror(errno));
		return false;
	}

	/* Two SDUs max, reject the others */
	if (cl_client->buf_count < 2)
		return llcp_add_incoming_sdu(cl_client,	len);
	else
		near_warn("No more than 2 SDU..ignored");

	return true;
}

/*
 * Connection oriented mode. We get the SDU and add it to the list.
 */
static bool llcp_co_data_recv(struct co_cl_client_data *co_client)
{
	int len;

	DBG("");

	len = recv(co_client->fd, co_client->miu_buffer, co_client->miu_len, 0);
	if (len < 0) {
		near_error("Could not read data %d %s", len, strerror(errno));
		return false;
	}
	return llcp_add_incoming_sdu(co_client, len);

}

/* Common function to initialize client connection data */
static bool llcp_common_read(int client_fd, uint32_t adapter_idx,
					uint32_t target_idx, near_tag_io_cb cb,
					near_incoming_cb llcp_read_bytes,
					const int sock_type)
{
	struct co_cl_client_data *cx_client = NULL;
	socklen_t len = sizeof(unsigned int);

	/* Check if this is the 1st call for this client */
	cx_client = g_hash_table_lookup(llcp_client_hash,
						GINT_TO_POINTER(client_fd));

	if (!cx_client) {
		cx_client = g_try_malloc0(sizeof(struct co_cl_client_data));
		if (!cx_client)
			goto error;

		cx_client->fd = client_fd;
		cx_client->sock_type = sock_type;

		/* get MIU */
		if (getsockopt(client_fd, SOL_NFC, NFC_LLCP_MIUX,
						&cx_client->miu_len, &len) == 0)
			cx_client->miu_len = cx_client->miu_len +
							LLCP_DEFAULT_MIU;
		else
			cx_client->miu_len = LLCP_DEFAULT_MIU;

		cx_client->miu_buffer = g_try_malloc0(cx_client->miu_len);
		if (!cx_client->miu_buffer) {
			DBG("Cannot allocate MIU buffer (size: %d)",
							cx_client->miu_len);
			goto error;
		}

		/* Add to the client hash table */
		g_hash_table_insert(llcp_client_hash,
				GINT_TO_POINTER(client_fd), cx_client);
	}

	/* Read the incoming bytes */
	return llcp_read_bytes(cx_client);

error:
	DBG("Memory allocation failed");
	g_free(cx_client);

	return false;
}

/* clean on close */
static void llcp_validation_close(int client_fd, int err, gpointer data)
{
	DBG("");

	/* remove client */
	g_hash_table_remove(llcp_client_hash, GINT_TO_POINTER(client_fd));
}

/* Connection Oriented: Wrapper for read function */
static bool llcp_validation_read_co(int client_fd, uint32_t adapter_idx,
							uint32_t target_idx,
							near_tag_io_cb cb,
							gpointer data)
{
	DBG("CO client with fd: %d", client_fd);
	return llcp_common_read(client_fd, adapter_idx, target_idx, cb,
						llcp_co_data_recv, SOCK_STREAM);
}

/* Connection less: Wrapper for read function */
static bool llcp_validation_read_cl(int client_fd, uint32_t adapter_idx,
							uint32_t target_idx,
							near_tag_io_cb cb,
							gpointer data)
{
	DBG("CL client with fd: %d", client_fd);
	return llcp_common_read(client_fd, adapter_idx, target_idx, cb,
						llcp_cl_data_recv, SOCK_DGRAM);
}

/* Connection-less server */
struct near_p2p_driver validation_llcp_driver_cl = {
	.name = "VALIDATION_LLCP_CL",
	.service_name = "urn:nfc:sn:cl-echo",
	.fallback_service_name = NULL,
	.sock_type = SOCK_DGRAM,
	.read = llcp_validation_read_cl,
	.close = llcp_validation_close,
};

/* Connection oriented server */
struct near_p2p_driver validation_llcp_driver_co = {
	.name = "VALIDATION_LLCP_CO",
	.service_name = "urn:nfc:sn:co-echo",
	.fallback_service_name = NULL,
	.sock_type = SOCK_STREAM,
	.single_connection = TRUE,
	.read = llcp_validation_read_co,
	.close = llcp_validation_close,
};

int llcp_validation_init(void)
{
	int err;

	DBG("");

	llcp_client_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, llcp_free_client);

	/* register drivers */
	err = near_p2p_register(&validation_llcp_driver_cl);
	if (err < 0)
		return err;

	err =  near_p2p_register(&validation_llcp_driver_co);
	if (err < 0)
		near_p2p_unregister(&validation_llcp_driver_cl);

	return err;
}

void llcp_validation_exit(void)
{
	DBG("");

	near_p2p_unregister(&validation_llcp_driver_co);
	near_p2p_unregister(&validation_llcp_driver_cl);
}

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

#include <near/types.h>
#include <near/log.h>
#include <near/adapter.h>
#include <near/device.h>
#include <near/tag.h>
#include <near/ndef.h>
#include <near/tlv.h>

#include "p2p.h"

#define NDEF_HR_MSG_MIN_LENGTH 0x06
#define HR_HEADER_SIZE	6		/* header (1) + type len (1) +
					*  payload len (1) + rec type (2) 'Hx'
					*  + version (1)
					*/

#define RECORD_TYPE_WKT_ALTERNATIVE_CARRIER 0x0a
#define FRAME_TYPE_OFFSET	4

enum loop_stage_flag {
	STATE_MAIN_NDEF		= 0x00,
	STATE_CFG_RECORD	= 0x01,
};

static GHashTable *hr_ndef_hash = NULL;

struct extra_ndef {
	uint8_t	*ndef;
	uint8_t	length;
};

struct hr_ndef {
	uint8_t *ndef;
	uint16_t cur_ptr;
	int cur_record_len;
	int missing_bytes;
	uint32_t adapter_idx;
	uint32_t target_idx;
	near_tag_io_cb cb;
	int extra_ndef_count;
	int block_free_size;
	near_bool_t cfg_record_state;
	near_bool_t in_extra_read;
};

struct hr_push_client {
	uint8_t fd;
	uint32_t adapter_idx;
	uint32_t target_idx;
	near_device_io_cb cb;
	guint watch;
};

static void free_hr_ndef(gpointer data)
{
	struct hr_ndef *ndef = data;

	if (ndef != NULL)
		g_free(ndef->ndef);
	g_free(ndef);
}

static void handover_close(int client_fd, int err)
{
	struct hr_ndef *ndef;

	DBG("");

	ndef = g_hash_table_lookup(hr_ndef_hash, GINT_TO_POINTER(client_fd));
	if (ndef == NULL)
		return;

	g_hash_table_remove(hr_ndef_hash, GINT_TO_POINTER(client_fd));
}

/* Parse an incoming handover buffer*/
static int handover_ndef_parse(int client_fd, struct hr_ndef *ndef)
{
	int err;
	GList *records;
	struct near_ndef_message *msg;

	DBG("");

	if ((ndef->ndef == NULL) ||
			(ndef->cur_ptr < NDEF_HR_MSG_MIN_LENGTH)) {
		err = -EINVAL;
		goto fail;
	}

	/* call the global parse function */
	records = near_ndef_parse(ndef->ndef, ndef->cur_ptr);
	if (records == NULL) {
		err = -ENOMEM;
		goto fail;
	}

	/*
	 * If we receive a request, we should reply with a Hs but
	 * if the initial frame is Hs (it means we initiated the
	 * exchange with a Hr), so we have to do some actions (e.g.:
	 * pairing with bluetooth)
	 */
	if (strncmp((char *)(ndef->ndef + FRAME_TYPE_OFFSET), "Hr", 2) == 0) {
		/*
		 * The first entry on the record list is the Hr record.
		 * We build the Hs based on it.
		 */
		msg = near_ndef_prepare_handover_record("Hs", records->data,
							NEAR_CARRIER_BLUETOOTH);

		near_info("Send Hs frame");
		err = send(client_fd, msg->data, msg->length, MSG_DONTWAIT);
		if (err >= 0)
			err = 0;

		g_free(msg->data);
		g_free(msg);
	} else {
		err = 0;
	}

	near_ndef_records_free(records);

	return err;

fail:
	near_error("ndef parsing failed (%d)", err);

	handover_close(client_fd, 0);

	return err;
}

static near_bool_t handover_recv_error(void)
{
	near_error("%s", strerror(errno));

	if (errno == EAGAIN)
		return TRUE;

	return FALSE;
}

/* Add extra records right after the end of the "Hr" ndef record */
static near_bool_t handover_read_cfg_records(int client_fd,
				uint32_t adapter_idx, uint32_t target_idx,
				near_tag_io_cb cb)
{
	struct hr_ndef *ndef;
	int bytes_recv;
	int ndef_size;

	ndef = g_hash_table_lookup(hr_ndef_hash, GINT_TO_POINTER(client_fd));
	if (ndef == NULL) {
		near_error("hr_ndef should exist !!!");
		return FALSE;
	}

	if (ndef->in_extra_read == TRUE) {
		/* Next prepare read to complete the Hr */
		ndef->ndef = g_try_realloc(ndef->ndef, ndef->cur_record_len +
				NDEF_HR_MSG_MIN_LENGTH);
		if (ndef == NULL)
			return FALSE;

		/* Read header bytes */
		bytes_recv = recv(client_fd, ndef->ndef + ndef->cur_ptr,
				NDEF_HR_MSG_MIN_LENGTH, MSG_DONTWAIT);
		if (bytes_recv < 0)
			return handover_recv_error();

		/* Now, check the ndef payload size plus header bytes */
		ndef_size = near_ndef_record_length(ndef->ndef + ndef->cur_ptr,
								bytes_recv);
		if (ndef_size < 0)
			goto fail;

		ndef->cur_ptr += bytes_recv;
		ndef->missing_bytes = ndef_size - bytes_recv;

		/* Next prepare read to complete the NDEF */
		ndef->ndef = g_try_realloc(ndef->ndef, ndef->cur_record_len
								+ ndef_size);
		if (ndef->ndef == NULL) {
			g_free(ndef);
			return FALSE;
		}
		ndef->cur_record_len += ndef_size;
		ndef->in_extra_read = FALSE;

		return TRUE;
	}

	/* Read remaining bytes */
	bytes_recv = recv(client_fd, ndef->ndef + ndef->cur_ptr,
					ndef->missing_bytes, MSG_DONTWAIT);
	if (bytes_recv < 0)
		return handover_recv_error();

	ndef->cur_ptr += bytes_recv;
	ndef->missing_bytes -= bytes_recv;

	/* Is the NDEF read complete ? */
	if (ndef->missing_bytes)
		return TRUE;	/* more bytes to come... */

	ndef->extra_ndef_count--;
	ndef->in_extra_read = TRUE;

	if (ndef->extra_ndef_count == 0) {
		/* All the bytes are read so now, parse the frame */
		handover_ndef_parse(client_fd, ndef);
		return FALSE;
	}

	/* Process the next NDEF */
	return TRUE;

fail:
	near_error("Handover read NDEFs failed");
	return FALSE;
}

static near_bool_t handover_read_hr(int client_fd,
		uint32_t adapter_idx, uint32_t target_idx, near_tag_io_cb cb)
{
	int bytes_recv;
	int extra_ndefs;
	struct hr_ndef *ndef;

	DBG("");

	ndef = g_hash_table_lookup(hr_ndef_hash, GINT_TO_POINTER(client_fd));
	if (ndef == NULL)
		return FALSE;

	/* Read remaining bytes */
	bytes_recv = recv(client_fd, ndef->ndef + ndef->cur_ptr,
			ndef->missing_bytes, MSG_DONTWAIT);
	if (bytes_recv < 0)
		return handover_recv_error();

	ndef->cur_ptr += bytes_recv;
	ndef->missing_bytes -= bytes_recv;

	/* Is the ndef "Hr" read complete or should we loop */
	if (ndef->missing_bytes)
		return TRUE;

	/*
	 * The first NDEF frame is read. We now should determine how many
	 * extra records follow the NDEF frame.
	 * We skip the first 6 bytes (Hr header) to jump on the first record
	 */
	extra_ndefs = near_ndef_count_records(ndef->ndef + HR_HEADER_SIZE,
			ndef->cur_record_len - HR_HEADER_SIZE,
			RECORD_TYPE_WKT_ALTERNATIVE_CARRIER);
	if (extra_ndefs < 0)
		goto fail;

	/* There's still some extra ndefs to read */
	ndef->extra_ndef_count = extra_ndefs;

	/* End of Handover message - now process extra records */
	ndef->in_extra_read = TRUE;
	ndef->cfg_record_state = TRUE;

	return TRUE;

fail:
	near_error("Handover read failed");
	return FALSE;
}

static near_bool_t handover_read_initialize(int client_fd,
		uint32_t adapter_idx, uint32_t target_idx, near_tag_io_cb cb)
{
	int bytes_recv;
	struct hr_ndef *ndef;

	DBG("");

	/* Allocate the ndef structure */
	ndef = g_try_malloc0(sizeof(struct hr_ndef));
	if (ndef == NULL)
		goto fail;

	/* Allocate and read frame header (6 bytes) */
	ndef->ndef = g_try_malloc0(NDEF_HR_MSG_MIN_LENGTH);
	if (ndef->ndef == NULL)
		goto fail;

	/* Initialize default values */
	ndef->cur_ptr = 0;
	ndef->cur_record_len = -1;
	ndef->adapter_idx = adapter_idx;
	ndef->target_idx = target_idx;
	ndef->cb = cb;
	ndef->cfg_record_state = FALSE;

	g_hash_table_insert(hr_ndef_hash, GINT_TO_POINTER(client_fd), ndef);

	/* Read header bytes (6) */
	bytes_recv = recv(client_fd, ndef->ndef,
				NDEF_HR_MSG_MIN_LENGTH, MSG_DONTWAIT);
	if (bytes_recv < 0)
		return handover_recv_error();

	/* Now, check the ndef payload size plus header bytes */
	ndef->cur_record_len = near_ndef_record_length(ndef->ndef, bytes_recv);
	if (ndef->cur_record_len < 0)
		goto fail;

	ndef->cur_ptr += bytes_recv;
	ndef->missing_bytes = ndef->cur_record_len - bytes_recv;

	DBG("Handover frame size is %d", ndef->cur_ptr);

	/* Next prepare read to complete the read */
	ndef->ndef = g_try_realloc(ndef->ndef, ndef->cur_record_len);
	if (ndef->ndef == NULL)
		goto fail;

	return TRUE;

fail:
	free_hr_ndef(ndef);

	return FALSE;
}

/*
 * This function is a "dispatcher", to read Hr/Hs messages,
 * and/or additionnal NDEF messages
 */
static near_bool_t handover_read(int client_fd,
		uint32_t adapter_idx, uint32_t target_idx,
		near_tag_io_cb cb)
{
	struct hr_ndef *ndef;

	ndef = g_hash_table_lookup(hr_ndef_hash, GINT_TO_POINTER(client_fd));
	if (ndef == NULL) {
		/* First call: allocate and read header bytes*/
		return handover_read_initialize(client_fd, adapter_idx,
						target_idx, cb);
	}

	if (ndef->cfg_record_state == TRUE) {
		return handover_read_cfg_records(client_fd, adapter_idx,
							target_idx, cb);
	}

	return handover_read_hr(client_fd, adapter_idx, target_idx, cb);
}

static void free_hr_push_client(struct hr_push_client *client, int status)
{
	DBG("");

	handover_close(client->fd, 0);
	close(client->fd);

	if (client->cb)
		client->cb(client->adapter_idx, client->target_idx, status);

	if (client->watch > 0)
		g_source_remove(client->watch);

	g_free(client);
}

static gboolean handover_push_event(GIOChannel *channel,
				GIOCondition condition,	gpointer data)
{
	near_bool_t ret;
	struct hr_push_client *client = (struct hr_push_client *)data;

	DBG("condition 0x%x", condition);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		near_error("Error with Handover client");

		free_hr_push_client(client, -EIO);

		return FALSE;
	}

	ret = handover_read(client->fd,
			client->adapter_idx, client->target_idx,
			client->cb);

	if (ret == FALSE)
		free_hr_push_client(client, 0);

	return ret;
}

static int handover_push(int client_fd,
			uint32_t adapter_idx, uint32_t target_idx,
			struct near_ndef_message *ndef,
			near_device_io_cb cb)
{
	int err;
	struct hr_push_client *client;
	GIOChannel *channel;

	DBG("");

	client = g_try_malloc0(sizeof(struct hr_push_client));
	if (client == NULL)
		return -ENOMEM;

	channel = g_io_channel_unix_new(client_fd);
	g_io_channel_set_close_on_unref(channel, TRUE);

	client->fd = client_fd;
	client->adapter_idx = adapter_idx;
	client->target_idx = target_idx;
	client->cb = cb;
	client->watch = g_io_add_watch(channel,
					G_IO_IN | G_IO_HUP | G_IO_NVAL |
					G_IO_ERR, handover_push_event,
					(gpointer) client);

	err = send(client_fd, ndef->data, ndef->length, MSG_DONTWAIT);
	if (err < 0)
		free_hr_push_client(client, err);

	return err;
}

struct near_p2p_driver handover_driver = {
	.name = "Handover",
	.service_name = NEAR_DEVICE_SN_HANDOVER,
	.read = handover_read,
	.push = handover_push,
	.close = handover_close,
};

int handover_init(void)
{
	hr_ndef_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_hr_ndef);

	return near_p2p_register(&handover_driver);
}

void handover_exit(void)
{
	near_p2p_unregister(&handover_driver);

	g_hash_table_destroy(hr_ndef_hash);
	hr_ndef_hash = NULL;
}

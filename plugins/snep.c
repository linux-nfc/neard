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

#define SNEP_SN "urn.nfc.sn.snep"

struct p2p_snep_channel {
	near_tag_io_cb cb;
	uint32_t adapter_idx;
	uint32_t target_idx;
	int fd;
	guint watch;
	GIOChannel *channel;
};

static struct p2p_snep_channel snep_server;

static gboolean snep_listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	DBG("condition 0x%x", condition);

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
		DBG("bind failed %d", err);

		close(snep_server.fd);
		return err;
	}

	err = listen(snep_server.fd, 10);
	if (err < 0) {
		DBG("listen failed %d", err);

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

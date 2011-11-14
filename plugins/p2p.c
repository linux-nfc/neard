/*
 *
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
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

static int p2p_read(uint32_t adapter_idx,
		uint32_t target_idx, near_tag_read_cb cb)
{
	int err;

	DBG("");

	err = near_adapter_connect(adapter_idx, target_idx, NFC_PROTO_NFC_DEP);
	if (err < 0) {
		near_error("Could not connect %d", err);

		return err;
	}

	return 0;
}

static struct near_tag_driver p2p_driver = {
		.type     = NEAR_TAG_NFC_DEP,
		.read_tag = p2p_read,
};

static int p2p_init(void)
{
	DBG("");

	return near_tag_driver_register(&p2p_driver);
}

static void p2p_exit(void)
{
	DBG("");

	near_tag_driver_unregister(&p2p_driver);
}

NEAR_PLUGIN_DEFINE(p2p, "NFC Forum peer to peer mode support", VERSION,
		NEAR_PLUGIN_PRIORITY_HIGH, p2p_init, p2p_exit)

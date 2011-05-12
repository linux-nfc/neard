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
#include <near/tag.h>
#include <near/ndef.h>

#define CMD_READ         0x30
#define CMD_WRITE        0xA2
#define META_BLOCK_START 0
#define DATA_BLOCK_START 4

static GHashTable *tag_hash;

struct type2_cmd {
	uint8_t cmd;
	uint8_t block;
	uint8_t data[];
} __attribute__((packed));

struct type2_tag {
	uint32_t target_idx;
	uint8_t uid[8];
	uint8_t lock[4];
	uint8_t cc[4];
	uint16_t data_length;
	uint8_t *data;
};

static void free_tag(gpointer data)
{
	struct type2_tag *tag = data;

	g_free(tag->data);
	g_free(tag);
}

static int meta_recv(uint8_t *resp, int length, void *data)
{
	int i;
	struct type2_tag *tag = data;

	DBG("%d", length);

	if (length < 0)
		return length; 

	if (resp[0] != 0)
		return -EIO;

	memcpy(&tag->uid, resp + NFC_HEADER_SIZE, length);

	for (i = 0; i < 16; i++)
		DBG("0x%x", resp[i + 1]);

	DBG("0x%x 0x%x 0x%x 0x%x", tag->cc[0], tag->cc[1], tag->cc[2], tag->cc[3]);

	return 0;
}

static int nfctype2_read_meta(uint32_t adapter_idx, uint32_t target_idx, struct type2_tag *tag)
{
	int err;
	struct type2_cmd cmd;
	
	DBG("");

	cmd.cmd = CMD_READ;
	cmd.block = META_BLOCK_START;

	err = near_adapter_send(adapter_idx, (uint8_t *)&cmd, sizeof(cmd), meta_recv, tag);
	if (err < 0)
		near_adapter_disconnect(adapter_idx);

	return 0;
}

static int nfctype2_read_tag(uint32_t adapter_idx,
					uint32_t target_idx)
{
	int err;
	struct type2_tag *tag;

	tag = g_hash_table_lookup(tag_hash, GINT_TO_POINTER(target_idx));
	if (tag == NULL) {
		tag = g_try_malloc0(sizeof(*tag));
		if (tag == NULL)
			return -ENOMEM;

		tag->target_idx = target_idx;

		g_hash_table_insert(tag_hash, GINT_TO_POINTER(target_idx), tag);
	}

	err = near_adapter_connect(adapter_idx, target_idx, NFC_PROTO_MIFARE);
	if (err < 0)
		return err;

	err = nfctype2_read_meta(adapter_idx, target_idx, tag);
	if (err < 0)
		near_adapter_disconnect(adapter_idx);

	return err;
}

static struct near_tag_driver type2_driver = {
	.type     = NEAR_TAG_NFC_TYPE2,
	.read_tag = nfctype2_read_tag,
};

static int nfctype2_init(void)
{
	DBG("");

	tag_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_tag);

	return near_tag_driver_register(&type2_driver);
}

static void nfctype2_exit(void)
{
	DBG("");

	g_hash_table_destroy(tag_hash);

	near_tag_driver_unregister(&type2_driver);
}

NEAR_PLUGIN_DEFINE(nfctype2, "NFC Forum Type 2 tags support", VERSION,
			NEAR_PLUGIN_PRIORITY_HIGH, nfctype2_init, nfctype2_exit)


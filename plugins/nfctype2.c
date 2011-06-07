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

#define CMD_READ         0x30
#define CMD_WRITE        0xA2

#define READ_SIZE  16
#define BLOCK_SIZE 4

#define META_BLOCK_START 0
#define DATA_BLOCK_START 4
#define TYPE2_MAGIC 0xe1

#define TLV_NULL 0x00
#define TLV_LOCK 0x01
#define TLV_MEM  0x02
#define TLV_NDEF 0x03
#define TLV_PROP 0xfd
#define TLV_END  0xfe

#define TAG_DATA_CC(data) ((data) + 12)
#define TAG_DATA_LENGTH(cc) ((cc)[2] * 8)
#define TAG_DATA_NFC(cc) ((cc)[0] & TYPE2_MAGIC)

struct type2_cmd {
	uint8_t cmd;
	uint8_t block;
	uint8_t data[];
} __attribute__((packed));

struct type2_tag {
	uint16_t current_block;

	struct near_tag *tag;
};

static uint16_t tlv_length(uint8_t *tlv)
{
	uint16_t length;

	if (tlv[0] == TLV_NULL || tlv[0] == TLV_END)
		length = 0;
	else if (tlv[1] == 0xff)
		length = *(uint16_t *)(tlv + 2);
	else
		length = tlv[1];

	return length;
}

static uint8_t *next_tlv(uint8_t *data)
{
	uint16_t length;
	uint8_t l_length;

	length = tlv_length(data);
	if (length > 0xfe)
		l_length = 3;
	else if (length == 0)
		l_length = 0;
	else
		l_length = 1;

	/* T (1 byte) + L (1 or 3 bytes) + V */
	return data + 1 + l_length + length;
}

static uint8_t *tlv_data(uint8_t *data)
{
	uint16_t length;
	uint8_t l_length;

	length = tlv_length(data);
	if (length > 0xfe)
		l_length = 3;
	else if (length == 0)
		l_length = 0;
	else
		l_length = 1;

	/* T (1 byte) + L (1 or 3 bytes) */
	return data + 1 + l_length;
}

static int data_parse(struct near_tag *tag, uint8_t *data, uint16_t length)
{
	uint8_t *tlv = data, t;

	DBG("");

	while(1) {
		t = tlv[0];

		DBG("tlv 0x%x", tlv[0]);

		switch (t) {
		case TLV_NDEF:
			DBG("NDEF found %d bytes long", tlv_length(tlv));

			near_tag_add_ndef(tag, tlv_data(tlv), tlv_length(tlv));

			break;
		case TLV_END:
			return 0;
		}

		tlv = next_tlv(tlv);

		if (tlv - data >= length)
			break;
	}

	DBG("Done");

	return 0;
}

static int data_recv(uint8_t *resp, int length, void *data)
{
	struct type2_tag *tag = data;
	struct type2_cmd cmd;
	uint8_t *nfc_data;
	uint16_t current_length, length_read, data_length;
	uint32_t adapter_idx;
	int read_blocks;

	DBG("%d", length);

	if (length < 0) {
		g_free(tag);

		return  length;
	}

	nfc_data = near_tag_get_data(tag->tag, (size_t *)&data_length);
	adapter_idx = near_tag_get_adapter_idx(tag->tag);

	length_read = length - NFC_HEADER_SIZE;
	current_length = tag->current_block * BLOCK_SIZE;
	if (current_length + length - NFC_HEADER_SIZE > data_length)
		length_read = data_length - current_length;

	memcpy(nfc_data + current_length, resp + NFC_HEADER_SIZE, length_read);

	if (current_length + length_read == data_length) {
		/* TODO parse tag->data for NDEFS, and notify target.c */
		near_adapter_disconnect(adapter_idx);
		tag->current_block = 0;

		DBG("Done reading");

		data_parse(tag->tag, nfc_data, data_length);

		g_free(tag);

		return 0;
	}

	read_blocks = length / BLOCK_SIZE;
	tag->current_block += read_blocks;

	cmd.cmd = CMD_READ;
	cmd.block = DATA_BLOCK_START + tag->current_block;

	DBG("adapter %d", adapter_idx);

	return near_adapter_send(adapter_idx,
				(uint8_t *)&cmd, sizeof(cmd),
					data_recv, tag);
}

static int data_read(struct type2_tag *tag)
{
	struct type2_cmd cmd;
	uint32_t adapter_idx;

	DBG("");

	tag->current_block = 0;

	cmd.cmd = CMD_READ;
	cmd.block = DATA_BLOCK_START;

	adapter_idx = near_tag_get_adapter_idx(tag->tag);

	return near_adapter_send(adapter_idx,
				(uint8_t *)&cmd, sizeof(cmd),
					data_recv, tag);
}

static int meta_recv(uint8_t *resp, int length, void *data)
{
        uint32_t *target_idx = data;
	struct near_tag *tag;
	struct type2_tag *t2_tag;
	uint8_t *cc;

	DBG("%d", length);

	if (length < 0)
		return length; 

	if (resp[0] != 0)
		return -EIO;

	cc = TAG_DATA_CC(resp + NFC_HEADER_SIZE);

	if (TAG_DATA_NFC(cc) == 0)
		return -EINVAL;

	tag = near_target_get_tag(*target_idx, TAG_DATA_LENGTH(cc));
	if (tag == NULL)
		return -ENOMEM;

	t2_tag = g_try_malloc0(sizeof(struct type2_tag));
	t2_tag->tag = tag;

	near_tag_set_uid(tag, resp + NFC_HEADER_SIZE, 8);

	return data_read(t2_tag);
}

static int nfctype2_read_meta(uint32_t adapter_idx, uint32_t target_idx)
{
	struct type2_cmd cmd;
	uint32_t *idx;
	
	DBG("");

	cmd.cmd = CMD_READ;
	cmd.block = META_BLOCK_START;

	idx = g_try_malloc0(sizeof(uint32_t));
	*idx = target_idx;

	return near_adapter_send(adapter_idx, (uint8_t *)&cmd, sizeof(cmd), meta_recv, idx);
}

static int nfctype2_read_tag(uint32_t adapter_idx,
					uint32_t target_idx)
{
	int err;

	DBG("");

	err = near_adapter_connect(adapter_idx, target_idx, NFC_PROTO_MIFARE);
	if (err < 0) {
		near_error("Could not connect %d", err);

		return err;
	}

	err = nfctype2_read_meta(adapter_idx, target_idx);
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

	return near_tag_driver_register(&type2_driver);
}

static void nfctype2_exit(void)
{
	DBG("");

	near_tag_driver_unregister(&type2_driver);
}

NEAR_PLUGIN_DEFINE(nfctype2, "NFC Forum Type 2 tags support", VERSION,
			NEAR_PLUGIN_PRIORITY_HIGH, nfctype2_init, nfctype2_exit)


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
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/socket.h>

#include <near/nfc_copy.h>
#include <near/plugin.h>
#include <near/log.h>
#include <near/types.h>
#include <near/adapter.h>
#include <near/tag.h>
#include <near/ndef.h>
#include <near/tlv.h>

extern int mifare_read(uint32_t adapter_idx, uint32_t target_idx,
		near_tag_io_cb cb, enum near_tag_sub_type tgt_subtype);

extern int mifare_check_presence(uint32_t adapter_idx, uint32_t target_idx,
			near_tag_io_cb cb, enum near_tag_sub_type tgt_subtype);

extern int mifare_write(uint32_t adapter_idx, uint32_t target_idx,
			struct near_ndef_message *ndef,
			near_tag_io_cb cb, enum near_tag_sub_type tgt_subtype);

#define CMD_READ         0x30
#define CMD_READ_SIZE    0x02

#define CMD_WRITE        0xA2

#define READ_SIZE  16
#define BLOCK_SIZE 4

#define META_BLOCK_START 0
#define DATA_BLOCK_START 4
#define TYPE2_MAGIC 0xe1

#define META_BLOCK_MULC_END 0x28

#define TAG_DATA_CC(data) ((data) + 12)
#define TAG_DATA_LENGTH(cc) ((cc)[2] * 8)
#define TAG_DATA_NFC(cc) ((cc)[0])

#define TYPE2_NOWRITE_ACCESS	0x0F
#define TYPE2_READWRITE_ACCESS	0x00
#define TAG_T2_WRITE_FLAG(cc) ((cc)[3] & TYPE2_NOWRITE_ACCESS)

#define NDEF_MAX_SIZE	0x30

#define CC_BLOCK_START 3
#define TYPE2_TAG_VER_1_0  0x10
#define TYPE2_DATA_SIZE_48 0x6

struct type2_cmd {
	uint8_t cmd;
	uint8_t block;
	uint8_t data[BLOCK_SIZE];
} __attribute__((packed));

struct type2_tag {
	uint32_t adapter_idx;
	uint16_t current_block;

	near_tag_io_cb cb;
	struct near_tag *tag;
};

struct t2_cookie {
	uint32_t adapter_idx;
	uint32_t target_idx;
	uint8_t current_block;
	struct near_ndef_message *ndef;
	near_tag_io_cb cb;
};

struct type2_cc {
	uint8_t magic;
	uint8_t version;
	uint8_t mem_size;
	uint8_t read_write;
};

static int t2_cookie_release(int err, void *data)
{
	struct t2_cookie *cookie = data;

	DBG("%p", cookie);

	if (!cookie)
		return err;

	if (cookie->cb)
		cookie->cb(cookie->adapter_idx, cookie->target_idx, err);

	if (cookie->ndef)
		g_free(cookie->ndef->data);

	g_free(cookie->ndef);
	g_free(cookie);

	return err;
}

static int data_recv(uint8_t *resp, int length, void *data)
{
	struct type2_tag *tag = data;
	struct type2_cmd cmd;
	uint8_t *nfc_data;
	size_t current_length, length_read, data_length;
	uint32_t adapter_idx, target_idx;
	int read_blocks;

	DBG("%d", length);

	if (length < 0) {
		g_free(tag);

		return  length;
	}

	nfc_data = near_tag_get_data(tag->tag, &data_length);
	adapter_idx = near_tag_get_adapter_idx(tag->tag);

	length_read = length - NFC_HEADER_SIZE;
	current_length = tag->current_block * BLOCK_SIZE;
	if (current_length + length - NFC_HEADER_SIZE > data_length)
		length_read = data_length - current_length;

	memcpy(nfc_data + current_length, resp + NFC_HEADER_SIZE, length_read);

	if (current_length + length_read == data_length ||
	    (length < READ_SIZE && tag->current_block == META_BLOCK_MULC_END)) {
		GList *records;

		/* TODO parse tag->data for NDEFS, and notify target.c */
		tag->current_block = 0;

		DBG("Done reading");

		records = near_tlv_parse(nfc_data, data_length);
		near_tag_add_records(tag->tag, records, tag->cb, 0);

		if (length < READ_SIZE) {
			/*
			 * We reached a non readable block.
			 * According to Mifare Ultralight C spec MF0ICU2,
			 * if we read a block from 0x2c the tag will return
			 * NAK on the RF interface.
			 * For future check presence, we then need to reactivate
			 * the target.
			 */
			target_idx = near_tag_get_target_idx(tag->tag);
			near_tag_activate_target(adapter_idx, target_idx,
						NFC_PROTO_MIFARE);
		}

		g_free(tag);

		return 0;
	}

	read_blocks = length / BLOCK_SIZE;
	tag->current_block += read_blocks;

	cmd.cmd = CMD_READ;
	cmd.block = DATA_BLOCK_START + tag->current_block;

	DBG("adapter %d", adapter_idx);

	return near_adapter_send(adapter_idx,
				(uint8_t *) &cmd, CMD_READ_SIZE,
					data_recv, tag, NULL);
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
					(uint8_t *) &cmd, CMD_READ_SIZE,
					data_recv, tag, NULL);
}

static int meta_recv(uint8_t *resp, int length, void *data)
{
	struct t2_cookie *cookie = data;
	struct near_tag *tag;
	struct type2_tag *t2_tag;
	uint8_t *cc;
	int err;

	DBG("%d", length);

	if (length < 0) {
		err = length;
		goto out_err;
	}

	if (resp[0] != 0) {
		err = -EIO;
		goto out_err;
	}

	cc = TAG_DATA_CC(resp + NFC_HEADER_SIZE);

	/* Default to 48 bytes data size in case of blank tag */
	err = near_tag_add_data(cookie->adapter_idx, cookie->target_idx,
			NULL, (TAG_DATA_LENGTH(cc) ? TAG_DATA_LENGTH(cc) :
			TYPE2_DATA_SIZE_48 << 3));

	if (err < 0)
		goto out_err;

	tag = near_tag_get_tag(cookie->adapter_idx, cookie->target_idx);
	if (!tag) {
		err = -ENOMEM;
		goto out_err;
	}

	t2_tag = g_try_malloc0(sizeof(struct type2_tag));
	if (!t2_tag) {
		err = -ENOMEM;
		goto out_err;
	}

	t2_tag->adapter_idx = cookie->adapter_idx;
	t2_tag->cb = cookie->cb;
	t2_tag->tag = tag;

	/* Set the ReadWrite flag */
	if (TAG_T2_WRITE_FLAG(cc) == TYPE2_NOWRITE_ACCESS)
		near_tag_set_ro(tag, TRUE);
	else
		near_tag_set_ro(tag, FALSE);

	near_tag_set_memory_layout(tag, NEAR_TAG_MEMORY_STATIC);

	if (TAG_DATA_NFC(cc) != TYPE2_MAGIC) {
		DBG("Mark as blank tag");
		near_tag_set_blank(tag, TRUE);
	} else {
		near_tag_set_blank(tag, FALSE);
	}

	err = data_read(t2_tag);
	if (err < 0)
		goto out_tag;

	/*
	 * As reading isn't complete,
	 * callback shouldn't be called while freeing the cookie
	 */
	cookie->cb = NULL;
	return t2_cookie_release(err, cookie);

out_tag:
	g_free(t2_tag);

out_err:
	return t2_cookie_release(err, cookie);
}

static int nfctype2_read_meta(uint32_t adapter_idx, uint32_t target_idx,
							near_tag_io_cb cb)
{
	struct type2_cmd cmd;
	struct t2_cookie *cookie;

	DBG("");

	cmd.cmd = CMD_READ;
	cmd.block = META_BLOCK_START;

	cookie = g_try_malloc0(sizeof(struct t2_cookie));
	if (!cookie)
		return -ENOMEM;

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;

	return near_adapter_send(adapter_idx, (uint8_t *) &cmd, CMD_READ_SIZE,
					meta_recv, cookie, t2_cookie_release);
}

static int nfctype2_read(uint32_t adapter_idx,
				uint32_t target_idx, near_tag_io_cb cb)
{
	enum near_tag_sub_type tgt_subtype;

	DBG("");

	tgt_subtype = near_tag_get_subtype(adapter_idx, target_idx);

	switch (tgt_subtype) {
	case NEAR_TAG_NFC_T2_MIFARE_ULTRALIGHT:
		return nfctype2_read_meta(adapter_idx, target_idx, cb);

	/* Specific Mifare read access */
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_1K:
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_4K:
		return mifare_read(adapter_idx, target_idx,
			cb, tgt_subtype);

	default:
		DBG("Unknown Tag Type 2 subtype %d", tgt_subtype);
		return -1;
	}
}

static int data_write_resp(uint8_t *resp, int length, void *data)
{
	int err;
	struct t2_cookie *cookie = data;
	struct type2_cmd cmd;

	DBG("");

	if (length < 0 || resp[0] != 0) {
		err = -EIO;
		goto out_err;
	}

	if (cookie->ndef->offset > cookie->ndef->length) {
		DBG("Done writing");

		return t2_cookie_release(0, cookie);
	}

	cmd.cmd = CMD_WRITE;
	cmd.block = cookie->current_block;
	cookie->current_block++;

	if ((cookie->ndef->offset + BLOCK_SIZE) <
			cookie->ndef->length) {
		memcpy(cmd.data, cookie->ndef->data +
					cookie->ndef->offset, BLOCK_SIZE);
		cookie->ndef->offset += BLOCK_SIZE;
	} else {
		memcpy(cmd.data, cookie->ndef->data + cookie->ndef->offset,
				cookie->ndef->length - cookie->ndef->offset);
		cookie->ndef->offset = cookie->ndef->length + 1;
	}

	return near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd,
					sizeof(cmd), data_write_resp, cookie,
					t2_cookie_release);

out_err:
	return t2_cookie_release(err, cookie);
}

static int data_write(uint32_t adapter_idx, uint32_t target_idx,
				struct near_ndef_message *ndef,
				near_tag_io_cb cb)
{
	struct type2_cmd cmd;
	struct t2_cookie *cookie;
	int err;

	DBG("");

	cookie = g_try_malloc0(sizeof(struct t2_cookie));
	if (!cookie) {
		err = -ENOMEM;
		if (cb)
			cb(adapter_idx, target_idx, err);
		return err;
	}

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->current_block = DATA_BLOCK_START;
	cookie->ndef = ndef;
	cookie->cb = cb;

	cmd.cmd = CMD_WRITE;
	cmd.block = cookie->current_block;
	memcpy(cmd.data, cookie->ndef->data, BLOCK_SIZE);
	cookie->ndef->offset += BLOCK_SIZE;
	cookie->current_block++;

	return near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd,
					sizeof(cmd), data_write_resp, cookie,
					t2_cookie_release);
}

static int nfctype2_write(uint32_t adapter_idx, uint32_t target_idx,
				struct near_ndef_message *ndef,
				near_tag_io_cb cb)
{
	struct near_tag *tag;
	enum near_tag_sub_type tgt_subtype;
	int err;

	DBG("");

	if (!ndef || !cb) {
		err = -EINVAL;
		goto out_err;
	}

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag) {
		err = -EINVAL;
		goto out_err;
	}

	tgt_subtype = near_tag_get_subtype(adapter_idx, target_idx);

	switch (tgt_subtype) {
	case NEAR_TAG_NFC_T2_MIFARE_ULTRALIGHT:
		/*
		 * This check is valid for only static tags.
		 * Max data length on Type 2 Tag
		 * including TLV's is NDEF_MAX_SIZE
		 */
		if (near_tag_get_memory_layout(tag) == NEAR_TAG_MEMORY_STATIC) {
			if ((ndef->length + 3) > near_tag_get_data_length(tag)) {
				near_error("Not enough space on tag %zd %zd",
						ndef->length,
						near_tag_get_data_length(tag));
				err = -ENOSPC;
				goto out_err;
			}
		}

		return data_write(adapter_idx, target_idx, ndef, cb);

	/* Specific Mifare write access */
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_1K:
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_4K:
		return mifare_write(adapter_idx, target_idx, ndef,
				cb, tgt_subtype);
	default:
		DBG("Unknown TAG Type 2 subtype %d", tgt_subtype);
		err = -EINVAL;
		goto out_err;
	}

	return 0;

out_err:
	if (cb)
		cb(adapter_idx, target_idx, err);

	return err;
}

static int check_presence(uint8_t *resp, int length, void *data)
{
	struct t2_cookie *cookie = data;
	int err = 0;

	DBG("%d", length);

	if (length < 0)
		err = -EIO;

	return t2_cookie_release(err, cookie);
}

static int nfctype2_check_presence(uint32_t adapter_idx, uint32_t target_idx,
							near_tag_io_cb cb)
{
	struct type2_cmd cmd;
	struct t2_cookie *cookie;
	enum near_tag_sub_type tgt_subtype;

	DBG("");

	tgt_subtype = near_tag_get_subtype(adapter_idx, target_idx);

	switch (tgt_subtype) {
	case NEAR_TAG_NFC_T2_MIFARE_ULTRALIGHT:
		cmd.cmd = CMD_READ;
		cmd.block = META_BLOCK_START;

		cookie = g_try_malloc0(sizeof(struct t2_cookie));
		if (!cookie)
			return -ENOMEM;

		cookie->adapter_idx = adapter_idx;
		cookie->target_idx = target_idx;
		cookie->cb = cb;

		return near_adapter_send(adapter_idx, (uint8_t *) &cmd,
					CMD_READ_SIZE, check_presence, cookie,
					t2_cookie_release);

	/* Specific Mifare check presence */
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_1K:
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_4K:
		return mifare_check_presence(adapter_idx, target_idx,
							cb, tgt_subtype);

	default:
		DBG("Unknown TAG Type 2 subtype %d", tgt_subtype);

		return -1;
	}
}

static int format_resp(uint8_t *resp, int length, void *data)
{
	int err = 0;
	struct t2_cookie *cookie = data;
	struct near_tag *tag;

	DBG("");

	if (length < 0 || resp[0] != 0) {
		err = -EIO;
		goto out_err;
	}

	tag = near_tag_get_tag(cookie->adapter_idx, cookie->target_idx);
	if (!tag) {
		err = -EINVAL;
		goto out_err;
	}

	DBG("Done formatting");
	near_tag_set_blank(tag, FALSE);

out_err:
	return t2_cookie_release(err, cookie);
}

static int nfctype2_format(uint32_t adapter_idx, uint32_t target_idx,
				near_tag_io_cb cb)
{
	struct type2_cmd cmd;
	struct t2_cookie *cookie;
	struct near_ndef_message *cc_ndef;
	struct type2_cc *t2_cc;
	struct near_tag *tag;
	enum near_tag_sub_type tgt_subtype;
	int err;

	DBG("");

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag)
		return -EINVAL;


	tgt_subtype = near_tag_get_subtype(adapter_idx, target_idx);

	if (tgt_subtype != NEAR_TAG_NFC_T2_MIFARE_ULTRALIGHT) {
		DBG("Unknown Tag Type 2 subtype %d", tgt_subtype);
		return -1;
	}

	t2_cc = g_try_malloc0(sizeof(struct type2_cc));
	cc_ndef = g_try_malloc0(sizeof(struct near_ndef_message));
	cookie = g_try_malloc0(sizeof(struct t2_cookie));

	if (!t2_cc || !cc_ndef || !cookie) {
		err = -ENOMEM;
		goto out_err;
	}

	t2_cc->magic = TYPE2_MAGIC;
	t2_cc->version = TYPE2_TAG_VER_1_0;
	t2_cc->mem_size = TYPE2_DATA_SIZE_48;
	t2_cc->read_write = TYPE2_READWRITE_ACCESS;

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->current_block = CC_BLOCK_START;
	cookie->ndef = cc_ndef;
	cookie->ndef->data = (uint8_t *) t2_cc;
	cookie->cb = cb;

	cmd.cmd = CMD_WRITE;
	cmd.block = CC_BLOCK_START;
	memcpy(cmd.data, (uint8_t *) t2_cc, BLOCK_SIZE);

	err = near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd,
				sizeof(cmd), format_resp, cookie, NULL);

out_err:
	if (err < 0) {
		g_free(t2_cc);
		g_free(cc_ndef);
		g_free(cookie);
	}

	return err;
}

static struct near_tag_driver type2_driver = {
	.type           = NFC_PROTO_MIFARE,
	.priority       = NEAR_TAG_PRIORITY_DEFAULT,
	.read           = nfctype2_read,
	.write          = nfctype2_write,
	.check_presence = nfctype2_check_presence,
	.format		= nfctype2_format,
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

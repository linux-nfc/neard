/*
 *  NFC Type 5 (ISO 15693) Tag code
 *
 *  Copyright (C) 2013 Animal Creek Technologies, Inc. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */
/*
 * Currently only single block reads and writes are used for I/O.
 * The read multiple command is used but only to determine if the
 * tag supports it which is necessary when setting the CC info
 * during format.
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

/* Only Type 5 NDEF version 1.0 is supported */
#define TYPE5_VERSION_MAJOR		1
#define TYPE5_VERSION_MINOR		0

/*
 * Type 5 NDEF CC Byte 2 can only indicate memory sizes up to 2040 bytes
 * (0xff * 8).  Any memory beyond that will be unused (ISO/15693 cards
 * can have up to 8192 bytes of memory)--this may chnge once the Type 5
 * spec is finialized.
 */
#define TYPE5_MAX_MEM_SIZE		2040

/*
 * At one point the NFC-V specification committee was supposed to
 * have agreed that that the NDEF data area will start at the
 * beginning of the first *block* after the end of the CC data
 * (which is 4 bytes long) regardless of the tag's block size.
 * It turns out that this may not be the case but until things
 * are finalized assume that is the case.
 *
 * For Example:
 *    - If the tag's block size is 1 byte, the data area starts at
 *	the beginning of 5th block (offset 4).
 *    - If the tag's block size is 32 bytes, the data area starts at
 *	the beginning of the 2nd block (offset 32).
 */
#define TYPE5_META_START_OFFSET		0

#define TYPE5_DATA_START_OFFSET(t) \
		MAX(near_tag_get_blk_size(t), sizeof(struct type5_cc))

#define TYPE5_LEN_CC_BYTES		0x04

#define TYPE5_CC0_NDEF_MAGIC		0xe1

#define TYPE5_CC1_VER_MAJOR_SHIFT	6
#define TYPE5_CC1_VER_MINOR_SHIFT	4
#define TYPE5_CC1_READ_ACCESS_SHIFT	2
#define TYPE5_CC1_WRITE_ACCESS_SHIFT	0

#define TYPE5_CC1_VER_MAJOR_MASK	(0x3 << TYPE5_CC1_VER_MAJOR_SHIFT)
#define TYPE5_CC1_VER_MINOR_MASK	(0x3 << TYPE5_CC1_VER_MINOR_SHIFT)
#define TYPE5_CC1_READ_ACCESS_MASK	(0x3 << TYPE5_CC1_READ_ACCESS_SHIFT)
#define TYPE5_CC1_WRITE_ACCESS_MASK	(0x3 << TYPE5_CC1_WRITE_ACCESS_SHIFT)

#define TYPE5_CC1_VER_GET_MAJOR(v)	(((v) & TYPE5_CC1_VER_MAJOR_MASK) >> \
						TYPE5_CC1_VER_MAJOR_SHIFT)
#define TYPE5_CC1_VER_GET_MINOR(v)	(((v) & TYPE5_CC1_VER_MINOR_MASK) >> \
						TYPE5_CC1_VER_MINOR_SHIFT)

#define TYPE5_CC1_READ_ACCESS_ALWAYS	(0x0 << TYPE5_CC1_READ_ACCESS_SHIFT)
#define TYPE5_CC1_WRITE_ACCESS_ALWAYS	(0x0 << TYPE5_CC1_WRITE_ACCESS_SHIFT)
#define TYPE5_CC1_WRITE_ACCESS_PROPRIETARY (0x2 << TYPE5_CC1_WRITE_ACCESS_SHIFT)
#define TYPE5_CC1_WRITE_ACCESS_NEVER	(0x3 << TYPE5_CC1_WRITE_ACCESS_SHIFT)
#define TYPE5_CC1_WRITE_ACCESS_NEVER	(0x3 << TYPE5_CC1_WRITE_ACCESS_SHIFT)

#define TYPE5_CC3_MBREAD_FLAG		0x01
#define TYPE5_CC3_LOCK_FLAG		0x08
#define TYPE5_CC3_SPECIAL_FRAME_FLAG	0x10

#define CMD_FLAG_SUB_CARRIER		0x01
#define CMD_FLAG_DATA_RATE		0x02
#define CMD_FLAG_INVENTORY		0x04
#define CMD_FLAG_PROTOCOL_EXT		0x08
#define CMD_FLAG_SELECT			0x10
#define CMD_FLAG_ADDRESS		0x20
#define CMD_FLAG_OPTION			0x40

#define RESP_FLAG_ERR			0x01
#define RESP_FLAG_EXT			0x08

#define CMD_READ_SINGLE_BLOCK		0x20
#define CMD_WRITE_SINGLE_BLOCK		0x21

struct type5_cmd_hdr {
	uint8_t			flags;
	uint8_t			cmd;
	uint8_t			uid[NFC_MAX_ISO15693_UID_LEN];
} __attribute__((packed));

struct type5_err_resp {
	uint8_t			flags;
	uint8_t			err_code;
} __attribute__((packed));

struct type5_read_single_block_cmd {
	struct type5_cmd_hdr	hdr;
	uint8_t			blk_no;
} __attribute__((packed));

struct type5_read_single_block_resp {
	uint8_t			flags;
	uint8_t			data[0];
} __attribute__((packed));

struct type5_write_single_block_cmd {
	struct type5_cmd_hdr	hdr;
	uint8_t			blk_no;
	uint8_t			data[0];
} __attribute__((packed));

struct type5_write_single_block_resp {
	uint8_t			flags;
} __attribute__((packed));

typedef int (*t5_local_cb)(struct near_tag *tag, int err, void *data);

struct t5_cookie {
	struct near_tag		*tag;
	near_tag_io_cb		cb;
	t5_local_cb		local_cb;
	uint8_t			*local_cb_data;
	uint8_t			*buf;
	struct near_ndef_message *ndef;
	int			src_offset;
	int			dst_offset;
	size_t			bytes_left;
	uint8_t			blk;
};

static int t5_cmd_hdr_init(struct near_tag *tag, struct type5_cmd_hdr *cmd_hdr,
		int cmd)
{
	uint8_t *uid;

	DBG("");

	uid = near_tag_get_iso15693_uid(near_tag_get_adapter_idx(tag),
						near_tag_get_target_idx(tag));
	if (!uid) {
		near_error("No type 5 UID");
		return -EINVAL;
	}

	cmd_hdr->flags = CMD_FLAG_ADDRESS | CMD_FLAG_DATA_RATE;
	cmd_hdr->cmd = cmd;
	memcpy(cmd_hdr->uid, uid, sizeof(cmd_hdr->uid));

	g_free(uid);

	return 0;
}

static int t5_check_resp(uint8_t *resp, int length)
{
	struct type5_err_resp *t5_err_resp =
		(struct type5_err_resp *)(resp + NFC_HEADER_SIZE);
	int err = 0;

	DBG("");

	if (length < 0) {
		near_error("Cmd failure: %d", length);
		err = length;
	} else if (resp[0]) {
		near_error("NFC Failure: 0x%x", resp[0]);
		err = -EIO;
	} else {
		length -= NFC_HEADER_SIZE;

		if (t5_err_resp->flags & RESP_FLAG_ERR) {
			if (length == 2)
				near_error("Tag failure: 0x%x",
						t5_err_resp->err_code);
			else
				near_error("Tag failure: Cause unknown");

			err = -EIO;
		}
	}

	return err;
}

static struct t5_cookie *t5_cookie_alloc(struct near_tag *tag)
{
	struct t5_cookie *cookie;

	cookie = g_try_malloc0(sizeof(*cookie));
	if (!cookie)
		return NULL;

	cookie->tag = tag;

	return cookie;
}

static __attribute__ ((unused)) int t5_cookie_release(int err, void *data)
{
	struct t5_cookie *cookie = data;

	DBG("%p", cookie);

	if (!cookie)
		return err;

	else if (cookie->cb)
		cookie->cb(near_tag_get_adapter_idx(cookie->tag),
				near_tag_get_target_idx(cookie->tag), err);

	if (cookie->ndef) {
		g_free(cookie->ndef->data);
		g_free(cookie->ndef);
	}

	g_free(cookie);

	return err;
}

/*
 * Provide "local" read and write routines that take care of reading
 * or writing 'n' bytes from/to the tag.
 */
static int t5_cookie_release_local(int err, void *data)
{
	struct t5_cookie *cookie = data;

	DBG("%p", cookie);

	if (!cookie)
		return err;

	if (cookie->local_cb)
		cookie->local_cb(cookie->tag, err, cookie->local_cb_data);

	g_free(cookie);

	return err;
}

static int t5_read_resp(uint8_t *resp, int length, void *data)
{
	struct type5_read_single_block_resp *t5_resp =
		(struct type5_read_single_block_resp *)(resp + NFC_HEADER_SIZE);
	struct type5_read_single_block_cmd t5_cmd;
	struct t5_cookie *cookie = data;
	struct near_tag *tag = cookie->tag;
	uint8_t blk_size = near_tag_get_blk_size(tag);
	int err;

	DBG("length: %d", length);

	err = t5_check_resp(resp, length);
	if (err)
		goto out_done;

	length -= NFC_HEADER_SIZE;

	if (length != (int)(sizeof(*t5_resp) + blk_size)) {
		near_error("Read - Invalid response - length: %d", length);
		err = -EIO;
		goto out_done;
	}

	length = blk_size - cookie->src_offset;
	length = MIN(length, (int)cookie->bytes_left);

	memcpy(&cookie->buf[cookie->dst_offset],
			&t5_resp->data[cookie->src_offset], length);

	if (cookie->bytes_left <= blk_size)
		goto out_done;

	cookie->bytes_left -= length;
	cookie->src_offset = 0;
	cookie->dst_offset += length;
	cookie->blk++;

	err = t5_cmd_hdr_init(tag, &t5_cmd.hdr, CMD_READ_SINGLE_BLOCK);
	if (err)
		goto out_done;

	t5_cmd.blk_no = cookie->blk;

	return near_adapter_send(near_tag_get_adapter_idx(tag),
			(uint8_t *)&t5_cmd, sizeof(t5_cmd), t5_read_resp,
			cookie, t5_cookie_release_local);

out_done:
	DBG("Done reading: %d", err);

	return t5_cookie_release_local(err, cookie);
}

static __attribute__ ((unused))
int t5_read(struct near_tag *tag, uint8_t offset, uint8_t *buf,
		size_t len, t5_local_cb local_cb, void *local_data)
{
	struct type5_read_single_block_cmd t5_cmd;
	struct t5_cookie *cookie = local_data;
	uint8_t blk_size = near_tag_get_blk_size(tag);
	int err;

	DBG("Reading %zd bytes starting at offset %d\n", len, offset);

	err = t5_cmd_hdr_init(tag, &t5_cmd.hdr, CMD_READ_SINGLE_BLOCK);
	if (err)
		return err;

	t5_cmd.blk_no = offset / blk_size;

	cookie = t5_cookie_alloc(tag);
	if (!cookie)
		return -ENOMEM;

	cookie->local_cb = local_cb;
	cookie->local_cb_data = local_data;
	cookie->buf = buf;
	cookie->src_offset = offset - (t5_cmd.blk_no * blk_size);
	cookie->dst_offset = 0;
	cookie->bytes_left = len;
	cookie->blk = t5_cmd.blk_no;

	return near_adapter_send(near_tag_get_adapter_idx(tag),
			(uint8_t *)&t5_cmd, sizeof(t5_cmd), t5_read_resp,
			cookie, t5_cookie_release_local);
}

static int t5_write_resp(uint8_t *resp, int length, void *data)
{
	struct type5_write_single_block_resp *t5_resp =
		(struct type5_write_single_block_resp *)
			(resp + NFC_HEADER_SIZE);
	struct type5_write_single_block_cmd *t5_cmd = NULL;
	struct t5_cookie *cookie = data;
	struct near_tag *tag = cookie->tag;
	uint8_t blk_size = near_tag_get_blk_size(tag);
	int err;

	DBG("length: %d", length);

	err = t5_check_resp(resp, length);
	if (err)
		goto out_done;

	length -= NFC_HEADER_SIZE;

	if (length != sizeof(*t5_resp)) {
		near_error("Wrte - Invalid response - length: %d", length);
		err = -EIO;
		goto out_done;
	}

	if (cookie->bytes_left <= blk_size)
		goto out_done;

	cookie->bytes_left -= blk_size;
	cookie->src_offset += blk_size;
	cookie->blk++;

	t5_cmd = g_try_malloc0(sizeof(*t5_cmd) + blk_size);
	if (!t5_cmd) {
		err = -ENOMEM;
		goto out_done;
	}

	err = t5_cmd_hdr_init(tag, &t5_cmd->hdr,
				CMD_WRITE_SINGLE_BLOCK);
	if (err)
		goto out_done;

	t5_cmd->hdr.flags |= CMD_FLAG_OPTION;

	t5_cmd->blk_no = cookie->blk;
	memcpy(t5_cmd->data, &cookie->buf[cookie->src_offset], blk_size);

	err = near_adapter_send(near_tag_get_adapter_idx(tag),
			(uint8_t *)t5_cmd, sizeof(*t5_cmd) + blk_size,
			t5_write_resp, cookie, t5_cookie_release_local);

	g_free(t5_cmd);
	return err;

out_done:
	DBG("Done writing: %d", err);

	if (t5_cmd)
		g_free(t5_cmd);

	return t5_cookie_release_local(err, cookie);
}

static int __attribute__ ((unused))
t5_write(struct near_tag *tag, uint8_t offset, uint8_t *buf,
		size_t len, t5_local_cb local_cb, void *local_data)
{
	struct type5_write_single_block_cmd *t5_cmd;
	struct t5_cookie *cookie = local_data;
	uint8_t blk_size = near_tag_get_blk_size(tag);
	int err;

	DBG("Writing %zd bytes starting at offset %d\n", len, offset);

	if (offset % blk_size) {
		near_error("Write - Invalid offset - offset: %d, blk_size: %d",
				offset, blk_size);
		return -EINVAL;
	}

	t5_cmd = g_try_malloc0(sizeof(*t5_cmd) + blk_size);
	if (!t5_cmd)
		return -ENOMEM;

	err = t5_cmd_hdr_init(tag, &t5_cmd->hdr, CMD_WRITE_SINGLE_BLOCK);
	if (err)
		goto out_err;

	/*
	 * According to the Note under Table 1-1 in section 1.6
	 * of http://www.ti.com/lit/ug/scbu011/scbu011.pdf, TI Tag-it
	 * HF-I transponders only work correctly when the option bit
	 * is set on write and lock commands.  To ensure that writes to
	 * those tags work, always enable the OPTION flag.
	 */
	t5_cmd->hdr.flags |= CMD_FLAG_OPTION;

	t5_cmd->blk_no = offset / blk_size;
	memcpy(t5_cmd->data, buf, blk_size);

	cookie = t5_cookie_alloc(tag);
	if (!cookie) {
		err = -ENOMEM;
		goto out_err;
	}

	cookie->local_cb = local_cb;
	cookie->local_cb_data = local_data;
	cookie->buf = buf;
	cookie->src_offset = 0;
	cookie->bytes_left = len;
	cookie->blk = t5_cmd->blk_no;

	err = near_adapter_send(near_tag_get_adapter_idx(tag),
			(uint8_t *)t5_cmd, sizeof(*t5_cmd) + blk_size,
			t5_write_resp, cookie, t5_cookie_release_local);

out_err:
	g_free(t5_cmd);
	return err;
}

static struct near_tag_driver type5_driver = {
	.type		= NFC_PROTO_ISO15693,
	.priority	= NEAR_TAG_PRIORITY_DEFAULT,
};

static int nfctype5_init(void)
{
	DBG("");

	return near_tag_driver_register(&type5_driver);
}

static void nfctype5_exit(void)
{
	DBG("");

	near_tag_driver_unregister(&type5_driver);
}

NEAR_PLUGIN_DEFINE(nfctype5, "ISO 15693 (NFC Type 5) tags support", VERSION,
			NEAR_PLUGIN_PRIORITY_HIGH, nfctype5_init, nfctype5_exit)

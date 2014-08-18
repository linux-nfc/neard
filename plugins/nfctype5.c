/*
 *  NFC Type 5 (ISO 15693) Tag code
 *
 *  Copyright (C) 2014 Marvell International Ltd.
 *  Copyright (C) 2013 Animal Creek Technologies, Inc. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */
/*
 * Currently only single block writes are used for I/O.
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
#define CMD_READ_MULITPLE_BLOCKS	0x23
#define CMD_GET_SYSTEM_INFO		0x2b

#define GET_SYS_INFO_FLAG_DSFID		0x01
#define GET_SYS_INFO_FLAG_AFI		0x02
#define GET_SYS_INFO_FLAG_MEM_SIZE	0x04
#define GET_SYS_INFO_FLAG_IC_REF	0x08
#define GET_SYS_INFO_FLAG_16B_NB_BLOCK	0x10

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

struct type5_read_multiple_blocks_cmd {
	struct type5_cmd_hdr	hdr;
	uint8_t			blk_no;
	uint8_t			num_blks;
} __attribute__((packed));

struct type5_read_multiple_blocks_resp {
	uint8_t			flags;
	uint8_t			data[0];
} __attribute__((packed));

struct type5_get_system_info_cmd {
	struct type5_cmd_hdr	hdr;
} __attribute__((packed));

struct type5_get_system_info_resp {
	uint8_t			flags;
	uint8_t			info_flags;
	uint8_t			uid[NFC_MAX_ISO15693_UID_LEN];
	uint8_t			data[0];
} __attribute__((packed));

struct type5_cc {
	uint8_t			cc0;
	uint8_t			cc1;
	uint8_t			cc2;
	uint8_t			cc3;
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
	uint8_t			nb_requested_blocks;
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

static int t5_cookie_release(int err, void *data)
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

static int t5_read(struct near_tag *tag, uint8_t offset, uint8_t *buf,
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

static int t5_write(struct near_tag *tag, uint8_t offset, uint8_t *buf,
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

/*
 * The remaining routines implement the read, write, check_presence,
 * and format plugin hooks
 */
static int t5_read_data_resp(struct near_tag *tag, int err, void *data)
{
	struct t5_cookie *cookie = data;
	size_t data_length;
	uint8_t *nfc_data;
	GList *records;

	DBG("");

	if (err)
		goto out_err;

	nfc_data = near_tag_get_data(tag, &data_length);
	if (!nfc_data) {
		err = -ENOMEM;
		goto out_err;
	}

	records = near_tlv_parse(nfc_data, data_length);
	near_tag_add_records(tag, records, NULL, 0);

out_err:
	return t5_cookie_release(err, cookie);
}

static bool t5_cc_is_valid(struct type5_cc *t5_cc)
{
	bool valid = false;

	if ((t5_cc->cc0 == TYPE5_CC0_NDEF_MAGIC) &&
			(TYPE5_CC1_VER_GET_MAJOR(t5_cc->cc1) ==
				 TYPE5_VERSION_MAJOR) &&
			(TYPE5_CC1_VER_GET_MINOR(t5_cc->cc1) ==
				 TYPE5_VERSION_MINOR))
		valid = true;

	return valid;
}

static size_t t5_cc_get_data_length(struct type5_cc *t5_cc)
{
	return t5_cc->cc2 * 8;
}

static bool t5_cc_is_read_only(struct type5_cc *t5_cc)
{
	return (t5_cc->cc1 & TYPE5_CC1_WRITE_ACCESS_MASK) !=
		TYPE5_CC1_WRITE_ACCESS_ALWAYS;
}

static int t5_read_multiple_blocks_resp(uint8_t *resp, int length, void *data)
{
	struct type5_read_multiple_blocks_resp *t5_resp =
		(struct type5_read_multiple_blocks_resp *)
					(resp + NFC_HEADER_SIZE);
	struct t5_cookie *cookie = data;
	struct near_tag *tag = cookie->tag;
	uint8_t blk_size = near_tag_get_blk_size(tag);
	size_t data_length;
	GList *records;
	int err;

	DBG("");

	cookie->buf = near_tag_get_data(tag, &data_length);

	err = t5_check_resp(resp, length);
	if (err)
		goto out_done;

	length -= NFC_HEADER_SIZE;

	if (length != (int)(sizeof(*t5_resp) +
			    (cookie->nb_requested_blocks * blk_size))) {
		err = -EIO;
		goto out_done;
	}

	/* Copy length - 2 bytes (-2 because of RMB header) */
	memcpy(cookie->buf, t5_resp->data, length - 2);

	records = near_tlv_parse(cookie->buf, data_length);
	near_tag_add_records(tag, records, NULL, 0);

out_done:
	return t5_cookie_release(err, cookie);
}

static int t5_read_multiple_blocks(struct near_tag *tag,
				   uint8_t starting_block,
				   uint8_t number_of_blocks,
				   near_recv rx_cb,
				   struct t5_cookie *cookie)
{
	struct type5_read_multiple_blocks_cmd t5_cmd;
	int err;

	DBG("");

	err = t5_cmd_hdr_init(tag, &t5_cmd.hdr, CMD_READ_MULITPLE_BLOCKS);
	if (err)
		return err;

	t5_cmd.blk_no = starting_block;
	t5_cmd.num_blks = number_of_blocks - 1;

	return near_adapter_send(near_tag_get_adapter_idx(tag),
			(uint8_t *)&t5_cmd, sizeof(t5_cmd),
                        rx_cb, cookie, t5_cookie_release);
}

static int t5_read_meta_resp(struct near_tag *tag, int err, void *data)
{
	struct t5_cookie *cookie = data;
	struct type5_cc *t5_cc;
	size_t data_length;
	uint8_t *tag_data;
	uint16_t first_block;
	int rmb_supported;

	DBG("");

	if (err)
		goto out_err;

	t5_cc = (struct type5_cc *)cookie->buf;

	if (t5_cc_is_valid(t5_cc)) {
		data_length = t5_cc_get_data_length(t5_cc) -
			TYPE5_DATA_START_OFFSET(tag);

		err = near_tag_add_data(near_tag_get_adapter_idx(tag),
				near_tag_get_target_idx(tag), NULL,
				data_length);
		if (err)
			goto out_err;

		tag_data = near_tag_get_data(tag, &data_length);
		if (!tag_data) {
			err = -EIO;
			goto out_err;
		}

		near_tag_set_blank(tag, FALSE);

		if (t5_cc_is_read_only(t5_cc))
			near_tag_set_ro(tag, TRUE);
		else
			near_tag_set_ro(tag, FALSE);

		rmb_supported = t5_cc->cc3 & TYPE5_CC3_MBREAD_FLAG;

		g_free(cookie->buf);

		if (rmb_supported) {
			first_block = TYPE5_DATA_START_OFFSET(tag) /
				near_tag_get_blk_size(tag);
			cookie->nb_requested_blocks =
				near_tag_get_num_blks(tag) - first_block;
			err = t5_read_multiple_blocks(tag, first_block,
					cookie->nb_requested_blocks,
					t5_read_multiple_blocks_resp,
					cookie);
		} else {
			err = t5_read(tag, TYPE5_DATA_START_OFFSET(tag),
				      tag_data, data_length, t5_read_data_resp,
				      cookie);
		}

		if (err < 0)
			err = t5_cookie_release(err, cookie);

		return err;
	} else {
		DBG("Mark as blank tag");
		near_tag_set_blank(tag, TRUE);
	}

out_err:
	g_free(cookie->buf);
	return t5_cookie_release(err, cookie);
}

static int t5_read_meta(struct near_tag *tag, struct t5_cookie *cookie)
{
	uint8_t *buf;
	int err;

	DBG("");

	buf = g_try_malloc0(TYPE5_LEN_CC_BYTES);
	if (!buf)
		return -ENOMEM;

	cookie->buf = buf;

	err = t5_read(tag, TYPE5_META_START_OFFSET, buf, TYPE5_LEN_CC_BYTES,
			t5_read_meta_resp, cookie);
	if (err < 0)
		g_free(buf);

	return err;
}

static int t5_get_sys_info_resp(uint8_t *resp, int length, void *data)
{
	struct type5_get_system_info_resp *t5_resp =
		(struct type5_get_system_info_resp *)(resp + NFC_HEADER_SIZE);
	struct t5_cookie *cookie = data;
	struct near_tag *tag = cookie->tag;
	uint8_t offset = 0;
	int err;

	DBG("length: %d", length);

	err = t5_check_resp(resp, length);
	if (err)
		goto out_err;

	length -= NFC_HEADER_SIZE;

	if (length < (int)sizeof(*t5_resp)) {
		near_error("Get System Info - Invalid response - length: %d",
				length);
		err = -EIO;
		goto out_err;
	}

	if (t5_resp->info_flags & GET_SYS_INFO_FLAG_DSFID)
		offset++;

	if (t5_resp->info_flags & GET_SYS_INFO_FLAG_AFI)
		offset++;

	if (t5_resp->info_flags & GET_SYS_INFO_FLAG_MEM_SIZE) {
		if (t5_resp->info_flags & GET_SYS_INFO_FLAG_16B_NB_BLOCK) {
			near_tag_set_num_blks(tag, (t5_resp->data[offset] |
				(t5_resp->data[offset + 1] << 8)) + 1);
			offset += 2;
		} else
			near_tag_set_num_blks(tag, t5_resp->data[offset++] + 1);
		near_tag_set_blk_size(tag,
			(t5_resp->data[offset++] & 0x1f) + 1);
	} else { /* Tag must provide memory size info */
		err = -EIO;
		goto out_err;
	}

	err = t5_read_meta(tag, cookie);

out_err:
	if (err < 0)
		err = t5_cookie_release(err, cookie);

	return err;
}

static int t5_get_sys_info(struct near_tag *tag, struct t5_cookie *cookie)
{
	struct type5_get_system_info_cmd t5_cmd;
	int err;

	DBG("");

	err = t5_cmd_hdr_init(tag, &t5_cmd.hdr, CMD_GET_SYSTEM_INFO);
	if (err)
		return err;

	return near_adapter_send(near_tag_get_adapter_idx(tag),
			(uint8_t *)&t5_cmd, sizeof(t5_cmd),
			t5_get_sys_info_resp, cookie, NULL);
}

static int nfctype5_read(uint32_t adapter_idx, uint32_t target_idx,
		near_tag_io_cb cb)
{
	struct t5_cookie *cookie;
	struct near_tag *tag;
	int err;

	DBG("");

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag) {
		err = -EINVAL;
		goto out_err;
	}

	cookie = t5_cookie_alloc(tag);
	if (!cookie) {
		err = -ENOMEM;
		goto out_err;
	}

	cookie->cb = cb;

	/*
	 * Only need to call t5_get_sys_info() to get the blk_size and
	 * num_blks once.  near_tag_get_blk_size() will return 0 if
	 * t5_get_sys_info() hasn't been called yet.
	 */
	if (near_tag_get_blk_size(tag))
		err = t5_read_meta(tag, cookie);
	else
		err = t5_get_sys_info(tag, cookie);

	if (err < 0)
		err = t5_cookie_release(err, cookie);

	return err;

out_err:
	if (cb)
		cb(adapter_idx, target_idx, err);

	return err;
}

static int nfctype5_write_resp(struct near_tag *tag, int err, void *data)
{
	struct t5_cookie *cookie = data;

	DBG("");

	return t5_cookie_release(err, cookie);
}

static int nfctype5_write(uint32_t adapter_idx, uint32_t target_idx,
		struct near_ndef_message *ndef, near_tag_io_cb cb)
{
	struct t5_cookie *cookie;
	struct near_tag *tag;
	int err;

	DBG("");

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag) {
		err = -EINVAL;
		goto out_err;
	}

	cookie = t5_cookie_alloc(tag);
	if (!cookie) {
		err = -ENOMEM;
		goto out_err;
	}

	cookie->cb = cb;
	cookie->ndef = ndef;

	err = t5_write(tag, TYPE5_DATA_START_OFFSET(tag),
			ndef->data + ndef->offset, ndef->length,
			nfctype5_write_resp, cookie);
	if (err < 0)
		err = t5_cookie_release(err, cookie);

	return err;

out_err:
	if (cb)
		cb(adapter_idx, target_idx, err);

	return err;
}

static int nfctype5_check_presence_resp(struct near_tag *tag, int err,
		void *data)
{
	struct t5_cookie *cookie = data;

	DBG("err: %d", err);

	g_free(cookie->buf);

	return t5_cookie_release(err, cookie);
}

static int nfctype5_check_presence(uint32_t adapter_idx, uint32_t target_idx,
		near_tag_io_cb cb)
{
	struct t5_cookie *cookie;
	struct near_tag *tag;
	uint8_t *buf;
	int err;

	DBG("");

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag) {
		err = -EINVAL;
		goto out_err;
	}

	cookie = t5_cookie_alloc(tag);
	if (!cookie) {
		err = -ENOMEM;
		goto out_err;
	}

	cookie->cb = cb;

	buf = g_try_malloc0(1);
	if (!buf) {
		err = -ENOMEM;
		return t5_cookie_release(err, cookie);
	}

	cookie->buf = buf;

	err = t5_read(tag, 0, buf, 1, nfctype5_check_presence_resp, cookie);
	if (err < 0) {
		g_free(buf);
		err = t5_cookie_release(err, cookie);
	}

	return err;

out_err:
	if (cb)
		cb(adapter_idx, target_idx, err);

	return err;
}

static int nfctype5_format_resp(struct near_tag *tag, int err, void *data)
{
	struct t5_cookie *cookie = data;

	DBG("");

	if (!err) {
		DBG("Done formatting");
		near_tag_set_blank(tag, FALSE);
	} else {
		near_error("Format Failed");
	}

	return t5_cookie_release(err, cookie);
}

static int t5_format_read_multiple_blocks_resp(uint8_t *resp, int length,
						void *data)
{
	struct type5_read_multiple_blocks_resp *t5_resp =
		(struct type5_read_multiple_blocks_resp *)
					(resp + NFC_HEADER_SIZE);
	struct t5_cookie *cookie = data;
	struct type5_cc t5_cc;
	struct near_tag *tag = cookie->tag;
	uint8_t blk_size = near_tag_get_blk_size(tag);
	size_t mem_size;
	bool read_multiple_supported = false;
	int err;

	DBG("");

	err = t5_check_resp(resp, length);
	if (!err) {
		length -= NFC_HEADER_SIZE;

		if (length == (int)(sizeof(*t5_resp) + (2 * blk_size)))
			read_multiple_supported = true;
	}

	t5_cc.cc0 = TYPE5_CC0_NDEF_MAGIC;

	t5_cc.cc1 = TYPE5_VERSION_MAJOR << TYPE5_CC1_VER_MAJOR_SHIFT;
	t5_cc.cc1 |= TYPE5_VERSION_MINOR << TYPE5_CC1_VER_MINOR_SHIFT;
	t5_cc.cc1 |= TYPE5_CC1_READ_ACCESS_ALWAYS;

	/*
	 * Assume that the tag is *not* read only because if it is, the tag
	 * would have to be formatted already and we wouldn't be here.
	 * Besides, if it is read only then the write below will fail and
	 * the CC won't be changed anyway.
	 */
	t5_cc.cc1 |= TYPE5_CC1_WRITE_ACCESS_ALWAYS;

	mem_size = blk_size * near_tag_get_num_blks(tag);
	mem_size = MIN(mem_size, TYPE5_MAX_MEM_SIZE);

	t5_cc.cc2 = mem_size / 8;

	/*
	 * We cannot set the lock flag in CC3.  The reason is that to know
	 * if LOCK operations are supported, we'd have to perform one.
	 * But performing one will permanently LOCK that block so instead
	 * just say that its not supported.  We also don't know whether
	 * the tag needs a special frame format so just say "no" for that
	 * one too.  If it does, we probably can't write to the tag anyway.
	 */
	t5_cc.cc3 = 0;

	if (read_multiple_supported)
		t5_cc.cc3 |= TYPE5_CC3_MBREAD_FLAG;

	err = t5_write(tag, TYPE5_META_START_OFFSET, (uint8_t *)&t5_cc,
			sizeof(t5_cc), nfctype5_format_resp, cookie);
	if (err < 0)
		err = t5_cookie_release(err, cookie);

	return err;
}

static int nfctype5_format(uint32_t adapter_idx, uint32_t target_idx,
		near_tag_io_cb cb)
{
	struct t5_cookie *cookie;
	struct near_tag *tag;
	int err;

	DBG("");

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag) {
		err = -EINVAL;
		goto out_err;
	}

	cookie = t5_cookie_alloc(tag);
	if (!cookie) {
		err = -ENOMEM;
		goto out_err;
	}

	cookie->cb = cb;

	return t5_read_multiple_blocks(tag, 0, 2,
				       t5_format_read_multiple_blocks_resp,
				       cookie);

out_err:
	if (cb)
		cb(adapter_idx, target_idx, err);

	return err;
}

static struct near_tag_driver type5_driver = {
	.type		= NFC_PROTO_ISO15693,
	.priority	= NEAR_TAG_PRIORITY_DEFAULT,
	.read		= nfctype5_read,
	.write		= nfctype5_write,
	.check_presence = nfctype5_check_presence,
	.format		= nfctype5_format,
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

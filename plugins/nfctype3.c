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

#define CMD_POLL		0x00
#define RESP_POLL		0x01

#define	CMD_REQUEST_SERVICE	0x02
#define	RESP_REQUEST_SERVICE	0x03

#define CMD_REQUEST_RESPONSE	0x04
#define RESP_REQUEST_RESPONSE	0x05

#define CMD_READ_WO_ENCRYPT	0x06
#define RESP_READ_WO_ENCRYPT	0x07

#define CMD_WRITE_WO_ENCRYPT	0x08
#define RESP_WRITE_WO_ENCRYPT	0x09

#define CMD_REQUEST_SYS_CODE	0x0C
#define RESP_REQUEST_SYS_CODE	0x0D

#define CMD_AUTHENTICATION_1	0x10
#define RESP_AUTHENTICATION_1	0x11

#define CMD_AUTHENTICATION_2	0x12
#define RESP_AUTHENTICATION_2	0x13

#define CMD_READ		0x14
#define RESP_READ		0x15

#define CMD_WRITE		0x16
#define RESP_WRITE		0x17

#define NFC_SERVICE_CODE	0x000B
#define BLOCK_SIZE		16
#define META_BLOCK_START	0
#define DATA_BLOCK_START 	1

#define LEN_ID			0x08
#define LEN_CMD			0x01
#define LEN_REPLY_CMD	        0x02
#define LEN_CMD_LEN		0x01

/* offsets */
#define OFS_NFC_STATUS	0
#define OFS_NFC_LEN	1
#define OFS_CMD_RESP	2
#define OFS_IDM		3
#define OFS_CMD_DATA	(LEN_CMD_LEN + LEN_CMD + LEN_ID)
#define OFS_READ_FLAG	12
#define OFS_READ_DATA	14
#define BLOCK_SIZE	16
#define CHECKSUM_LEN	2

#define MAX_DATA_SIZE	254

#define NDEF_MAPPING_VERSION	0x10
#define MAX_READ_BLOCKS_PER_CHECK	0x04
#define MAX_WRITE_BLOCKS_PER_UPDATE	0x01
#define MAX_BLOCKS_FOR_NDEF_DATA	0x000D
#define ATTR_BLOCK_WRITE_FLAG	0x00
#define ATTR_BLOCK_RW_FLAG	0x01

#define IC_TYPE_OFFSET	12
#define SYSTEM_OPTION_OFFSET	17
#define FELICA_LITE_MC_BLOCK	0x88
#define FELICA_LITE_IC_TYPE	0xF0
#define FELICA_LITE_S_IC_TYPE	0xF1
#define FELICA_PLUG_IC_TYPE	0xE0

#define FELICA_LITE_AND_LITE_S_SYS_CODE	0x88B4

struct type3_cmd {
	uint8_t len;
	uint8_t cmd;
	uint8_t data[MAX_DATA_SIZE];
} __attribute__((packed));

struct type3_tag {
	uint32_t adapter_idx;
	uint16_t current_block;
	uint8_t IDm[LEN_ID];

	near_tag_io_cb cb;
	struct near_tag *tag;
};

struct t3_cookie {
	uint32_t adapter_idx;
	uint32_t target_idx;
	near_tag_io_cb cb;
	uint8_t IDm[LEN_ID];
	uint8_t current_block;
	uint8_t attr[BLOCK_SIZE];
	struct near_ndef_message *ndef;
	uint8_t ic_type;
	uint8_t mc_block[BLOCK_SIZE];
};

static int t3_cookie_release(int err, void *data)
{
	struct t3_cookie *cookie = data;

	DBG("%p", cookie);

	if (!cookie)
		return err;

	if (cookie->cb)
		cookie->cb(cookie->adapter_idx, cookie->target_idx, err);

	if (cookie->ndef)
		g_free(cookie->ndef->data);

	g_free(cookie->ndef);
	g_free(cookie);
	cookie = NULL;

	return err;
}

/* common: Initialize structure to write block */
static void prepare_write_block(uint8_t *UID, struct type3_cmd *cmd,
					uint8_t block, uint8_t *data)
{
	cmd->cmd = CMD_WRITE_WO_ENCRYPT;	/* command */
	memcpy(cmd->data, UID, LEN_ID);		/* IDm */

	cmd->data[LEN_ID] = 1;			/* number of services */
	cmd->data[LEN_ID + 1] = 0x09;		/* service 0x0009 */
	cmd->data[LEN_ID + 2] = 0x00;

	cmd->data[LEN_ID + 3] = 0x01;		/* number of blocks */
	cmd->data[LEN_ID + 4] = 0x80;		/* 2 byte block number format */
	cmd->data[LEN_ID + 5] = block;		/* block number */
	memcpy(cmd->data + LEN_ID + 6, data, BLOCK_SIZE); /* data to write */

	cmd->len = LEN_ID + LEN_CMD + LEN_CMD_LEN + 6 + BLOCK_SIZE;
}

/* common: Initialize structure to read block */
static void prepare_read_block(uint8_t cur_block,
				uint8_t *UID,
				struct type3_cmd *cmd)
{
	cmd->cmd = CMD_READ_WO_ENCRYPT;			/* command */
	memcpy(cmd->data, UID, LEN_ID);			/* IDm */

	cmd->data[LEN_ID] = 1;				/* number of service */
	cmd->data[LEN_ID + 1] = 0x0B;			/* service x000B */
	cmd->data[LEN_ID + 2] = 0x00;

	cmd->data[LEN_ID + 3] = 0x01;			/* number of block */
	cmd->data[LEN_ID + 4] = 0x80;			/* 2 bytes block id*/
	cmd->data[LEN_ID + 5] = cur_block;		/* block number */

	cmd->len = LEN_ID + LEN_CMD + LEN_CMD_LEN + 6;
}

/* common: Simple checks on received frame */
static int check_recv_frame(uint8_t *resp, uint8_t reply_code)
{
	if (resp[OFS_NFC_STATUS] != 0) {
		DBG("NFC Command failed: 0x%x", resp[OFS_NFC_STATUS]);
		return -EIO;
	}

	if (resp[OFS_CMD_RESP] != reply_code) {
		DBG("Felica cmd failed: 0x%x", resp[OFS_CMD_RESP]);
		return -EIO;
	}

	return 0;
}

static int data_recv(uint8_t *resp, int length, void *data)
{
	struct type3_tag *tag = data;
	struct type3_cmd cmd;
	uint8_t *nfc_data;
	size_t current_length, length_read, data_length;
	uint32_t adapter_idx;
	uint32_t target_idx;
	int read_blocks;
	int err;

	DBG("%d", length);

	adapter_idx = near_tag_get_adapter_idx(tag->tag);
	target_idx = near_tag_get_target_idx(tag->tag);

	if (length < 0) {
		err = -EIO;
		goto out_err;
	}

	nfc_data = near_tag_get_data(tag->tag, &data_length);
	length_read = length - OFS_READ_DATA;
	current_length = tag->current_block * BLOCK_SIZE;
	if (current_length + (length - OFS_READ_DATA) > data_length)
		length_read = data_length - current_length;

	memcpy(nfc_data + current_length, resp + OFS_READ_DATA, length_read);

	if (current_length + length_read >= data_length) {
		GList *records;

		tag->current_block = 0;

		DBG("Done reading %zd bytes at %p", data_length, nfc_data);
		records = near_ndef_parse_msg(nfc_data, data_length, NULL);
		near_tag_add_records(tag->tag, records, tag->cb, 0);

		g_free(tag);

		return 0;
	}

	/* Read the next block */
	read_blocks = length / BLOCK_SIZE;
	tag->current_block += read_blocks;

	prepare_read_block(DATA_BLOCK_START + tag->current_block,
				tag->IDm, &cmd);

	err = near_adapter_send(adapter_idx, (uint8_t *) &cmd, cmd.len,
				data_recv, tag, NULL);

	if (err < 0)
		goto out_err;

	return 0;

out_err:
	if (err < 0 && tag->cb)
		tag->cb(adapter_idx, target_idx, err);

	g_free(tag);

	return err;
}

static int data_read(struct type3_tag *tag)
{
	struct type3_cmd cmd;
	uint32_t adapter_idx;

	DBG("");

	tag->current_block = 0;

	prepare_read_block(DATA_BLOCK_START + tag->current_block,
							tag->IDm, &cmd);

	adapter_idx = near_tag_get_adapter_idx(tag->tag);

	return near_adapter_send(adapter_idx,
					(uint8_t *) &cmd, cmd.len,
					data_recv, tag, NULL);
}

/* Read block 0 to retrieve the data length */
static int nfctype3_recv_block_0(uint8_t *resp, int length, void *data)
{
	struct t3_cookie *cookie = data;
	int err = 0;
	struct near_tag *tag;
	struct type3_tag *t3_tag = NULL;
	uint32_t ndef_data_length;

	DBG("%d", length);

	if (length < 0) {
		err = -EIO;
		goto out_err;
	}

	err = check_recv_frame(resp, RESP_READ_WO_ENCRYPT);
	if (err < 0)
		goto out_err;

	if (resp[OFS_READ_FLAG] != 0) {
		DBG("Status 0x%x", resp[OFS_READ_FLAG]);
		err = -EIO;
		goto out_err;
	}

	/* Block 0:[11 - 13]: length is a 3 bytes value */
	ndef_data_length =  resp[OFS_READ_DATA + 11] * 0x100;
	ndef_data_length += resp[OFS_READ_DATA + 12];
	ndef_data_length *= 0x100;
	ndef_data_length += resp[OFS_READ_DATA + 13];

	/* Add data to the tag */
	err = near_tag_add_data(cookie->adapter_idx, cookie->target_idx,
					NULL, ndef_data_length);
	if (err < 0)
		goto out_err;

	tag = near_tag_get_tag(cookie->adapter_idx, cookie->target_idx);
	if (!tag) {
		err = -ENOMEM;
		goto out_err;
	}

	/* Block 0:[10]: RW Flag. 1 for RW */
	if (resp[OFS_READ_DATA + 10] == 0)
		near_tag_set_ro(tag, TRUE);
	else
		near_tag_set_ro(tag, FALSE);

	t3_tag = g_try_malloc0(sizeof(struct type3_tag));
	if (!t3_tag) {
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(t3_tag->IDm, cookie->IDm, LEN_ID);

	near_tag_set_idm(tag, cookie->IDm, LEN_ID);
	near_tag_set_attr_block(tag, resp + OFS_READ_DATA, BLOCK_SIZE);
	near_tag_set_blank(tag, FALSE);
	near_tag_set_ic_type(tag, cookie->ic_type);

	t3_tag->adapter_idx = cookie->adapter_idx;
	t3_tag->cb = cookie->cb;
	t3_tag->tag = tag;

	err = data_read(t3_tag);

	/*
	 * As reading isn't complete,
	 * callback shouldn't be called while freeing the cookie
	 */
	if (err >= 0)
		cookie->cb = NULL;

out_err:
	if (err < 0)
		g_free(t3_tag);

	return t3_cookie_release(err, cookie);
}

static int poll_ndef_system_code(uint8_t *resp, int length, void *data)
{
	struct t3_cookie *cookie = data;
	int err = 0;
	struct type3_cmd cmd;

	DBG("length: %d", length);

	if (length < 0) {
		err = -EIO;
		goto out_err;
	}

	err = check_recv_frame(resp, RESP_POLL);
	if (err < 0)
		goto out_err;

	prepare_read_block(META_BLOCK_START, cookie->IDm, &cmd);

	err = near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd,
				cmd.len, nfctype3_recv_block_0, cookie, NULL);
	if (err < 0)
		goto out_err;

	return 0;

out_err:
	return t3_cookie_release(err, cookie);
}

static int check_sys_op_in_mc_block(uint8_t *resp, int length, void *data)
{
	struct type3_cmd cmd;
	struct near_tag *tag;
	struct t3_cookie *cookie = data;
	int err = 0;

	DBG("length %d", length);

	if (length < 0) {
		err = -EIO;
		goto out_err;
	}

	err = check_recv_frame(resp, RESP_READ_WO_ENCRYPT);
	if (err < 0)
		goto out_err;

	if (resp[SYSTEM_OPTION_OFFSET] == 0x00) {
		DBG("Blank tag detected");

		err = near_tag_add_data(cookie->adapter_idx,
					cookie->target_idx,
					NULL, 1 /* dummy length */);
		if (err < 0)
			goto out_err;

		tag = near_tag_get_tag(cookie->adapter_idx,
					cookie->target_idx);
		if (!tag) {
			err = -ENOMEM;
		goto out_err;
		}

		near_tag_set_idm(tag, cookie->IDm, LEN_ID);
		near_tag_set_ic_type(tag, cookie->ic_type);
		near_tag_set_blank(tag, TRUE);

		return t3_cookie_release(0, cookie);
	} else {
		/* CMD POLL */
		cmd.cmd	 = CMD_POLL;	/* POLL command */
		cmd.data[0] = 0x12;     /* System code (NFC SC) */
		cmd.data[1] = 0xFC;
		cmd.data[2] = 01;	/* request code */
		cmd.data[3] = 0x00;	/* time slot */
		/* data len + 2 bytes */
		cmd.len = LEN_CMD + LEN_CMD_LEN + 4 ;

		err = near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd,
			cmd.len , poll_ndef_system_code, cookie, NULL);
	}

	if (err < 0)
		goto out_err;

	return 0;

out_err:
	return t3_cookie_release(err, cookie);
}

static int receive_system_code(uint8_t *resp, int length, void *data)
{
	struct t3_cookie *cookie = data;
	int err = 0;
	struct type3_cmd cmd;

	DBG("length: %d", length);

	if (length < 0) {
		err = -EIO;
		goto out_err;
	}

	err = check_recv_frame(resp, RESP_POLL);
	if (err < 0)
		goto out_err;

	cookie->ic_type = resp[IC_TYPE_OFFSET];
	memcpy(cookie->IDm, resp + OFS_IDM, LEN_ID);

	switch (resp[IC_TYPE_OFFSET]) {
	case FELICA_LITE_IC_TYPE:
		prepare_read_block(FELICA_LITE_MC_BLOCK, cookie->IDm, &cmd);
		err = near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd,
					cmd.len, check_sys_op_in_mc_block,
					cookie, NULL);
		break;

	default:
		/* CMD POLL */
		cmd.cmd	 = CMD_POLL;	/* POLL command */
		cmd.data[0] = 0x12;     /* System code (NFC SC) */
		cmd.data[1] = 0xFC;
		cmd.data[2] = 01;	/* request code */
		cmd.data[3] = 0x00;	/* time slot */
		/* data len + 2 bytes */
		cmd.len = LEN_CMD + LEN_CMD_LEN + 4 ;

		err = near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd,
					cmd.len, poll_ndef_system_code, cookie,
					NULL);
	}

	if (err < 0)
		goto out_err;

	return 0;

out_err:
	return t3_cookie_release(err, cookie);
}

static int nfctype3_read(uint32_t adapter_idx,
				uint32_t target_idx, near_tag_io_cb cb)
{
	struct type3_cmd cmd;
	struct t3_cookie *cookie;

	DBG("");

	/* CMD POLL */
	cmd.cmd	 = CMD_POLL;	/* POLL command */
	cmd.data[0] = 0xFF;     /* System code */
	cmd.data[1] = 0xFF;
	cmd.data[2] = 01;	/* request code */
	cmd.data[3] = 0x00;	/* time slot */

	/* data len + 2 bytes */
	cmd.len = LEN_CMD + LEN_CMD_LEN + 4;

	cookie = g_try_malloc0(sizeof(struct t3_cookie));
	if (!cookie)
		return -ENOMEM;

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;

	return near_adapter_send(adapter_idx, (uint8_t *) &cmd, cmd.len,
					receive_system_code, cookie,
					t3_cookie_release);
}

static int update_attr_block_cb(uint8_t *resp, int length, void *data)
{
	struct t3_cookie *cookie = data;
	int err;

	DBG("");

	if (length < 0) {
		err = -EIO;
		goto out_err;
	}

	err = check_recv_frame(resp, RESP_WRITE_WO_ENCRYPT);
	if (err < 0)
		goto out_err;

	DBG("Done writing");

out_err:
	return t3_cookie_release(err, cookie);
}

static int update_attr_block(struct t3_cookie *cookie)
{
	struct type3_cmd cmd;
	uint16_t checksum;
	uint8_t i;

	DBG("");

	cookie->attr[9] = 0x00; /* writing data completed */
	cookie->attr[11] = (uint8_t) (cookie->ndef->length >> 16);
	cookie->attr[12] = (uint8_t) (cookie->ndef->length >> 8);
	cookie->attr[13] = (uint8_t) cookie->ndef->length;
	checksum = 0;

	for (i = 0; i < (BLOCK_SIZE - CHECKSUM_LEN); i++)
		checksum += cookie->attr[i];

	cookie->attr[14] = (uint8_t) (checksum >> 8);
	cookie->attr[15] = (uint8_t) checksum;

	prepare_write_block(cookie->IDm, &cmd, 0, cookie->attr);

	return near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd, cmd.len,
					update_attr_block_cb, cookie,
					t3_cookie_release);
}

static int data_write_resp(uint8_t *resp, int length, void *data)
{
	struct t3_cookie *cookie = data;
	struct type3_cmd cmd;
	uint8_t padding[BLOCK_SIZE] = {0};
	int err;

	DBG("");

	if (length < 0) {
		err = -EIO;
		goto out_err;
	}

	err = check_recv_frame(resp, RESP_WRITE_WO_ENCRYPT);
	if (err < 0)
		goto out_err;

	if (cookie->ndef->offset >= cookie->ndef->length) {
		err = update_attr_block(cookie);
		if (err < 0)
			goto out_err;

		return 0;
	}

	if ((cookie->ndef->length - cookie->ndef->offset) <
			BLOCK_SIZE) {
		memcpy(padding, cookie->ndef->data + cookie->ndef->offset,
				cookie->ndef->length - cookie->ndef->offset);
		prepare_write_block(cookie->IDm, &cmd,
					cookie->current_block, padding);
	} else {
		prepare_write_block(cookie->IDm, &cmd, cookie->current_block,
				cookie->ndef->data + cookie->ndef->offset);
	}

	cookie->current_block++;
	cookie->ndef->offset += BLOCK_SIZE;

	err = near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd, cmd.len,
						data_write_resp, cookie, NULL);
	if (err < 0)
		goto out_err;

	return 0;

out_err:
	return t3_cookie_release(err, cookie);
}

static int data_write(uint32_t adapter_idx, uint32_t target_idx,
				struct near_ndef_message *ndef,
				struct near_tag *tag,
				near_tag_io_cb cb)
{
	struct t3_cookie *cookie;
	struct type3_cmd cmd;
	uint16_t checksum, nmaxb;
	uint8_t i, len = 0;
	uint8_t *idm, *attr;
	int err;

	DBG("");

	cookie = g_try_malloc0(sizeof(struct t3_cookie));

	if (!cookie) {
		err = -ENOMEM;

		if (cb)
			cb(adapter_idx, target_idx, err);

		return err;
	}

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->ndef = ndef;
	cookie->cb = cb;
	cookie->current_block = 0;

	idm = near_tag_get_idm(tag, &len);
	if (!idm)
		return t3_cookie_release(-EINVAL, cookie);

	memcpy(cookie->IDm, idm, len);

	attr = near_tag_get_attr_block(tag, &len);
	if (!attr)
		return t3_cookie_release(-EINVAL, cookie);

	memcpy(cookie->attr, attr, len);
	nmaxb = (((uint16_t) (cookie->attr[3])) << 8) | cookie->attr[4];

	if (cookie->ndef->length > (nmaxb * BLOCK_SIZE)) {
		near_error("not enough space on tag");

		return t3_cookie_release(-ENOSPC, cookie);
	}

	cookie->attr[9] = 0x0F; /* writing data in progress */
	checksum = 0;

	for (i = 0; i < 14; i++)
		checksum += cookie->attr[i];

	cookie->attr[14] = (uint8_t) (checksum >> 8);
	cookie->attr[15] = (uint8_t) checksum;

	prepare_write_block(cookie->IDm, &cmd, cookie->current_block,
							cookie->attr);
	cookie->current_block++;

	return near_adapter_send(adapter_idx, (uint8_t *) &cmd, cmd.len,
					data_write_resp, cookie,
					t3_cookie_release);
}

static int nfctype3_write(uint32_t adapter_idx, uint32_t target_idx,
				struct near_ndef_message *ndef,
				near_tag_io_cb cb)
{
	struct near_tag *tag;
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

	err = data_write(adapter_idx, target_idx, ndef, tag, cb);

out_err:
	if (cb && err < 0)
		cb(adapter_idx, target_idx, err);

	return err;
}

static int check_presence(uint8_t *resp, int length, void *data)
{
	struct t3_cookie *cookie = data;
	int err = 0;

	DBG("length %d", length);

	if (length < 0)
		err = -EIO;

	return t3_cookie_release(err, cookie);
}

static int nfctype3_check_presence(uint32_t adapter_idx,
				uint32_t target_idx, near_tag_io_cb cb)
{
	struct type3_cmd cmd;
	struct t3_cookie *cookie;

	DBG("");

	/* CMD POLL */
	cmd.cmd	 = CMD_POLL;	/* POLL command */
	cmd.data[0] = 0xFF;     /* System code */
	cmd.data[1] = 0xFF;
	cmd.data[2] = 01;	/* request code */
	cmd.data[3] = 0x00;	/* time slot */

	/* data len + 2 bytes */
	cmd.len = LEN_CMD + LEN_CMD_LEN + 4 ;

	cookie = g_try_malloc0(sizeof(struct t3_cookie));
	if (!cookie)
		return -ENOMEM;

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;

	return near_adapter_send(adapter_idx, (uint8_t *) &cmd,
				cmd.len, check_presence, cookie,
				t3_cookie_release);
}

static int format_resp(uint8_t *resp, int length, void *data)
{
	struct near_tag *tag;
	struct t3_cookie *cookie = data;
	int err;

	DBG("");

	if (length < 0) {
		err = -EIO;
		goto out_err;
	}

	err = check_recv_frame(resp, RESP_WRITE_WO_ENCRYPT);
	if (err < 0)
		goto out_err;

	tag = near_tag_get_tag(cookie->adapter_idx, cookie->target_idx);
	if (!tag) {
		err = -ENOMEM;
		goto out_err;
	}

	near_tag_set_ro(tag, FALSE);
	near_tag_set_idm(tag, cookie->IDm, LEN_ID);
	near_tag_set_attr_block(tag, cookie->attr, BLOCK_SIZE);
	near_tag_set_blank(tag, FALSE);

	DBG("Formatting is done");

out_err:
	return t3_cookie_release(err, cookie);
}

static int write_attr_block(uint8_t *resp, int length , void *data)
{
	struct type3_cmd cmd;
	struct t3_cookie *cookie = data;
	int err, i;
	uint16_t checksum = 0;

	DBG("length %d", length);

	if (length < 0) {
		err = -EIO;
		goto out_err;
	}

	err = check_recv_frame(resp, RESP_WRITE_WO_ENCRYPT);
	if (err < 0)
		goto out_err;

	cookie->attr[0] = NDEF_MAPPING_VERSION;
	cookie->attr[1] = MAX_READ_BLOCKS_PER_CHECK;
	cookie->attr[2] = MAX_WRITE_BLOCKS_PER_UPDATE;
	cookie->attr[3] = (uint8_t) (MAX_BLOCKS_FOR_NDEF_DATA >> 8);
	cookie->attr[4] = (uint8_t) (MAX_BLOCKS_FOR_NDEF_DATA);
	cookie->attr[5] = 0;
	cookie->attr[6] = 0;
	cookie->attr[7] = 0;
	cookie->attr[8] = 0;
	cookie->attr[9] = ATTR_BLOCK_WRITE_FLAG;
	cookie->attr[10] = ATTR_BLOCK_RW_FLAG;
	cookie->attr[11] = 0;
	cookie->attr[12] = 0;
	cookie->attr[13] = 0;

	for (i = 0; i < (BLOCK_SIZE - CHECKSUM_LEN); i++)
		checksum += cookie->attr[i];

	cookie->attr[14] = (uint8_t) (checksum >> 8);
	cookie->attr[15] = (uint8_t) checksum;

	prepare_write_block(cookie->IDm, &cmd, META_BLOCK_START,
						cookie->attr);

	err = near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd,
				cmd.len, format_resp, cookie, NULL);
	if (err < 0)
		goto out_err;

	return 0;

out_err:
	return t3_cookie_release(err, cookie);
}

static int write_mc_block(uint8_t *resp, int length, void *data)
{
	struct type3_cmd cmd;
	struct t3_cookie *cookie = data;
	int err;

	DBG("length %d", length);

	if (length < 0) {
		err = -EIO;
		goto out_err;
	}

	err = check_recv_frame(resp, RESP_READ_WO_ENCRYPT);
	if (err < 0)
		goto out_err;

	if (resp[OFS_READ_FLAG] != 0) {
		DBG("Status 0x%x", resp[OFS_READ_FLAG]);
		err = -EIO;
		goto out_err;
	}

	memcpy(cookie->mc_block, resp + 14, BLOCK_SIZE);
	/*
	 * By updating Byte3 to 01h means making Felica Lite
	 * compatible with NDEF.
	 */
	cookie->mc_block[3] = 1;
	prepare_write_block(cookie->IDm, &cmd, FELICA_LITE_MC_BLOCK,
				cookie->mc_block);
	err = near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd,
				cmd.len, write_attr_block, cookie, NULL);
	if (err < 0)
		goto out_err;

	return 0;

out_err:
	return t3_cookie_release(err, cookie);
}

static int nfctype3_format(uint32_t adapter_idx,
				uint32_t target_idx, near_tag_io_cb cb)
{
	struct type3_cmd cmd;
	struct near_tag *tag;
	struct t3_cookie *cookie;
	uint8_t ic_type;
	uint8_t *idm, len;

	DBG("");

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag)
		return -ENOMEM;

	ic_type = near_tag_get_ic_type(tag);
	if (ic_type != FELICA_LITE_IC_TYPE)
		return -EOPNOTSUPP;

	cookie = g_try_malloc0(sizeof(struct t3_cookie));
	if (!cookie)
		return -ENOMEM;

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;
	cookie->ic_type = ic_type;

	idm = near_tag_get_idm(tag, &len);
	if (!idm)
		return t3_cookie_release(-EINVAL, cookie);

	memcpy(cookie->IDm, idm, len);

	prepare_read_block(FELICA_LITE_MC_BLOCK, cookie->IDm, &cmd);

	return near_adapter_send(cookie->adapter_idx, (uint8_t *) &cmd, cmd.len,
					write_mc_block, cookie,
					t3_cookie_release);

}

static struct near_tag_driver type1_driver = {
	.type           = NFC_PROTO_FELICA,
	.priority       = NEAR_TAG_PRIORITY_DEFAULT,
	.read           = nfctype3_read,
	.write          = nfctype3_write,
	.format		= nfctype3_format,
	.check_presence = nfctype3_check_presence,
};

static int nfctype3_init(void)
{
	DBG("");

	return near_tag_driver_register(&type1_driver);
}

static void nfctype3_exit(void)
{
	DBG("");

	near_tag_driver_unregister(&type1_driver);
}

NEAR_PLUGIN_DEFINE(nfctype3, "NFC Forum Type 3 tags support", VERSION,
			NEAR_PLUGIN_PRIORITY_HIGH, nfctype3_init, nfctype3_exit)

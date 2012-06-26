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
#include <near/tlv.h>

#define CMD_READ_ALL		0x00	/* Read seg 0 (incl: HR) */
#define CMD_READ_SEGS		0x10	/* Read 16 blocks (128 bytes) */
#define CMD_RID			0x78	/* Read tag UID */

#define CMD_WRITE_E		0x53	/* Write with erase */
#define CMD_WRITE_NE		0x1A	/* Write no erase */

#define OFFSET_STATUS_CMD	0x00
#define OFFSET_HEADER_ROM	0x01

#define HR0_TYPE1_STATIC	0x11
#define HR0_TYPE2_HIGH		0x10
#define HR0_TYPE2_LOW		0x0F

#define BLOCK_SIZE		8
#define LEN_STATUS_BYTE		0x01	/* Status byte */
#define LEN_SPEC_BYTES		(LEN_STATUS_BYTE + 0x02)	/* HRx */
#define LEN_UID_BYTES		(LEN_STATUS_BYTE + 0x07)	/* UID bytes */
#define LEN_CC_BYTES		0x04	/* Capab. container */
#define LEN_DYN_BYTES		0x0A	/* Bytes CtrlIT and TLV - Dyn. only */

#define TYPE1_MAGIC 0xe1

#define TAG_T1_DATA_UID(data) ((data) + LEN_SPEC_BYTES)
#define TAG_T1_DATA_CC(data) ((data) + LEN_SPEC_BYTES + LEN_UID_BYTES)
#define TAG_T1_DATA_LENGTH(cc) ((cc[2] + 1) * 8 - LEN_CC_BYTES)

#define TAG_T1_DATA_NFC(cc) ((cc)[0] & TYPE1_MAGIC)

#define TYPE1_NOWRITE_ACCESS	0x0F
#define TAG_T1_WRITE_FLAG(cc) ((cc)[3] & TYPE1_NOWRITE_ACCESS)
#define TAG_T1_SEGMENT_SIZE	128

#define TYPE1_STATIC_MAX_DATA_SIZE	0x60

#define UID_LENGTH 4

struct type1_cmd {
	uint8_t cmd;
	uint8_t addr;
	uint8_t data[1];
	uint8_t uid[UID_LENGTH];
} __attribute__((packed));

struct type1_tag {
	uint32_t adapter_idx;
	uint16_t current_block;
	uint16_t current_seg;
	uint16_t last_seg;
	uint16_t data_read;
	uint8_t uid[UID_LENGTH];

	near_tag_io_cb cb;
	struct near_tag *tag;
};

struct t1_cookie {
	uint32_t adapter_idx;
	uint32_t target_idx;
	uint8_t uid[UID_LENGTH];
	uint32_t current_block; /* Static tag */
	uint32_t current_byte;  /* Static tag */
	struct near_ndef_message *ndef;
	near_tag_io_cb cb;
};

static void t1_init_cmd(struct type1_tag *tag, struct type1_cmd *cmd)
{
	if (tag == NULL || cmd == NULL)
		return;

	memcpy(cmd->uid, tag->uid, UID_LENGTH);
}

static void t1_cookie_release(struct t1_cookie *cookie)
{
	if (cookie == NULL)
		return;

	if (cookie->ndef)
		g_free(cookie->ndef->data);

	g_free(cookie->ndef);
	g_free(cookie);
	cookie = NULL;
}

/* Read segments (128 bytes)and store them to the tag data block */
static int segment_read_recv(uint8_t *resp, int length, void *data)
{
	struct type1_tag *t1_tag = data;
	struct type1_cmd t1_cmd;
	uint8_t *tagdata;
	size_t data_length;

	int err;

	DBG("%d", length);

	if (length < 0) {
		err = length;
		goto out_err;
	}

	length = length - LEN_STATUS_BYTE;  /* ignore first byte */

	/* Add data to tag mem*/
	tagdata = near_tag_get_data(t1_tag->tag, &data_length);
	memcpy(tagdata + t1_tag->data_read, resp+1, length);

	/* Next segment */
	t1_tag->data_read =  t1_tag->data_read + length;
	t1_tag->current_seg = t1_tag->current_seg + 1;

	if (t1_tag->current_seg <= t1_tag->last_seg) {
		/* RSEG cmd */
		t1_init_cmd(t1_tag, &t1_cmd);

		t1_cmd.cmd = CMD_READ_SEGS;
		t1_cmd.addr = (t1_tag->current_seg << 4) & 0xFF;

		err = near_adapter_send(t1_tag->adapter_idx,
				(uint8_t *)&t1_cmd, sizeof(t1_cmd),
				segment_read_recv, t1_tag);
		if (err < 0)
			goto out_err;
	} else { /* This is the end */
		GList *records;

		DBG("READ complete");

		records = near_tlv_parse(tagdata, data_length);
		near_tag_add_records(t1_tag->tag, records, t1_tag->cb, 0);

		err = 0;

		/* free memory */
		g_free(t1_tag);
	}

out_err:
	return err;
}

/* The dynamic read function:
 * Bytes [0..3] : CC
 * [4..8]: TLV Lock ControlIT (0x01, 0x03, v1, V2, V3)
 * [9..13]: TLV Reserved Memory Control	(0x02, 0x03, V1, V2, V3)
 * [14..]: TLV NDEF (0x03, L0, L1, L2, V1,V2 ...)
 */
static int read_dynamic_tag(uint8_t *cc, int length, void *data)
{
	struct type1_tag *t1_tag = data;
	struct type1_cmd t1_cmd;

	uint8_t *tagdata;
	uint8_t	*pndef;
	size_t data_length;

	DBG("Dynamic Mode");

	tagdata = near_tag_get_data(t1_tag->tag, &data_length);

	/* Skip un-needed bytes */
	pndef = cc + 4;		/* right after CC bytes */
	pndef = pndef + 5;	/* skip TLV Lock bits bytes */
	pndef = pndef + 5;	/* skip TLV ControlIT bytes */

	/* Save first NFC bytes to tag memory
	 * 10 blocks[0x3..0xC] of 8 bytes + 2 bytes from block 2
	 * */
	memcpy(tagdata,	pndef, 10 * BLOCK_SIZE + 2);

	/* Read the next one, up to the end of the data area */
	t1_tag->current_seg = 1;
	t1_tag->last_seg = ((cc[2] * BLOCK_SIZE) / TAG_T1_SEGMENT_SIZE);
	t1_tag->data_read = 10 * BLOCK_SIZE + 2;

	t1_init_cmd(t1_tag, &t1_cmd);

	/* T1 read segment */
	t1_cmd.cmd = CMD_READ_SEGS;
	/* 5.3.3 ADDS operand is [b8..b5] */
	t1_cmd.addr = (t1_tag->current_seg << 4) & 0xFF;

	return near_adapter_send(t1_tag->adapter_idx,
			(uint8_t *)&t1_cmd, sizeof(t1_cmd),
			segment_read_recv, t1_tag);
}

static int meta_recv(uint8_t *resp, int length, void *data)
{
	struct t1_cookie *cookie = data;
	struct near_tag *tag;
	struct type1_tag *t1_tag = NULL;

	uint8_t *cc;
	int err = -EOPNOTSUPP;

	DBG("%d", length);

	if (length < 0) {
		err = length;
		goto out_err;
	}

	/* First byte is cmd status */
	if (resp[OFFSET_STATUS_CMD] != 0) {
		DBG("Command failed: 0x%x",resp[OFFSET_STATUS_CMD]);
		err = -EIO;
		goto out_err;
	}

	/* Check Magic NFC tag */
	cc = TAG_T1_DATA_CC(resp);
	if (TAG_T1_DATA_NFC(cc) == 0) {
		DBG("Not a valid NFC magic tag: 0x%x",cc[0]);
		err = -EINVAL;
		goto out_err;
	}

	/* Add data to the tag */
	err = near_tag_add_data(cookie->adapter_idx, cookie->target_idx,
					NULL, TAG_T1_DATA_LENGTH(cc));
	if (err < 0)
		goto out_err;

	tag = near_tag_get_tag(cookie->adapter_idx, cookie->target_idx);
	if (tag == NULL) {
		err = -ENOMEM;
		goto out_err;
	}

	t1_tag = g_try_malloc0(sizeof(struct type1_tag));
	if (t1_tag == NULL) {
		err = -ENOMEM;
		goto out_err;
	}

	t1_tag->adapter_idx = cookie->adapter_idx;
	t1_tag->cb = cookie->cb;
	t1_tag->tag = tag;
	memcpy(t1_tag->uid, cookie->uid, UID_LENGTH);

	/*s Set the ReadWrite flag */
	if (TAG_T1_WRITE_FLAG(cc) == TYPE1_NOWRITE_ACCESS)
		near_tag_set_ro(tag, TRUE);
	else
		near_tag_set_ro(tag, FALSE);

	/* Check Static or Dynamic memory model */
	if (resp[OFFSET_HEADER_ROM] == HR0_TYPE1_STATIC) {
		uint8_t *tagdata;
		size_t data_length;
		GList *records;

		DBG("READ Static complete");

		tagdata = near_tag_get_data(t1_tag->tag, &data_length);
		memcpy(tagdata, cc + LEN_CC_BYTES, TAG_T1_DATA_LENGTH(cc));

		near_tag_set_memory_layout(tag, NEAR_TAG_MEMORY_STATIC);

		records = near_tlv_parse(tagdata, data_length);
		near_tag_add_records(t1_tag->tag, records, t1_tag->cb, 0);

		g_free(t1_tag);

		return 0;
	} else if ((resp[OFFSET_HEADER_ROM] & 0xF0) == HR0_TYPE2_HIGH) {
		near_tag_set_memory_layout(tag, NEAR_TAG_MEMORY_DYNAMIC);
		err = read_dynamic_tag(cc, length, t1_tag);
	} else {
		err = -EOPNOTSUPP ;
	}

out_err:
	DBG("err %d", err);

	if (err < 0 && cookie->cb)
		cookie->cb(cookie->adapter_idx, cookie->target_idx, err);

	t1_cookie_release(cookie);

	return err;
}

/*
 * READALL to read a maximum of 124 bytes.
 * This cmd is common to static and dynamic targets
 * This should allow to get the HR0 byte.
 */
static int rid_resp(uint8_t *resp, int length, void *data)
{
	struct t1_cookie *cookie = data;
	struct type1_cmd t1_cmd;
	uint8_t *uid;
	int err;

	DBG("");

	/* First byte is cmd status */
	if (resp[OFFSET_STATUS_CMD] != 0) {
		DBG("Command failed: 0x%x",resp[OFFSET_STATUS_CMD]);
		err = -EIO;
		goto out_err;
	}

	uid = TAG_T1_DATA_UID(resp);

	DBG("UID 0x%x 0x%x 0x%x 0x%x", uid[0], uid[1], uid[2], uid[3]);

	near_tag_set_nfcid(cookie->adapter_idx, cookie->target_idx,
							uid, UID_LENGTH);

	t1_cmd.cmd = CMD_READ_ALL;     /* Read ALL cmd give 124 bytes */
	t1_cmd.addr = 0;	       /* NA */
	t1_cmd.data[0] = 0;
	memcpy(t1_cmd.uid, uid, UID_LENGTH);

	memcpy(cookie->uid, uid, UID_LENGTH);

	return near_adapter_send(cookie->adapter_idx,
				(uint8_t *)&t1_cmd, sizeof(t1_cmd),
				meta_recv, cookie);

out_err:
	DBG("err %d", err);

	if (err < 0 && cookie->cb)
		cookie->cb(cookie->adapter_idx, cookie->target_idx, err);

	t1_cookie_release(cookie);

	return err;
}

/* First step: RID to get the tag UID */
static int nfctype1_read(uint32_t adapter_idx,
				uint32_t target_idx, near_tag_io_cb cb)
{
	struct type1_cmd t1_cmd;
	struct t1_cookie *cookie;
	uint8_t *uid, uid_length;

	DBG("");

	uid = near_tag_get_nfcid(adapter_idx, target_idx, &uid_length);
	if (uid == NULL || uid_length != UID_LENGTH) {
		if (uid != NULL && uid_length != UID_LENGTH) {
			near_error("Invalid UID");

			g_free(uid);
			return -EINVAL;
		}

		t1_cmd.cmd = CMD_RID;
		t1_cmd.addr = 0;
		t1_cmd.data[0] = 0;
		memset(t1_cmd.uid, 0, UID_LENGTH);

		cookie = g_try_malloc0(sizeof(struct t1_cookie));
		cookie->adapter_idx = adapter_idx;
		cookie->target_idx = target_idx;
		cookie->cb = cb;

		return near_adapter_send(adapter_idx,
					(uint8_t *)&t1_cmd, sizeof(t1_cmd),
					rid_resp, cookie);
	}

	t1_cmd.cmd = CMD_READ_ALL;     /* Read ALL cmd give 124 bytes */
	t1_cmd.addr = 0;	       /* NA */
	t1_cmd.data[0] = 0;
	memcpy(t1_cmd.uid, uid, UID_LENGTH);

	cookie = g_try_malloc0(sizeof(struct t1_cookie));
	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	memcpy(cookie->uid, uid, UID_LENGTH);
	cookie->cb = cb;

	g_free(uid);

	return near_adapter_send(adapter_idx, (uint8_t *)&t1_cmd, sizeof(t1_cmd),
							meta_recv, cookie);

}

static int write_nmn_e1_resp(uint8_t *resp, int length, void *data)
{
	int err = 0;
	struct t1_cookie *cookie = data;

	DBG("");

	if (length < 0)
		err = length;

	if (resp[OFFSET_STATUS_CMD] != 0)
		err = -EIO;

	DBG("Done writing");

	cookie->cb(cookie->adapter_idx, cookie->target_idx, err);

	t1_cookie_release(cookie);

	return err;
}

static int write_nmn_e1(struct t1_cookie *cookie)
{
	struct type1_cmd cmd;

	DBG("");

	cmd.cmd = CMD_WRITE_E;
	cmd.addr = 0x08;
	cmd.data[0] = TYPE1_MAGIC;
	memcpy(cmd.uid, cookie->uid, UID_LENGTH);

	return near_adapter_send(cookie->adapter_idx, (uint8_t *)&cmd,
					sizeof(cmd), write_nmn_e1_resp, cookie);
}

static int data_write(uint8_t *resp, int length, void *data)
{
	struct t1_cookie *cookie = data;
	uint8_t addr = 0;
	struct type1_cmd cmd;
	int err;

	DBG("");

	if (length < 0) {
		err = length;
		goto out;
	}

	if (resp[OFFSET_STATUS_CMD] != 0) {
		err = -EIO;
		goto out;
	}

	if (cookie->ndef->offset > cookie->ndef->length)
		return write_nmn_e1(cookie);

	if (cookie->current_byte >= BLOCK_SIZE) {
		cookie->current_byte = 0;
		cookie->current_block++;
	}

	cmd.cmd = CMD_WRITE_E;
	addr = cookie->current_block << 3;
	cmd.addr = addr | (cookie->current_byte & 0x7);
	cmd.data[0] = cookie->ndef->data[cookie->ndef->offset];
	memcpy(cmd.uid, cookie->uid, UID_LENGTH);
	cookie->ndef->offset++;
	cookie->current_byte++;

	err = near_adapter_send(cookie->adapter_idx, (uint8_t *)&cmd,
					sizeof(cmd), data_write, cookie);
	if (err < 0)
		goto out;

	return 0;

out:
	if (err < 0 && cookie->cb)
		cookie->cb(cookie->adapter_idx, cookie->target_idx, err);

	t1_cookie_release(cookie);

	return err;
}

static int write_nmn_0(uint32_t adapter_idx, uint32_t target_idx,
			struct near_ndef_message *ndef, near_tag_io_cb cb)
{
	int err;
	struct type1_cmd cmd;
	struct t1_cookie *cookie;
	uint8_t *uid, uid_length;

	DBG("");

	uid = near_tag_get_nfcid(adapter_idx, target_idx, &uid_length);
	if (uid == NULL || uid_length != UID_LENGTH) {
		near_error("Invalid type 1 UID");
		return -EINVAL;
	}

	cmd.cmd  = CMD_WRITE_E;
	cmd.addr = 0x08;
	cmd.data[0] = 0x00;
	memcpy(cmd.uid, uid, UID_LENGTH);

	cookie = g_try_malloc0(sizeof(struct t1_cookie));
	if (cookie == NULL) {
		g_free(uid);
		err = -ENOMEM;
		return err;
	}

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	memcpy(cookie->uid, uid, UID_LENGTH);
	cookie->current_block = 1;
	cookie->current_byte = LEN_CC_BYTES;
	cookie->ndef = ndef;
	cookie->cb = cb;

	g_free(uid);

	err = near_adapter_send(cookie->adapter_idx, (uint8_t *)&cmd,
					sizeof(cmd), data_write, cookie);
	if (err < 0)
		goto out;

	return 0;

out:
	t1_cookie_release(cookie);

	return err;
}

/*
 * The writing of a new NDEF message SHALL occur as follows:
 * Write NMN = 00h to indicate that no valid NDEF message is present
 * during writing to allow error detection in the event that the tag
 * is removed from the field prior to completion of operation.
 * Write VNo and RWA if required
 * Write NDEF Message TLV
 * Write NDEF Message data
 * Write NMN = E1h as the last byte to be written
 */
static int nfctype1_write(uint32_t adapter_idx, uint32_t target_idx,
				struct near_ndef_message *ndef,
				near_tag_io_cb cb)
{
	struct near_tag *tag;

	DBG("");

	if (ndef == NULL || cb == NULL)
		return -EINVAL;

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (tag == NULL)
		return -EINVAL;

	/* This check is valid for only static tags.
	 * Max data length on Type 2 Tag including TLV's
	 * is TYPE1_STATIC_MAX_DATA_SIZE */
	if (near_tag_get_memory_layout(tag) == NEAR_TAG_MEMORY_STATIC) {
		if ((ndef->length + 3) > TYPE1_STATIC_MAX_DATA_SIZE) {
			near_error("not enough space on data");
			return -ENOMEM;
		}
	}

	return write_nmn_0(adapter_idx, target_idx, ndef, cb);
}

static int check_presence(uint8_t *resp, int length, void *data)
{
	struct t1_cookie *cookie = data;
	int err = 0;

	DBG("%d", length);

	if (length < 0)
		err = -EIO;

	if (cookie->cb)
		cookie->cb(cookie->adapter_idx,
				cookie->target_idx, err);

	t1_cookie_release(cookie);

	return err;
}

static int nfctype1_check_presence(uint32_t adapter_idx,
				uint32_t target_idx, near_tag_io_cb cb)
{
	struct type1_cmd t1_cmd;
	struct t1_cookie *cookie;
	uint8_t *uid, uid_length;
	int err;

	DBG("");

	uid = near_tag_get_nfcid(adapter_idx, target_idx, &uid_length);
	if (uid == NULL || uid_length != UID_LENGTH) {
		near_error("Invalid type 1 UID");
		return -EINVAL;
	}

	t1_cmd.cmd = CMD_READ_ALL;     /* Read ALL cmd give 124 bytes */
	t1_cmd.addr = 0;	       /* NA */
	t1_cmd.data[0] = 0;
	memcpy(t1_cmd.uid, uid, UID_LENGTH);

	g_free(uid);

	cookie = g_try_malloc0(sizeof(struct t1_cookie));
	if (cookie == NULL)
		return -ENOMEM;

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;

	err = near_adapter_send(adapter_idx, (uint8_t *)&t1_cmd, sizeof(t1_cmd),
							check_presence, cookie);
	if (err < 0)
		goto out;

	return 0;

out:
	t1_cookie_release(cookie);

	return err;
}

static struct near_tag_driver type1_driver = {
	.type           = NFC_PROTO_JEWEL,
	.priority       = NEAR_TAG_PRIORITY_DEFAULT,
	.read           = nfctype1_read,
	.write          = nfctype1_write,
	.check_presence = nfctype1_check_presence,
};

static int nfctype1_init(void)
{
	DBG("");

	return near_tag_driver_register(&type1_driver);
}

static void nfctype1_exit(void)
{
	DBG("");

	near_tag_driver_unregister(&type1_driver);
}

NEAR_PLUGIN_DEFINE(nfctype1, "NFC Forum Type 1 tags support", VERSION,
			NEAR_PLUGIN_PRIORITY_HIGH, nfctype1_init, nfctype1_exit)

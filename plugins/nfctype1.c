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

#define CMD_READ_ALL		0x00	/* Read seg 0 (incl: HR) */
#define CMD_READ_SEGS		0x10	/* Read 16 blocks (128 bytes) */

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

#define TAG_T1_DATA_CC(data) ((data) + LEN_SPEC_BYTES + LEN_UID_BYTES)
#define TAG_T1_DATA_LENGTH(cc) ((cc[2] + 1) * 8 - LEN_CC_BYTES)

#define TAG_T1_DATA_NFC(cc) ((cc)[0] & TYPE1_MAGIC)

#define TYPE1_NOWRITE_ACCESS	0x0F
#define TAG_T1_WRITE_FLAG(cc) ((cc)[3] & TYPE1_NOWRITE_ACCESS)
#define TAG_T1_SEGMENT_SIZE	128

struct type1_cmd {
	uint8_t cmd;
	uint8_t addr;
	uint8_t data[];
} __attribute__((packed));

struct type1_tag {
	uint32_t adapter_idx;
	uint16_t current_block;
	uint16_t current_seg;
	uint16_t last_seg;
	uint16_t data_read;

	near_tag_io_cb cb;
	struct near_tag *tag;
};

struct recv_cookie {
	uint32_t adapter_idx;
	uint32_t target_idx;
	near_tag_io_cb cb;
};

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
		t1_cmd.cmd = CMD_READ_SEGS;
		t1_cmd.addr = (t1_tag->current_seg << 4) & 0xFF;

		err = near_adapter_send(t1_tag->adapter_idx,
				(uint8_t *)&t1_cmd, sizeof(t1_cmd),
				segment_read_recv, t1_tag);
		if (err < 0)
			goto out_err;
	} else { /* This is the end */
		DBG("READ Static complete");
		err = near_tlv_parse(t1_tag->tag,
					t1_tag->cb,
					tagdata,
					t1_tag->data_read);

		err = near_adapter_disconnect(t1_tag->adapter_idx);
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
	struct recv_cookie *cookie = data;
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

	/* Associate the DATA length to the tag */
	tag = near_target_add_tag(cookie->adapter_idx, cookie->target_idx,
					TAG_T1_DATA_LENGTH(cc));
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

	/* Save the UID */
	near_tag_set_uid(tag, resp + LEN_SPEC_BYTES, LEN_UID_BYTES);

	/*s Set the ReadWrite flag */
	if (TAG_T1_WRITE_FLAG(cc) == TYPE1_NOWRITE_ACCESS)
		near_tag_set_ro(tag, TRUE);
	else
		near_tag_set_ro(tag, FALSE);

	/* Check Static or Dynamic memory model */
	if (resp[OFFSET_HEADER_ROM] == HR0_TYPE1_STATIC) {
		DBG("READ Static complete");
		err = near_tlv_parse(t1_tag->tag, t1_tag->cb,
			cc + LEN_CC_BYTES, TAG_T1_DATA_LENGTH(cc));
		if (err < 0)
			goto out_err;

		near_adapter_disconnect(t1_tag->adapter_idx);
		g_free(t1_tag);
	} else if ((resp[OFFSET_HEADER_ROM] & 0xF0) == HR0_TYPE2_HIGH) {
			err = read_dynamic_tag(cc, length, t1_tag);
	} else {
		err = -EOPNOTSUPP ;
	}

out_err:
	if (err < 0 && cookie->cb) {
		cookie->cb(cookie->adapter_idx, err);
		if (t1_tag)
			near_adapter_disconnect(t1_tag->adapter_idx);
	}
	g_free(cookie);

	return err;
}

/* First step: READALL to read a maximum of 124 bytes
 * This cmd is common to static and dynamic targets
 * This should allow to get the HR0 byte
 */
static int nfctype1_read_all(uint32_t adapter_idx, uint32_t target_idx,
							near_tag_io_cb cb)
{
	struct type1_cmd t1_cmd;
	struct recv_cookie *cookie;

	DBG("");

	t1_cmd.cmd = CMD_READ_ALL;     /* Read ALL cmd give 124 bytes */
	t1_cmd.addr = 0;	       /* NA */

	cookie = g_try_malloc0(sizeof(struct recv_cookie));
	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;

	return near_adapter_send(adapter_idx, (uint8_t *)&t1_cmd, sizeof(t1_cmd),
							meta_recv, cookie);
}

static int nfctype1_read_tag(uint32_t adapter_idx,
				uint32_t target_idx, near_tag_io_cb cb)
{
	int err;

	DBG("");

	err = near_adapter_connect(adapter_idx, target_idx, NFC_PROTO_JEWEL);
	if (err < 0) {
		near_error("Could not connect %d", err);

		return err;
	}

	err = nfctype1_read_all(adapter_idx, target_idx, cb);
	if (err < 0)
		near_adapter_disconnect(adapter_idx);

	return err;
}

static struct near_tag_driver type1_driver = {
	.type     = NEAR_TAG_NFC_TYPE1,
	.read_tag = nfctype1_read_tag,
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

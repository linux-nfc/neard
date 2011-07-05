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

#define CMD_READ_ALL		0x00	/* Read all bytes (incl: HR) */

#define OFFSET_STATUS_CMD	0x00
#define OFFSET_HEADER_ROM	0x01

#define HR0_TYPE1_STATIC	0x11

#define LEN_STATUS_BYTE		0x01	/* Status byte */
#define LEN_SPEC_BYTES		(LEN_STATUS_BYTE + 0x02)	/* HRx */
#define LEN_UID_BYTES		(LEN_STATUS_BYTE + 0x07)	/* UID bytes */
#define LEN_CC_BYTES		0x04	/* Capab. container */

#define TYPE1_MAGIC 0xe1

#define TAG_T1_DATA_CC(data) ((data) + LEN_SPEC_BYTES + LEN_UID_BYTES )
#define TAG_T1_DATA_LENGTH(cc) ((cc)[2] * 8 - LEN_CC_BYTES)
#define TAG_T1_DATA_NFC(cc) ((cc)[0] & TYPE1_MAGIC)

struct type1_cmd {
	uint8_t cmd;
	uint8_t offset;
	uint8_t data[];
} __attribute__((packed));

struct type1_tag {
	uint32_t adapter_idx;
	uint16_t current_block;

	near_tag_read_cb cb;
	struct near_tag *tag;
};

struct recv_cookie {
	uint32_t adapter_idx;
	uint32_t target_idx;
	near_tag_read_cb cb;
};

static int meta_recv(uint8_t *resp, int length, void *data)
{
    struct recv_cookie *cookie = data;
	struct near_tag *tag;
	struct type1_tag *t1_tag;
	uint8_t *cc;
	int err;

	DBG("%d", length);

	if (length < 0) {
		err = length;
		goto out;
	}

	/* First byte is cmd status */
	if (resp[OFFSET_STATUS_CMD] != 0) {
		DBG("Command failed: 0x%x",resp[OFFSET_STATUS_CMD]);
		err = -EIO;
		goto out;
	}

	/* Check Magic NFC tag */
	cc = TAG_T1_DATA_CC(resp);

	if (TAG_T1_DATA_NFC(cc) == 0) {
		DBG("Not a valid NFC magic tag: 0x%x",cc[0]);
		err = -EINVAL;
		goto out;
	}

	/* Associate the DATA length to the tag */
	tag = near_target_add_tag(cookie->adapter_idx, cookie->target_idx,
					TAG_T1_DATA_LENGTH(cc));
	if (tag == NULL) {
		err = -ENOMEM;
		goto out;
	}

	t1_tag = g_try_malloc0(sizeof(struct type1_tag));
	if (t1_tag == NULL) {
		err = -ENOMEM;
		goto out;
	}

	t1_tag->adapter_idx = cookie->adapter_idx;
	t1_tag->cb = cookie->cb;
	t1_tag->tag = tag;

	/* Save the UID */
	near_tag_set_uid(tag, resp + LEN_SPEC_BYTES, LEN_UID_BYTES);

	/* Check Static or Dynamic memory model */
	if (resp[OFFSET_HEADER_ROM] == HR0_TYPE1_STATIC) {
		err = near_tlv_parse(t1_tag->tag, t1_tag->cb,
				cc + LEN_CC_BYTES, TAG_T1_DATA_LENGTH(cc));
		near_adapter_disconnect(t1_tag->adapter_idx);
	} else {
		err = -EOPNOTSUPP ;
	}

out:
	g_free(cookie);

	if (err < 0 && cookie->cb)
		cookie->cb(cookie->adapter_idx, err);

	return err;
}

/* First step: READALL to read a maximum of 124 bytes
 * This cmd is common to static and dynamic targets
 * This should allow to get the HR0 byte
 */
static int nfctype1_read_all(uint32_t adapter_idx, uint32_t target_idx,
							near_tag_read_cb cb)
{
	struct type1_cmd t1_cmd;
	struct recv_cookie *cookie;

	DBG("");

	t1_cmd.cmd = CMD_READ_ALL;     /* Read ALL cmd give 124 bytes */
	t1_cmd.offset = 0;	       /* NA */

	cookie = g_try_malloc0(sizeof(struct recv_cookie));
	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;

	return near_adapter_send(adapter_idx, (uint8_t *)&t1_cmd, sizeof(t1_cmd),
							meta_recv, cookie);
}

static int nfctype1_read_tag(uint32_t adapter_idx,
				uint32_t target_idx, near_tag_read_cb cb)
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

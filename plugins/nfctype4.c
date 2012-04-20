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

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#define NFC_STATUS		0
#define NFC_STATUS_BYTE_LEN	1

#define STATUS_WORD_1		1
#define STATUS_WORD_2		2
#define APDU_HEADER_LEN		5
#define APDU_OK			0x9000
#define APDU_NOT_FOUND		0x6A82

#define T4_ALL_ACCESS		0x00
#define T4_READ_ONLY		0xFF

#define APDU_STATUS(a) (g_ntohs(*((uint16_t *)(a))))

/* Tag Type 4 version ID */
static uint8_t iso_appname_v1[] = { 0xd2, 0x76, 0x0, 0x0, 0x85, 0x01, 0x0 };
static uint8_t iso_appname_v2[] = { 0xd2, 0x76, 0x0, 0x0, 0x85, 0x01, 0x1 };

/* Tag T4 File ID */
static uint8_t iso_cc_fileid[] = { 0xe1, 0x03 };
#define LEN_ISO_CC_FILEID	2

#define LEN_ISO_CC_READ_SIZE	0x0F

#define CMD_HEADER_SIZE		5
struct type4_cmd {			/* iso 7816 */
	uint8_t class;
	uint8_t instruction;
	uint8_t param1;
	uint8_t param2;
	uint8_t data_length;
	uint8_t data[];
} __attribute__((packed));

struct type4_NDEF_file_control_tlv {
	uint8_t tag	;		/* should be 4 */
	uint8_t len	;		/* should be 6 */
	uint16_t file_id ;
	uint16_t max_ndef_size ;
	uint8_t read_access ;
	uint8_t write_access ;
} __attribute__((packed));

struct type4_cc {			/* Capability Container */
	uint16_t CCLEN;
	uint8_t mapping_version;
	uint16_t max_R_apdu_data_size;
	uint16_t max_C_apdu_data_size;
	struct type4_NDEF_file_control_tlv tlv_fc ;
	uint8_t tlv_blocks[];
} __attribute__((packed));

struct t4_cookie {
	uint32_t adapter_idx;
	uint32_t target_idx;
	near_tag_io_cb cb;
	struct near_tag *tag;
	uint16_t read_data;
	uint16_t r_apdu_max_size;
	uint16_t c_apdu_max_size;
	uint16_t max_ndef_size;
	uint8_t write_access;
	struct near_ndef_message *ndef;
};

/* ISO functions: This code prepares APDU */
static int ISO_send_cmd(uint8_t class,
			uint8_t instruction,
			uint8_t param1,
			uint8_t param2,
			uint8_t *cmd_data,
			uint8_t cmd_data_length,
			near_recv cb,
			void *in_data)
{
	struct type4_cmd *cmd;
	struct t4_cookie *in_rcv = in_data;
	int err;

	DBG("CLA:x%02x INS:x%02x P1:%02x P2:%02x",
			class, instruction, param1, param2);

	cmd = g_try_malloc0(APDU_HEADER_LEN + cmd_data_length);
	if (cmd == NULL) {
		DBG("Mem alloc failed");
		err = -ENOMEM;
		goto out_err;
	}

	cmd->class	=	class;
	cmd->instruction =	instruction ;
	cmd->param1	=	param1 ;
	cmd->param2	=	param2 ;
	cmd->data_length =	cmd_data_length;

	if (cmd_data)
		memcpy(cmd->data, cmd_data, cmd_data_length);
	else
		cmd_data_length = 0 ;

	err =  near_adapter_send(in_rcv->adapter_idx, (uint8_t *)cmd,
			APDU_HEADER_LEN + cmd_data_length , cb, in_rcv);
	if (err < 0)
		g_free(in_rcv);

out_err:
	/* On exit, clean memory */
	g_free(cmd);

	return err;
}

/* ISO 7816 command: Select applications or files
 * p1=0 select by "file id"
 * P1=4 select by "DF name"
 *  */
static int ISO_Select(uint8_t *filename, uint8_t fnamelen, uint8_t P1,
		near_recv cb, void *cookie)
{
	DBG("");

	return ISO_send_cmd(
			0x00,		/* CLA */
			0xA4,		/* INS: Select file */
			P1,		/* P1: select by name */
			0x00,		/* P2: First or only occurence */
			filename,	/* cmd_data */
			fnamelen,	/* uint8_t cmd_data_length*/
			cb,
			cookie);
}

/* ISO 7816 command: Read binary data from files */
static int ISO_ReadBinary(uint16_t offset, uint8_t readsize,
			near_recv cb, void *cookie)
{
	DBG("");
	return ISO_send_cmd(
			0x00,		/* CLA */
			0xB0,		/* INS: Select file */
			(uint8_t)((offset & 0xFF00)>>8),
			(uint8_t)(offset & 0xFF),
			0,		/* no data send */
			readsize,	/* bytes to read */
			cb,
			cookie);
}

/* ISO 7816 command: Update data */
static int ISO_Update(uint16_t offset, uint8_t nlen,
			uint8_t *data, near_recv cb, void *cookie)
{
	DBG("");
	return ISO_send_cmd(
			0x00,			/* CLA */
			0xD6,			/* INS: Select file */
			(uint8_t)((offset & 0xFF00) >> 8),
			(uint8_t)(offset & 0xFF),
			data,			/* length of NDEF data */
			nlen,			/* NLEN + NDEF data */
			cb,
			cookie);
}

static int t4_cookie_release(int err, struct t4_cookie *cookie)
{
	if (cookie == NULL)
		return err;

	if (err < 0 && cookie->cb)
		cookie->cb(cookie->adapter_idx, cookie->target_idx, err);

	if (cookie->ndef)
		g_free(cookie->ndef->data);

	g_free(cookie->ndef);
	g_free(cookie);

	return err;
}


static int data_read_cb(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data ;
	uint8_t *nfc_data;
	uint16_t data_length, length_read, current_length;
	uint16_t remain_bytes;
	int err = 0;

	DBG("%d", length);

	if (length < 0)
		return t4_cookie_release(err, cookie);

	if (APDU_STATUS(resp + length - 2) != APDU_OK) {
		DBG("Fail read_cb SW:x%04x", APDU_STATUS(resp + length - 2));
		err = -EIO;
		return t4_cookie_release(err, cookie);
	}

	nfc_data = near_tag_get_data(cookie->tag, (size_t *)&data_length);

	/* Remove SW1 / SW2  and NFC header */
	length_read = length - NFC_HEADER_SIZE - 2 ;
	length = length_read;

	current_length = cookie->read_data;

	if (current_length + (length_read) > data_length)
		length_read = data_length - current_length;

	memcpy(nfc_data + current_length, resp + NFC_HEADER_SIZE, length_read);
	if (current_length + length_read == data_length) {
		GList *records;

		DBG("Done reading");

		records = near_ndef_parse(nfc_data, data_length);
		near_tag_add_records(cookie->tag, records, cookie->cb, 0);

		err = 0;
		goto out_err;
	}

	cookie->read_data += length ;
	remain_bytes = (data_length - cookie->read_data);

	if (remain_bytes >= cookie->r_apdu_max_size)
		err = ISO_ReadBinary(cookie->read_data + 2,
				cookie->r_apdu_max_size, data_read_cb, cookie);
	else
		err = ISO_ReadBinary(cookie->read_data + 2,
				(uint8_t)remain_bytes, data_read_cb, cookie);
	if (err < 0)
		goto out_err;

	return err;

out_err:
	return t4_cookie_release(err, cookie);
}


static int t4_readbin_NDEF_ID(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data ;
	struct near_tag *tag;
	int err = 0;

	DBG("%d", length);

	if (length < 0) {
		err = length;
		goto out_err;
	}

	if (APDU_STATUS(resp + length - 2) != APDU_OK) {
		DBG("Fail SW:x%04x", APDU_STATUS(resp + length - 2));
		err = -EIO;
		goto out_err;
	}

	/* Add data to the tag */
	err = near_tag_add_data(cookie->adapter_idx, cookie->target_idx, NULL,
				g_ntohs(*((uint16_t *)(resp + NFC_STATUS_BYTE_LEN))));
	if (err < 0)
		goto out_err;

	tag = near_tag_get_tag(cookie->adapter_idx, cookie->target_idx);
	if (tag == NULL) {
		err = -ENOMEM;
		goto out_err;
	}

	near_tag_set_max_ndef_size(tag, cookie->max_ndef_size);
	near_tag_set_c_apdu_max_size(tag, cookie->c_apdu_max_size);

	/* save the tag */
	cookie->tag = tag;

	/* Set write conditions */
	if (cookie->write_access == T4_READ_ONLY)
		near_tag_set_ro(tag, TRUE);
	else
		near_tag_set_ro(tag, FALSE);

	/* TODO: see how we can get the UID value:
	 *  near_tag_set_uid(tag, resp + NFC_HEADER_SIZE, 8);
	 *  */

	/* Read 1st block */
	err = ISO_ReadBinary(2, cookie->r_apdu_max_size - 2,
			data_read_cb, cookie);
	if (err < 0)
		goto out_err;

	return err;

out_err:
	return t4_cookie_release(err, cookie);
}

static int t4_select_NDEF_ID(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;
	int err = 0;

	DBG("%d", length);

	if (length < 0) {
		err = length;
		goto out_err;
	}

	/* Check for APDU error */
	if (APDU_STATUS(resp + STATUS_WORD_1) != APDU_OK) {
		DBG("Fail SW:x%04x", APDU_STATUS(resp + STATUS_WORD_1));
		err = -EIO;
		goto out_err;
	}

	/* Read 0x0f bytes, to grab the NDEF msg length */
	err = ISO_ReadBinary(0, LEN_ISO_CC_READ_SIZE,
					t4_readbin_NDEF_ID, cookie);
	if (err < 0)
		goto out_err;

	return err;

out_err:
	return t4_cookie_release(err, cookie);
}


static int t4_readbin_cc(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data ;
	struct type4_cc	*read_cc ;
	int err = 0;

	DBG("%d", length);

	if (length < 0) {
		err = length;
		goto out_err;
	}

	/* Check APDU error ( the two last bytes of the resp) */
	if (APDU_STATUS(resp + length - 2) != APDU_OK) {
		DBG("Fail SW:x%04x", APDU_STATUS(resp + length - 2));
		err = -EIO;
		goto out_err;
	}

	/* -2 for status word and -1 is for NFC first byte... */
	read_cc = g_try_malloc0(length - 2 - NFC_STATUS_BYTE_LEN);
	if (read_cc == NULL) {
		DBG("Mem alloc failed");
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(read_cc, &resp[1], length - 2 - NFC_STATUS_BYTE_LEN) ;

	cookie->r_apdu_max_size = g_ntohs(read_cc->max_R_apdu_data_size) -
			APDU_HEADER_LEN ;
	cookie->c_apdu_max_size = g_ntohs(read_cc->max_C_apdu_data_size);
	cookie->max_ndef_size = g_ntohs(read_cc->tlv_fc.max_ndef_size);

	/* TODO 5.1.1 :TLV blocks can be zero, one or more...  */
	/* TODO 5.1.2 :Must ignore proprietary blocks (x05)...  */
	if (read_cc->tlv_fc.tag  != 0x4) {
		DBG("NDEF File Control tag not found !") ;
		err = -EINVAL ;
		goto out_err ;
	}

	/* save rw conditions */
	cookie->write_access = read_cc->tlv_fc.write_access;

	err = ISO_Select((uint8_t *)&read_cc->tlv_fc.file_id,
			LEN_ISO_CC_FILEID, 0, t4_select_NDEF_ID, cookie);
	if (err < 0)
		goto out_err;

	return err;

out_err:
	return t4_cookie_release(err, cookie);
}

static int t4_select_cc(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;
	int err = 0;

	DBG("%d", length);

	if (length < 0) {
		err = length;
		goto out_err;
	}

	/* Check for APDU error */
	if (APDU_STATUS(resp + STATUS_WORD_1) != APDU_OK) {
		DBG("Fail SW:x%04x", APDU_STATUS(resp + STATUS_WORD_1));
		err = -EIO;
		goto out_err;
	}

	err = ISO_ReadBinary(0, LEN_ISO_CC_READ_SIZE, t4_readbin_cc, cookie);
	if (err < 0)
		goto out_err;

	return err;

out_err:
	return t4_cookie_release(err, cookie);
}


static int t4_select_file_by_name_v1(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;
	int err = 0 ;

	DBG("%d", length);

	if (length < 0) {
		err = length;
		goto out_err;
	}

	/* Check for APDU error */
	if (APDU_STATUS(resp + STATUS_WORD_1) != APDU_OK) {
		DBG("V1 Fail SW:x%04x", APDU_STATUS(resp + STATUS_WORD_1));
		err = -EIO;
		goto out_err;
	}

	if (resp[NFC_STATUS] != 0) {
		err = -EIO;
		goto out_err;
	}

	/* Jump to select phase */
	err = ISO_Select(iso_cc_fileid, LEN_ISO_CC_FILEID, 0,
				t4_select_cc, cookie);
	if (err < 0)
		goto out_err;

	return err;

out_err:
	return t4_cookie_release(err, cookie);
}


static int t4_select_file_by_name_v2(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;
	int err = 0 ;

	DBG("%d", length);

	if (length < 0) {
		err = length;
		goto out_err;
	}

	/* Check for APDU error - Not found */
	if (APDU_STATUS(resp + STATUS_WORD_1) == APDU_NOT_FOUND) {
		DBG("Fallback to V1");
		err = ISO_Select(iso_appname_v1, ARRAY_SIZE(iso_appname_v1),
				0x4, t4_select_file_by_name_v1, cookie);
		if (err < 0)
			goto out_err;

		return err;
	}

	if (APDU_STATUS(resp + STATUS_WORD_1) != APDU_OK) {
		DBG("V2 Fail SW:x%04x", APDU_STATUS(resp + STATUS_WORD_1));
		err = -EIO;
		goto out_err;
	}

	if (resp[NFC_STATUS] != 0) {
		err = -EIO;
		goto out_err;
	}

	/* Jump to select phase */
	err = ISO_Select(iso_cc_fileid, LEN_ISO_CC_FILEID, 0,
			t4_select_cc, cookie);
	if (err < 0)
		goto out_err;

	return err;

out_err:
	return t4_cookie_release(err, cookie);
}

static int nfctype4_read(uint32_t adapter_idx,
		uint32_t target_idx, near_tag_io_cb cb)
{
	struct t4_cookie *cookie;
	int err = 0;

	DBG("");

	cookie = g_try_malloc0(sizeof(struct t4_cookie));
	if (cookie == NULL) {
		err = -ENOMEM;
		goto out_err;
	}

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;
	cookie->tag = NULL;
	cookie->read_data = 0;;

	/* Check for V2 type 4 tag */
	err = ISO_Select(iso_appname_v2, ARRAY_SIZE(iso_appname_v2),
			0x4, t4_select_file_by_name_v2, cookie);
	if (err < 0)
		goto out_err;

	return err;

out_err:
	return t4_cookie_release(err, cookie);
}

static int data_write_cb(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;
	int err = 0;

	DBG("%d", length);

	if (length < 0)
		return t4_cookie_release(err, cookie);

	if (APDU_STATUS(resp + length - 2) != APDU_OK) {
		near_error("write failed SWx%04x",
				APDU_STATUS(resp + length - 2));
		err = -EIO;

		return t4_cookie_release(err, cookie);
	}

	if (cookie->ndef->offset >= cookie->ndef->length) {
		DBG("Done writing");
		near_adapter_disconnect(cookie->adapter_idx);

		return t4_cookie_release(0, cookie);
	}

	if ((cookie->ndef->length - cookie->ndef->offset) >
			cookie->c_apdu_max_size) {
		err = ISO_Update(cookie->ndef->offset,
				cookie->c_apdu_max_size,
				cookie->ndef->data + cookie->ndef->offset,
				data_write_cb, cookie);
		cookie->ndef->offset += cookie->c_apdu_max_size;
	} else {
		err = ISO_Update(cookie->ndef->offset,
				cookie->ndef->length - cookie->ndef->offset,
				cookie->ndef->data + cookie->ndef->offset,
				data_write_cb, cookie);
		cookie->ndef->offset = cookie->ndef->length;
	}

	if (err < 0)
		return t4_cookie_release(err, cookie);

	return err;
}

static int data_write(uint32_t adapter_idx, uint32_t target_idx,
				struct near_ndef_message *ndef,
				struct near_tag *tag, near_tag_io_cb cb)
{
	struct t4_cookie *cookie;
	int err;

	cookie = g_try_malloc0(sizeof(struct t4_cookie));
	if (cookie == NULL) {
		err = -ENOMEM;
		goto out;
	}

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;
	cookie->tag = NULL;
	cookie->read_data = 0;
	cookie->max_ndef_size = near_tag_get_max_ndef_size(tag);
	cookie->c_apdu_max_size = near_tag_get_c_apdu_max_size(tag);
	cookie->ndef = ndef;

	if (cookie->max_ndef_size < cookie->ndef->length) {
		near_error("not enough space on tag to write data");
		err = -ENOMEM;
		goto out;
	}

	if ((cookie->ndef->length - cookie->ndef->offset) >
			cookie->c_apdu_max_size) {
		err = ISO_Update(cookie->ndef->offset,
				cookie->c_apdu_max_size,
				cookie->ndef->data,
				data_write_cb, cookie);
		cookie->ndef->offset += cookie->c_apdu_max_size;
	} else {
		err = ISO_Update(cookie->ndef->offset,
				cookie->ndef->length,
				cookie->ndef->data,
				data_write_cb, cookie);
		cookie->ndef->offset = cookie->ndef->length;
	}

	if (err < 0)
		goto out;

	return 0;

out:
	t4_cookie_release(err, cookie);

	return err;
}

static int nfctype4_write(uint32_t adapter_idx, uint32_t target_idx,
			struct near_ndef_message *ndef, near_tag_io_cb cb)
{
	struct near_tag *tag;

	DBG("");

	if (ndef == NULL || cb == NULL)
		return -EINVAL;

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (tag == NULL)
		return -EINVAL;

	if (near_tag_get_ro(tag) == TRUE) {
		DBG("tag is read-only");
		return -EPERM;
	}

	return data_write(adapter_idx, target_idx, ndef, tag, cb);
}

static int check_presence(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;
	int err = 0;

	DBG("%d", length);

	if (length < 0)
		err = -EIO;

	if (cookie->cb)
		cookie->cb(cookie->adapter_idx,
				cookie->target_idx, err);

	return t4_cookie_release(err, cookie);
}

static int nfctype4_check_presence(uint32_t adapter_idx,
		uint32_t target_idx, near_tag_io_cb cb)
{
	struct t4_cookie *cookie;
	int err = 0;

	DBG("");

	cookie = g_try_malloc0(sizeof(struct t4_cookie));
	if (cookie == NULL) {
		err = -ENOMEM;
		goto out_err;
	}

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;
	cookie->tag = NULL;
	cookie->read_data = 0;;

	/* Check for V2 type 4 tag */
	err = ISO_Select(iso_appname_v2, ARRAY_SIZE(iso_appname_v2),
			0x4, check_presence, cookie);
	if (err < 0)
		goto out_err;

	return err;

out_err:
	return t4_cookie_release(err, cookie);
}

static struct near_tag_driver type4_driver = {
	.type           = NFC_PROTO_ISO14443,
	.priority       = NEAR_TAG_PRIORITY_DEFAULT,
	.read           = nfctype4_read,
	.write          = nfctype4_write,
	.check_presence = nfctype4_check_presence,
};

static int nfctype4_init(void)
{
	DBG("");

	return near_tag_driver_register(&type4_driver);
}

static void nfctype4_exit(void)
{
	DBG("");

	near_tag_driver_unregister(&type4_driver);
}

NEAR_PLUGIN_DEFINE(nfctype4, "NFC Forum Type 4 tags support", VERSION,
		NEAR_PLUGIN_PRIORITY_HIGH, nfctype4_init, nfctype4_exit)

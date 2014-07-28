/*
 *
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2014  Marvell International Ltd.
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

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define NFC_STATUS		0
#define NFC_STATUS_BYTE_LEN	1

#define STATUS_WORD_1		1
#define STATUS_WORD_2		2
#define APDU_HEADER_LEN		5
#define APDU_OK			0x9000
#define APDU_NOT_FOUND		0x6A82

/* PICC Level Commands */
#define PICC_CLASS		0x90
#define GET_VERSION		0x60
#define CREATE_APPLICATION	0xCA
#define SELECT_APPLICATION	0x5A
#define CREATE_STD_DATA_FILE	0xCD
#define WRITE_DATA_TO_FILE	0x3D

#define DESFire_EV1_MAJOR_VERSION	0x01
#define PICC_LEVEL_APDU_OK		0x9100
#define GET_VERSION_FRAME_RESPONSE_BYTE 0xAF
#define DESFIRE_KEY_SETTINGS	0x0F
#define	DESFIRE_NUM_OF_KEYS	0x21
#define DESFIRE_CC_FILE_NUM	0x01
#define DESFIRE_NDEF_FILE_NUM	0x02
#define DESFIRE_COMMSET		0x00
#define MAPPING_VERSION		0x20
#define	FREE_READ_ACCESS	0x00
#define	FREE_WRITE_ACCESS	0x00

#define T4_ALL_ACCESS		0x00
#define T4_READ_ONLY		0xFF
#define T4_V1			0x01
#define T4_V2			0x02

#define APDU_STATUS(a) near_get_be16(a)

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

struct desfire_app {
	uint8_t aid[3];
	uint8_t key_settings;
	uint8_t number_of_keys;
	uint8_t file_id[2];
	uint8_t iso_appname[7];
} __attribute__((packed));

struct desfire_std_file {
	uint8_t file_num;
	uint8_t file_id[2];
	uint8_t comm_set;
	uint8_t access_rights[2];
	uint8_t size[3];
} __attribute__((packed));

struct desfire_cc_file {
	uint8_t file_num;
	uint8_t offset[3];
	uint8_t max_len[3];
	uint8_t cc_len[2];
	uint8_t version;
	uint8_t mle[2];
	uint8_t mlc[2];
	uint8_t ndef_tlv[4];
	uint8_t ndef_size[2];
	uint8_t read_access;
	uint8_t write_access;
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
	uint16_t memory_size;
	uint8_t version;
};

static int t4_cookie_release(int err, void *data)
{
	struct t4_cookie *cookie = data;

	DBG("%p", cookie);

	if (!cookie)
		return err;

	if (err < 0 && cookie->cb)
		cookie->cb(cookie->adapter_idx, cookie->target_idx, err);

	if (cookie->ndef)
		g_free(cookie->ndef->data);

	g_free(cookie->ndef);
	g_free(cookie);

	return err;
}

/* ISO functions: This code prepares APDU */
static int ISO_send_cmd(uint8_t class,
			uint8_t instruction,
			uint8_t param1,
			uint8_t param2,
			uint8_t *cmd_data,
			uint8_t cmd_data_length,
			bool le,
			near_recv cb,
			void *in_data)
{
	struct type4_cmd *cmd;
	struct t4_cookie *in_rcv = in_data;
	uint8_t total_cmd_length;
	int err;

	DBG("CLA-%02x INS-%02x P1-%02x P2-%02x",
			class, instruction, param1, param2);

	if (!le) {
		if (cmd_data)
			total_cmd_length = APDU_HEADER_LEN + cmd_data_length;
		else
			total_cmd_length = APDU_HEADER_LEN;
	} else {  /* Extra byte for Le */
		total_cmd_length = APDU_HEADER_LEN + cmd_data_length + 1;
	}

	cmd = g_try_malloc0(total_cmd_length);
	if (!cmd) {
		DBG("Mem alloc failed");
		err = t4_cookie_release(-ENOMEM, in_rcv);
		goto out_err;
	}

	cmd->class	=	class;
	cmd->instruction =	instruction ;
	cmd->param1	=	param1 ;
	cmd->param2	=	param2 ;
	cmd->data_length =	cmd_data_length;

	if (cmd_data) {
		memcpy(cmd->data, cmd_data, cmd_data_length);
		/* The Le byte set to 0x00 defined that any length
		 * of PICC response is allowed */
		if (le)
			cmd->data[cmd_data_length] = 0;
	}

	err = near_adapter_send(in_rcv->adapter_idx, (uint8_t *) cmd,
					total_cmd_length, cb, in_rcv,
					t4_cookie_release);

out_err:
	/* On exit, clean memory */
	g_free(cmd);

	return err;
}

/* ISO 7816 command: Select applications or files
 * p1=0 select by "file id"
 * P1=4 select by "DF name"
 * If P1 == 0, then P2 is 0x0C if T4_V2, 0 if T4_V1.
 * If P1 == 4, then P2 is 0x00.
 *  */
static int ISO_Select(uint8_t *filename, uint8_t fnamelen, uint8_t P1,
		near_recv cb, void *data)
{
	uint16_t P2;
	struct t4_cookie *cookie = data;

	DBG("");

	if (cookie->version == T4_V1 && P1 == 0)
		P2 = 0;
	else
		P2 = P1 ? 0x00 : 0x0C;

	return ISO_send_cmd(
			0x00,		/* CLA */
			0xA4,		/* INS: Select file */
			P1,		/* P1: select by name */
			P2,		/* P2: First or only occurrence */
			filename,	/* cmd_data */
			fnamelen,	/* uint8_t cmd_data_length*/
			false,
			cb,
			data);
}

/* ISO 7816 command: Read binary data from files */
static int ISO_ReadBinary(uint16_t offset, uint8_t readsize,
			near_recv cb, void *cookie)
{
	DBG("");
	return ISO_send_cmd(
			0x00,		/* CLA */
			0xB0,		/* INS: Select file */
			(uint8_t) ((offset & 0xFF00) >> 8),
			(uint8_t) (offset & 0xFF),
			0,		/* no data send */
			readsize,	/* bytes to read */
			false,
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
			(uint8_t) ((offset & 0xFF00) >> 8),
			(uint8_t) (offset & 0xFF),
			data,			/* length of NDEF data */
			nlen,			/* NLEN + NDEF data */
			false,
			cb,
			cookie);
}

static int data_read_cb(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data ;
	uint8_t *nfc_data;
	size_t data_length, length_read, current_length;
	uint16_t remain_bytes;

	DBG("%d", length);

	if (length < 0)
		return t4_cookie_release(length, cookie);

	if (APDU_STATUS(resp + length - 2) != APDU_OK) {
		DBG("Fail read_cb SW:x%04x", APDU_STATUS(resp + length - 2));

		return t4_cookie_release(-EIO, cookie);
	}

	nfc_data = near_tag_get_data(cookie->tag, &data_length);

	/* Remove SW1 / SW2  and NFC header */
	length_read = length - NFC_HEADER_SIZE - 2 ;
	length = length_read;

	current_length = cookie->read_data;

	if ((current_length + length_read) > data_length)
		length_read = data_length - current_length;

	memcpy(nfc_data + current_length, resp + NFC_HEADER_SIZE, length_read);
	if ((current_length + length_read) == data_length) {
		GList *records;

		DBG("Done reading");

		records = near_ndef_parse_msg(nfc_data, data_length, NULL);
		near_tag_add_records(cookie->tag, records, cookie->cb, 0);

		return t4_cookie_release(0, cookie);
	}

	cookie->read_data += length ;
	remain_bytes = data_length - cookie->read_data;

	if (remain_bytes >= cookie->r_apdu_max_size)
		return ISO_ReadBinary(cookie->read_data + 2,
				cookie->r_apdu_max_size, data_read_cb, cookie);
	else
		return ISO_ReadBinary(cookie->read_data + 2,
				(uint8_t) remain_bytes, data_read_cb, cookie);
}

static int t4_readbin_NDEF_ID(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;
	struct near_tag *tag = cookie->tag;
	size_t data_length;
	int err;

	DBG("%d", length);

	if (length < 0)
		return t4_cookie_release(length, cookie);

	if (APDU_STATUS(resp + length - 2) != APDU_OK) {
		DBG("Fail SW:x%04x", APDU_STATUS(resp + length - 2));

		return t4_cookie_release(-EIO, cookie);
	}

	data_length = near_get_be16(resp + NFC_STATUS_BYTE_LEN);

	/* Add data to the tag */
	err = near_tag_add_data(cookie->adapter_idx, cookie->target_idx, NULL,
				data_length);
	if (err < 0)
		return t4_cookie_release(err, cookie);

	near_tag_set_blank(tag, FALSE);

	/* Set write conditions */
	if (cookie->write_access == T4_READ_ONLY)
		near_tag_set_ro(tag, TRUE);
	else
		near_tag_set_ro(tag, FALSE);

	/*
	 * TODO: see how we can get the UID value:
	 * near_tag_set_uid(tag, resp + NFC_HEADER_SIZE, 8);
	 */

	/* Read 1st block */
	if (data_length >= cookie->r_apdu_max_size)
		return ISO_ReadBinary(2, cookie->r_apdu_max_size, data_read_cb,
				cookie);
	else
		return ISO_ReadBinary(2, (uint8_t) data_length, data_read_cb,
				cookie);
}

static int t4_get_file_len(struct t4_cookie *cookie)
{
	cookie->r_apdu_max_size = near_tag_get_r_apdu_max_size(cookie->tag);

	/* Read 2 bytes from offset 0 which conatins the NDEF file length */
	return ISO_ReadBinary(0, 2, t4_readbin_NDEF_ID, cookie);
}

static int t4_select_NDEF_ID(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;

	DBG("%d", length);

	if (length < 0)
		return t4_cookie_release(length, cookie);

	/* Check for APDU error */
	if (APDU_STATUS(resp + STATUS_WORD_1) != APDU_OK) {
		DBG("Fail SW:x%04x", APDU_STATUS(resp + STATUS_WORD_1));

		return t4_cookie_release(-EIO, cookie);
	}

	return t4_get_file_len(cookie);
}

static int t4_readbin_cc(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;
	struct type4_cc *read_cc = (struct type4_cc *)&resp[1];

	DBG("%d", length);

	if (length < 0)
		return t4_cookie_release(length, cookie);

	/* Check APDU error ( the two last bytes of the resp) */
	if (APDU_STATUS(resp + length - 2) != APDU_OK) {
		DBG("Fail SW:x%04x", APDU_STATUS(resp + length - 2));

		return t4_cookie_release(-EIO, cookie);
	}

	cookie->r_apdu_max_size = g_ntohs(read_cc->max_R_apdu_data_size) -
			APDU_HEADER_LEN;
	cookie->c_apdu_max_size = g_ntohs(read_cc->max_C_apdu_data_size);
	cookie->max_ndef_size = g_ntohs(read_cc->tlv_fc.max_ndef_size);

	near_tag_set_max_ndef_size(cookie->tag, cookie->max_ndef_size);
	near_tag_set_c_apdu_max_size(cookie->tag, cookie->c_apdu_max_size);
	near_tag_set_r_apdu_max_size(cookie->tag, cookie->r_apdu_max_size);

	/* TODO 5.1.1: TLV blocks can be zero, one or more... */
	/* TODO 5.1.2: Must ignore proprietary blocks (x05)... */
	if (read_cc->tlv_fc.tag != 0x4) {
		DBG("NDEF File Control tag not found");

		return t4_cookie_release(-EINVAL, cookie);
	}

	/* save rw conditions */
	cookie->write_access = read_cc->tlv_fc.write_access;

	near_tag_set_file_id(cookie->tag, read_cc->tlv_fc.file_id);

	return ISO_Select((uint8_t *) &read_cc->tlv_fc.file_id,
			LEN_ISO_CC_FILEID, 0, t4_select_NDEF_ID, cookie);
}

static int t4_select_cc(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;
	int err;

	DBG("%d", length);

	if (length < 0)
		return t4_cookie_release(length, cookie);

	/* Check for APDU error */
	if (APDU_STATUS(resp + STATUS_WORD_1) != APDU_OK) {

		DBG(" Found empty tag");
		/* Add data to the tag */
		err = near_tag_add_data(cookie->adapter_idx, cookie->target_idx,
					NULL, 1 /* dummy length */);
		if (err < 0)
			return t4_cookie_release(err, cookie);

		near_tag_set_blank(cookie->tag, TRUE);

		if (cookie->cb)
			cookie->cb(cookie->adapter_idx, cookie->target_idx, 0);

		return t4_cookie_release(0, cookie);
	}

	return ISO_ReadBinary(0, LEN_ISO_CC_READ_SIZE, t4_readbin_cc, cookie);
}

static int t4_select_file_by_name_v1(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;

	DBG("%d", length);

	if (length < 0)
		return t4_cookie_release(length, cookie);

	/* Check for APDU error */
	if (APDU_STATUS(resp + STATUS_WORD_1) != APDU_OK) {
		DBG("V1 Fail SW:x%04x", APDU_STATUS(resp + STATUS_WORD_1));

		return t4_cookie_release(-EIO, cookie);
	}

	if (resp[NFC_STATUS] != 0)
		return t4_cookie_release(-EIO, cookie);

	/* Tag is V1 */
	cookie->version = T4_V1;

	/* Jump to select phase */
	return ISO_Select(iso_cc_fileid, LEN_ISO_CC_FILEID, 0,
				t4_select_cc, cookie);
}

static int t4_select_file_by_name_v2(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;

	DBG("%d", length);

	if (length < 0)
		return t4_cookie_release(length, cookie);

	/* Check for APDU error - Not found */
	if (APDU_STATUS(resp + STATUS_WORD_1) == APDU_NOT_FOUND) {
		DBG("Fallback to V1");

		return ISO_Select(iso_appname_v1, ARRAY_SIZE(iso_appname_v1),
					0x4, t4_select_file_by_name_v1, cookie);
	}

	if (APDU_STATUS(resp + STATUS_WORD_1) != APDU_OK) {
		DBG("V2 Fail SW:x%04x", APDU_STATUS(resp + STATUS_WORD_1));

		return t4_cookie_release(-EIO, cookie);
	}

	if (resp[NFC_STATUS] != 0)
		return t4_cookie_release(-EIO, cookie);

	/* Tag is V2 */
	cookie->version = T4_V2;

	/* Jump to select phase */
	return ISO_Select(iso_cc_fileid, LEN_ISO_CC_FILEID, 0, t4_select_cc,
									cookie);
}

static int nfctype4_read(uint32_t adapter_idx,
		uint32_t target_idx, near_tag_io_cb cb)
{
	struct t4_cookie *cookie;

	DBG("");

	cookie = g_try_malloc0(sizeof(struct t4_cookie));
	if (!cookie)
		return -ENOMEM;

	cookie->tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!cookie->tag)
		return t4_cookie_release(-ENOMEM, cookie);

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;
	cookie->read_data = 0;

	/*
	 * If the NDEF file has already been selected by a previous
	 * read, check_presence, or format operation, go straight
	 * to reading the NDEF file length.  Otherwise, go through the
	 * complete NDEF detection procedure.  If near_tag_get_r_apdu_max_size()
	 * returns anything other than 0, we know the NDEF file is selected.
	 */
	if (near_tag_get_r_apdu_max_size(cookie->tag))
		return t4_get_file_len(cookie);
	else
		return ISO_Select(iso_appname_v2, ARRAY_SIZE(iso_appname_v2),
				0x4, t4_select_file_by_name_v2, cookie);
}

static int data_write_cb(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;
	int err = 0;

	DBG("%d", length);

	if (length < 0)
		return t4_cookie_release(length, cookie);

	if (APDU_STATUS(resp + length - 2) != APDU_OK) {
		near_error("write failed SWx%04x",
				APDU_STATUS(resp + length - 2));

		return t4_cookie_release(-EIO, cookie);
	}

	if (cookie->ndef->offset >= cookie->ndef->length) {
		DBG("Done writing");

		if (cookie->cb)
			cookie->cb(cookie->adapter_idx, cookie->target_idx, 0);

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

	return err;
}

static int data_write(uint32_t adapter_idx, uint32_t target_idx,
				struct near_ndef_message *ndef,
				struct near_tag *tag, near_tag_io_cb cb)
{
	struct t4_cookie *cookie;
	int err;

	cookie = g_try_malloc0(sizeof(struct t4_cookie));

	if (!cookie) {
		err = -ENOMEM;

		if (cb)
			cb(adapter_idx, target_idx, err);

		return err;
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

		return t4_cookie_release(-ENOMEM, cookie);
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

	return err;
}

static int nfctype4_write(uint32_t adapter_idx, uint32_t target_idx,
			struct near_ndef_message *ndef, near_tag_io_cb cb)
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

	return data_write(adapter_idx, target_idx, ndef, tag, cb);

out_err:
	if (cb)
		cb(adapter_idx, target_idx, err);

	return err;
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
	struct near_tag *tag;
	uint16_t file_id;

	DBG("");

	tag = near_tag_get_tag(adapter_idx, target_idx);
	if (!tag)
		return -EINVAL;

	cookie = g_try_malloc0(sizeof(struct t4_cookie));
	if (!cookie)
		return -ENOMEM;

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;
	cookie->tag = NULL;
	cookie->read_data = 0;

	file_id = near_tag_get_file_id(tag);

	/* Check for V2 type 4 tag */
	return ISO_Select((uint8_t *)&file_id, LEN_ISO_CC_FILEID, 0,
			check_presence, cookie);
}

static int select_ndef_file(uint8_t *resp, int length, void *data)
{
	struct near_tag *tag;
	struct t4_cookie *cookie = data;

	DBG("%d", length);

	if (length < 0)
		return t4_cookie_release(length, cookie);

	if (APDU_STATUS(resp + STATUS_WORD_1) != APDU_OK) {
		near_error("select ndef file resp failed %02X",
					resp[length - 1]);

		tag = near_tag_get_tag(cookie->adapter_idx, cookie->target_idx);
		if (tag) {
			near_tag_set_max_ndef_size(tag, 0);
			near_tag_set_c_apdu_max_size(tag, 0);
			near_tag_set_r_apdu_max_size(tag, 0);
		}

		return t4_cookie_release(-EIO, cookie);
	}

	DBG("ndef file selected");

	if (cookie->cb)
		cookie->cb(cookie->adapter_idx, cookie->target_idx, 0);

	return t4_cookie_release(0, cookie);
}

static int read_cc_file(uint8_t *resp, int length, void *data)
{
	struct t4_cookie *cookie = data;
	struct near_tag *tag;
	struct type4_cc	*read_cc = NULL;
	int err = 0;

	DBG("%d", length);

	if (length < 0) {
		err = length;
		goto out_err;
	}

	/* Check APDU error ( the two last bytes of the resp) */
	if (APDU_STATUS(resp + length - 2) != APDU_OK) {
		near_error("read cc failed SWx%04x",
					APDU_STATUS(resp + length - 2));
		err = -EIO;
		goto out_err;
	}

	/* -2 for status word and -1 is for NFC first byte... */
	read_cc = g_try_malloc0(length - 2 - NFC_STATUS_BYTE_LEN);
	if (!read_cc) {
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(read_cc, &resp[1], length - 2 - NFC_STATUS_BYTE_LEN) ;
	cookie->r_apdu_max_size = g_ntohs(read_cc->max_R_apdu_data_size) -
			APDU_HEADER_LEN;
	cookie->c_apdu_max_size = g_ntohs(read_cc->max_C_apdu_data_size);
	cookie->max_ndef_size = g_ntohs(read_cc->tlv_fc.max_ndef_size);

	tag = near_tag_get_tag(cookie->adapter_idx, cookie->target_idx);
	if (!tag) {
		err = -EINVAL;
		goto out_err;
	}

	near_tag_set_max_ndef_size(tag, cookie->memory_size);
	near_tag_set_c_apdu_max_size(tag, cookie->c_apdu_max_size);
	near_tag_set_r_apdu_max_size(tag, cookie->r_apdu_max_size);

	if (read_cc->tlv_fc.tag  != 0x4) {
		near_error("NDEF File not found") ;
		err = -EINVAL ;
		goto out_err;
	}

	err = ISO_Select((uint8_t *)&read_cc->tlv_fc.file_id,
			LEN_ISO_CC_FILEID, 0, select_ndef_file, cookie);
	if (err < 0)
		near_error("select ndef file req failed %d", err);

	g_free(read_cc);
	return err;

out_err:
	g_free(read_cc);
	return t4_cookie_release(err, cookie);
}

static int select_cc_file(uint8_t *resp, int length, void *data)
{
	int err = 0;
	struct t4_cookie *cookie = data;

	if (length < 0) {
		near_error("CC file select resp failed %d", length);

		return t4_cookie_release(length, cookie);
	}

	if (APDU_STATUS(resp + STATUS_WORD_1) != APDU_OK) {
		near_error("CC file select response %02X",
						resp[length - 1]);

		return t4_cookie_release(-EIO, cookie);
	}

	err = ISO_ReadBinary(0, LEN_ISO_CC_READ_SIZE, read_cc_file, cookie);
	if (err < 0)
		near_error("read cc file req failed %d", err);

	return err;
}

static int select_iso_appname_v2(uint8_t *resp, int length, void *data)
{
	int err = 0;
	struct t4_cookie *cookie = data;

	if (length < 0) {
		near_error("iso app select resp failed %d", length);

		return t4_cookie_release(length, cookie);
	}

	if (resp[NFC_STATUS] != 0x00) {
		near_error("iso app select response %02X",
					resp[length - 1]);

		return t4_cookie_release(-EIO, cookie);
	}

	err = ISO_Select(iso_cc_fileid, LEN_ISO_CC_FILEID, 0,
			select_cc_file, cookie);
	if (err < 0)
		near_error("select cc req failed %d", err);

	return err;
}

static int format_resp(uint8_t *resp, int length, void *data)
{
	int err = 0;
	struct t4_cookie *cookie = data;
	struct near_tag *tag;

	DBG("");

	if (length < 0) {
		near_error("write data to ndef file resp failed %d", length);

		return t4_cookie_release(length, cookie);
	}

	if (APDU_STATUS(resp + 1) != PICC_LEVEL_APDU_OK) {
		near_error("wrtie data to ndef file response %02X",
						resp[length - 1]);

		return t4_cookie_release(-EIO, cookie);
	}

	tag = near_tag_get_tag(cookie->adapter_idx, cookie->target_idx);
	if (!tag)
		return t4_cookie_release(-EINVAL, cookie);

	DBG("Formatting is done");
	near_tag_set_blank(tag, FALSE);

	/*
	 * 1) Till now all commands which are used for formatting are
	 *    at mifare desfire level. Now select iso appname_v2,
	 *    cc file and ndef file with ISO 7816-4 commands.
	 * 2) Selecting ndef file means making sure that read write
	 *    operations will perform on NDEF file.
	 */
	err = ISO_Select(iso_appname_v2, ARRAY_SIZE(iso_appname_v2),
			0x4, select_iso_appname_v2, cookie);
	if (err < 0)
		near_error("iso_select appnamev2 req failed %d", err);

	return err;
}

static int write_data_to_ndef_file(uint8_t *resp, int length, void *data)
{
	int err = 0;
	struct t4_cookie *cookie = data;
	uint8_t *cmd_data = NULL;
	uint8_t cmd_data_length;
	uint8_t ndef_file_offset[] = {0x00, 0x00, 0x00};
	uint8_t empty_ndef_file_len[] = {0x02, 0x00, 0x00}; /* 000002h */
	uint8_t ndef_nlen[] = {0x00, 0x00}; /* 0000h */

	DBG("");

	if (length < 0) {
		near_error("create ndef file resp failed %d", length);
		err = length;
		goto out_err;
	}

	if (APDU_STATUS(resp + 1) != PICC_LEVEL_APDU_OK) {
		near_error("create ndef file response %02X",
						resp[length - 1]);
		err = -EIO;
		goto out_err;
	}

	/* Step8 : Write data to NDEF file ( no NDEF message) */
	cmd_data_length = 1 /* File num */
				+ ARRAY_SIZE(ndef_file_offset)
				+ ARRAY_SIZE(empty_ndef_file_len)
				+ ARRAY_SIZE(ndef_nlen);

	cmd_data = g_try_malloc0(cmd_data_length);
	if (!cmd_data) {
		err = -ENOMEM;
		goto out_err;
	}

	cmd_data[0] = DESFIRE_NDEF_FILE_NUM;
	memcpy(cmd_data + 1, ndef_file_offset, ARRAY_SIZE(ndef_file_offset));
	memcpy(cmd_data + 4, empty_ndef_file_len,
			ARRAY_SIZE(empty_ndef_file_len));
	memcpy(cmd_data + 7, ndef_nlen, ARRAY_SIZE(ndef_nlen));

	err = ISO_send_cmd(PICC_CLASS, WRITE_DATA_TO_FILE,
				0x00, 0x00, cmd_data, cmd_data_length,
				true, format_resp, cookie);
	if (err < 0)
		near_error("wrtie data to ndef file req failed %d", err);

	g_free(cmd_data);
	return err;

out_err:
	g_free(cmd_data);
	return t4_cookie_release(err, cookie);
}

static int create_ndef_file(uint8_t *resp, int length, void *data)
{
	int err = 0;
	struct t4_cookie *cookie = data;
	struct desfire_std_file *ndef = NULL;
	uint8_t iso_ndef_file_id[] = {0x04, 0xE1}; /* E104h */
	uint8_t ndef_file_access_rights[] = {0xE0, 0xEE}; /* EEE0h */

	DBG("");

	if (length < 0) {
		near_error("write data to cc file resp failed %d", length);
		err = length;
		goto out_err;
	}

	if (APDU_STATUS(resp + 1) != PICC_LEVEL_APDU_OK) {
		near_error("write data to cc file response %02X",
						resp[length - 1]);
		err = -EIO;
		goto out_err;
	}

	ndef = g_try_malloc0(sizeof(struct desfire_std_file));
	if (!ndef) {
		err = -ENOMEM;
		goto out_err;
	}

	ndef->file_num = DESFIRE_NDEF_FILE_NUM;
	memcpy(ndef->file_id, iso_ndef_file_id, ARRAY_SIZE(iso_ndef_file_id));
	ndef->comm_set = DESFIRE_COMMSET;
	memcpy(ndef->access_rights, ndef_file_access_rights,
				ARRAY_SIZE(ndef_file_access_rights));
	ndef->size[0] = 0;
	ndef->size[1] = (uint8_t) (cookie->memory_size >> 8);
	ndef->size[2] = (uint8_t) cookie->memory_size;

	err = ISO_send_cmd(PICC_CLASS, CREATE_STD_DATA_FILE,
				0x00, 0x00, (uint8_t *)ndef,
				sizeof(struct desfire_std_file),
				true, write_data_to_ndef_file, cookie);
	if (err < 0)
		near_error("create ndef file req failed %d", err);

	g_free(ndef);
	return err;

out_err:
	g_free(ndef);
	return t4_cookie_release(err, cookie);
}

static int write_data_to_cc_file(uint8_t *resp, int length, void *data)
{
	int err = 0;
	struct t4_cookie *cookie = data;
	struct desfire_cc_file *cc = NULL;
	uint8_t cc_file_offset[] = {0x00, 0x00, 0x00};
	uint8_t cc_file_max_len[] = {0x0F, 0x00, 0x00}; /* 00000Fh */
	uint8_t cc_len[] = {0x00, 0x0F}; /* 000Fh*/
	uint8_t mle_r_apdu[] = {0x00, 0x3B}; /* 003Bh */
	uint8_t mlc_c_apdu[] = {0x00, 0x34}; /* 0034h */
	/* T: 04, L: 06: V: E104h (NDEF ISO FID = E104h)*/
	uint8_t ndef_tlv[] = {0x04, 0x06, 0xE1, 0x04};


	DBG("");

	if (length < 0) {
		near_error("create cc file resp failed %d", length);
		err = length;
		goto out_err;
	}

	if (APDU_STATUS(resp + 1) != PICC_LEVEL_APDU_OK) {
		near_error("create cc file response %02X",
						resp[length - 1]);
		err = -EIO;
		goto out_err;
	}

	cc = g_try_malloc0(sizeof(struct desfire_cc_file));
	if (!cc) {
		err = -ENOMEM;
		goto out_err;
	}

	cc->file_num = DESFIRE_CC_FILE_NUM;
	memcpy(cc->offset, cc_file_offset, ARRAY_SIZE(cc_file_offset));
	memcpy(cc->max_len, cc_file_max_len, ARRAY_SIZE(cc_file_max_len));
	memcpy(cc->cc_len, cc_len, ARRAY_SIZE(cc_len));
	cc->version = MAPPING_VERSION;
	memcpy(cc->mle, mle_r_apdu, ARRAY_SIZE(mle_r_apdu));
	memcpy(cc->mlc, mlc_c_apdu, ARRAY_SIZE(mlc_c_apdu));
	memcpy(cc->ndef_tlv, ndef_tlv, ARRAY_SIZE(ndef_tlv));
	cc->ndef_size[0] = (uint8_t) (cookie->memory_size >> 8);
	cc->ndef_size[1] = (uint8_t) cookie->memory_size;
	cc->read_access = FREE_READ_ACCESS;
	cc->write_access = FREE_WRITE_ACCESS;

	err = ISO_send_cmd(PICC_CLASS, WRITE_DATA_TO_FILE,
				0x00, 0x00, (uint8_t *)cc,
				sizeof(struct desfire_cc_file),
				true, create_ndef_file, cookie);
	if (err < 0)
		near_error("write data to cc file req failed %d", err);

	g_free(cc);
	return err;

out_err:
	g_free(cc);
	return t4_cookie_release(err, cookie);
}

static int create_cc_file(uint8_t *resp, int length, void *data)
{
	int err = 0;
	struct t4_cookie *cookie = data;
	struct desfire_std_file *cc = NULL;
	uint8_t iso_cc_file_id[] = {0x03, 0xe1}; /* E103h */
	uint8_t cc_file_access_rights[]	= {0xE0, 0xEE}; /* EEE0h */
	uint8_t cc_file_max_len[] = {0x0F, 0x00, 0x00}; /* 00000Fh */

	DBG("");

	if (length < 0) {
		near_error("select application1 resp failed %d", length);
		err = length;
		goto out_err;
	}

	if (APDU_STATUS(resp + 1) != PICC_LEVEL_APDU_OK) {
		near_error("select application1 response %02X",
						resp[length - 1]);
		err = -EIO;
		goto out_err;
	}

	cc = g_try_malloc0(sizeof(struct desfire_std_file));
	if (!cc) {
		err = -ENOMEM;
		goto out_err;
	}

	cc->file_num = DESFIRE_CC_FILE_NUM;
	memcpy(cc->file_id, iso_cc_file_id, ARRAY_SIZE(iso_cc_file_id));
	cc->comm_set = DESFIRE_COMMSET;
	memcpy(cc->access_rights, cc_file_access_rights,
				ARRAY_SIZE(cc_file_access_rights));
	memcpy(cc->size, cc_file_max_len, ARRAY_SIZE(cc_file_max_len));

	err = ISO_send_cmd(PICC_CLASS,
				CREATE_STD_DATA_FILE,
				0x00, 0x00, (uint8_t *)cc,
				sizeof(struct desfire_std_file),
				true, write_data_to_cc_file, cookie);
	if (err < 0)
		near_error("create cc file req failed %d", err);

	g_free(cc);
	return err;

out_err:
	g_free(cc);
	return t4_cookie_release(err, cookie);
}

static int select_application_1(uint8_t *resp, int length, void *data)
{
	int err = 0;
	struct t4_cookie *cookie = data;
	uint8_t *cmd_data = NULL;
	uint8_t cmd_data_length;
	uint8_t desfire_aid_1[]	= {0x01, 0x00, 0x00}; /* 000001h */

	DBG("");

	if (length < 0) {
		near_error("create application resp failed %d", length);
		err = length;
		goto out_err;
	}

	if (APDU_STATUS(resp + 1) != PICC_LEVEL_APDU_OK) {
		near_error("create application response %02X",
						resp[length - 1]);
		err = -EIO;
		goto out_err;
	}

	/* Step4 : Select application (which is created just now) */
	cmd_data_length = ARRAY_SIZE(desfire_aid_1);
	cmd_data = g_try_malloc0(cmd_data_length);
	if (!cmd_data) {
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(cmd_data, desfire_aid_1, cmd_data_length);
	err = ISO_send_cmd(PICC_CLASS, SELECT_APPLICATION,
				0x00, 0x00, cmd_data, cmd_data_length,
				true, create_cc_file, cookie);
	if (err < 0)
		near_error("select application1 req failed %d", err);

	g_free(cmd_data);
	return err;

out_err:
	g_free(cmd_data);
	return t4_cookie_release(err, cookie);
}

static int create_application(uint8_t *resp, int length, void *data)
{
	int err = 0;
	struct t4_cookie *cookie = data;
	uint8_t desfire_aid_1[]	= {0x01, 0x00, 0x00}; /* 000001h */
	uint8_t desfire_file_id[] = {0x10, 0xE1}; /* E110h */
	struct desfire_app *app = NULL;

	DBG("");

	if (length < 0) {
		near_error("select application resp failed %d", length);
		err = length;
		goto out_err;
	}

	if (APDU_STATUS(resp + 1) != PICC_LEVEL_APDU_OK) {
		near_error("select application response %02X",
						resp[length - 1]);
		err = -EIO;
		goto out_err;
	}

	app = g_try_malloc0(sizeof(struct desfire_app));
	if (!app) {
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(app->aid, desfire_aid_1, ARRAY_SIZE(desfire_aid_1));
	app->key_settings = DESFIRE_KEY_SETTINGS;
	app->number_of_keys = DESFIRE_NUM_OF_KEYS;
	memcpy(app->file_id, desfire_file_id, ARRAY_SIZE(desfire_file_id));
	memcpy(app->iso_appname, iso_appname_v2, ARRAY_SIZE(iso_appname_v2));

	/* Step3 : Create Application */
	err = ISO_send_cmd(PICC_CLASS, CREATE_APPLICATION,
				0x00, 0x00, (uint8_t *)app,
				sizeof(struct desfire_app),
				true, select_application_1, cookie);
	if (err < 0)
		near_error("create application req failed %d", err);

	g_free(app);
	return err;

out_err:
	g_free(app);
	return t4_cookie_release(err, cookie);
}

static int select_application(uint8_t *resp, int length, void *data)
{
	int err;
	struct t4_cookie *cookie = data;
	uint8_t *cmd_data = NULL;
	uint8_t cmd_data_length;
	uint8_t desfire_aid[] = {0x00, 0x00, 0x00}; /* 000000h */

	DBG("");

	if (length < 0) {
		near_error("get version3 resp failed %d", length);
		err = length;
		goto out_err;
	}

	if (resp[length - 1] != 0x00) {
		near_error("get version3 response %02X",
						resp[length - 1]);
		err = -EIO;
		goto out_err;
	}

	/* AID : 000000h */
	cmd_data_length = ARRAY_SIZE(desfire_aid);
	cmd_data = g_try_malloc0(cmd_data_length);
	if (!cmd_data) {
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(cmd_data, desfire_aid, cmd_data_length);
	/* Step2 : Select Application */
	err = ISO_send_cmd(PICC_CLASS,
				SELECT_APPLICATION,
				0x00, 0x00, cmd_data, cmd_data_length,
				true, create_application, cookie);
	if (err < 0)
		near_error("select application req failed %d", err);

	g_free(cmd_data);
	return err;

out_err:
	g_free(cmd_data);
	return t4_cookie_release(err, cookie);
}

static int get_version_frame3(uint8_t *resp, int length, void *data)
{
	int err;
	struct t4_cookie *cookie = data;

	DBG("");

	if (length < 0) {
		near_error("get version2 resp failed %d", length);

		return t4_cookie_release(length, cookie);
	}

	if (resp[4] == 0x01 /* Major Version */
		&& resp[length - 1] == GET_VERSION_FRAME_RESPONSE_BYTE) {

		err = ISO_send_cmd(PICC_CLASS,
					GET_VERSION_FRAME_RESPONSE_BYTE,
					0x00, 0x00, NULL, 0, false,
					select_application, cookie);
		if (err < 0)
			near_error("get version3 req failed %d", err);

		return err;
	}

	near_error("get version2 response %02X", resp[length - 1]);

	return t4_cookie_release(-EIO, cookie);
}

static int get_version_frame2(uint8_t *resp, int length, void *data)
{
	int err;
	struct t4_cookie *cookie = data;

	DBG("");

	if (length < 0) {
		near_error(" get version resp failed %d", length);

		return t4_cookie_release(length, cookie);
	}

	if (resp[4] == 0x01 /* Major Version */
		&& resp[length - 1] == GET_VERSION_FRAME_RESPONSE_BYTE) {

		/*
		 * When N is the GET_VERSION response 6th byte,
		 * the DESFire tag memory size is 2 ^ (N /2).
		 */
		cookie->memory_size = (1 << (resp[6] / 2));
		err = ISO_send_cmd(PICC_CLASS,
					GET_VERSION_FRAME_RESPONSE_BYTE,
					0x00, 0x00, NULL, 0, false,
					get_version_frame3, cookie);
		if (err < 0)
			near_error("get version2 req failed %d", err);

		return err;
	}

	near_error("get version response %02X", resp[length - 1]);

	return t4_cookie_release(-EIO, cookie);
}

/* Steps to format Type 4 (MIFARE DESFire EV1) tag as per AN1104.pdf from nxp.
 * 1) Get version to determine memory size of tag
 * 2) Select applciation with AID equal to 000000h (PICC level)
 * 3) Create application with AID equal to 000001h
 * 4) Select application (Select previously created application in step3)
 * 5) Create std data file with File number equal to 01h (CC file), ISOFileID
 *    equal to E103h, ComSet equal to 00h, AccesRights to EEEEh, FileSize bigger
 *    equal to 00000Fh
 * 6) Write data to CC file with CCLEN equal to 000Fh, Mapping version equal to
 *    20h, MLe equal to 003Bh, MLc equal to 0034h, and NDEF File control TLV
 *    equal to: T=04h, L=06h, V=E1 04 (NDEF ISO FID = E104h), 08 00 (NDEF File
 *    size = 2048 Bytes) 00 (free read access) 00 (free write access)
 * 7) Create std data file with File number equal to 02h (NDEF File DESFireFId),
 *    ISO FileID equal to E104h, ComSet equal to 00h, ComSet equal to 00h,
 *    AccessRights equal to EEE0h, FileSize equal to 000800h (2048 bytes)
 * 8) Write data to write content of the NDEF File with NLEN equal to 0000h, and
 *    no NDEF messsage.
 * 9) Now Formatting is done, then select ISO appname2, select CC file and read.
 * 10) Select NDEF file (by doing last two steps means, making sure that read
 *    write operations perform on NDEF file).
 * */

static int nfctype4_format(uint32_t adapter_idx, uint32_t target_idx,
						near_tag_io_cb cb)
{
	int err;
	struct t4_cookie *cookie;

	DBG("");

	cookie = g_try_malloc0(sizeof(struct t4_cookie));
	if (!cookie)
		return -ENOMEM;

	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;

	/* Step1 : Get Version */
	err = ISO_send_cmd(PICC_CLASS, GET_VERSION,
				0x00, 0x00, NULL, 0, false,
				get_version_frame2, cookie);

	if (err < 0)
		near_error("get version req failed %d", err);

	return err;
}

static struct near_tag_driver type4a_driver = {
	.type           = NFC_PROTO_ISO14443,
	.priority       = NEAR_TAG_PRIORITY_DEFAULT,
	.read           = nfctype4_read,
	.write          = nfctype4_write,
	.check_presence = nfctype4_check_presence,
	.format		= nfctype4_format,
};

static struct near_tag_driver type4b_driver = {
	.type           = NFC_PROTO_ISO14443_B,
	.priority       = NEAR_TAG_PRIORITY_DEFAULT,
	.read           = nfctype4_read,
	.write          = nfctype4_write,
	.check_presence = nfctype4_check_presence,
	.format		= nfctype4_format,
};

static int nfctype4_init(void)
{
	int ret;

	DBG("");

	ret = near_tag_driver_register(&type4b_driver);
	if (ret < 0)
		return ret;

	return near_tag_driver_register(&type4a_driver);
}

static void nfctype4_exit(void)
{
	DBG("");

	near_tag_driver_unregister(&type4a_driver);
	near_tag_driver_unregister(&type4b_driver);
}

NEAR_PLUGIN_DEFINE(nfctype4, "NFC Forum Type 4 tags support", VERSION,
		NEAR_PLUGIN_PRIORITY_HIGH, nfctype4_init, nfctype4_exit)

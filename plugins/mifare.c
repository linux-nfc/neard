/*
 *
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

/*
 * NXP Application Notes:
 * AN1304, AN1305, ...
 * http://www.nxp.com/technical-support-portal/53420/71108/application-notes
 */

/* Prototypes */
int mifare_read(uint32_t adapter_idx, uint32_t target_idx,
		near_tag_io_cb cb, enum near_tag_sub_type tgt_subtype);

int mifare_check_presence(uint32_t adapter_idx, uint32_t target_idx,
		near_tag_io_cb cb, enum near_tag_sub_type tgt_subtype);

int mifare_write(uint32_t adapter_idx, uint32_t target_idx,
		struct near_ndef_message *ndef,
		near_tag_io_cb cb, enum near_tag_sub_type tgt_subtype);

/* MIFARE command set */
#define MF_CMD_WRITE		0xA0
#define MF_CMD_READ		0x30
#define MF_CMD_AUTH_KEY_A	0x60

#define NFC_AID_TAG		0xE103

/*
 * Define boundaries for 1K / 2K / 4K
 * 1K:   sector 0 to 15 (3 blocks each + trailer block )
 * 2K:   sector 0 to 31 (3 blocks each + trailer block )
 * 4K:   sector 0 to 31 (3 blocks each + trailer block )
 *	and sector 32 to 39 (15 blocks each + trailer block )
 */
#define DEFAULT_BLOCK_SIZE	16	/* MF_CMD_READ */

#define STD_BLK_SECT_TRAILER	4	/* bl per sect with trailer 1K/2K */
#define EXT_BLK_SECT_TRAILER	16	/* bl per sect with trailer 4K */

#define STD_BLK_PER_SECT	3	/* 1 sect == 3blocks */
#define EXT_BLK_PER_SECT	15	/* for 4K tags */

/* Usual sector size, including trailer */
#define STD_SECTOR_SIZE		(4 * DEFAULT_BLOCK_SIZE)	/* 00-31 */
#define EXT_SECTOR_SIZE		(16 * DEFAULT_BLOCK_SIZE)	/* 32-39 */

/* Usual sector size, without trailer */
#define SECTOR_SIZE		(3 * DEFAULT_BLOCK_SIZE)
#define BIG_SECTOR_SIZE		(15 * DEFAULT_BLOCK_SIZE)

#define T4K_BOUNDARY		32
#define T4K_BLK_OFF		0x80	/* blocks count before sector 32 */

#define NO_TRAILER	0
#define WITH_TRAILER	1
#define SECT_IS_NFC	1

/* Default MAD keys. Key length = 6 bytes */
#define MAD_KEY_LEN	6
static uint8_t MAD_public_key[] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};
static uint8_t MAD_NFC_key[] = {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7};

#define MAD1_SECTOR		0x00	/* Sector 0 is for MAD1 */
#define MAD1_1ST_BLOCK		0x00	/* 1st block of sector 0 */
#define	MAD2_GPB_BITS		0x02	/* MAD v2 flag */

#define MAD2_SECTOR		0x10	/* Sector 16 is for MAD2 */
#define MAD2_1ST_BLOCK		0x40	/* 1st block of MAD2 */

#define MAD_V1_AIDS_LEN		15	/* 1 to 0x0F */
#define MAD_V2_AIDS_LEN		23	/*0x11 to 0x27 */

#define NFC_1ST_BLOCK		0x04	/* Sectors from 1 are for NFC */

#define ACC_BITS_LEN            3

/* Access bits for data blocks mask */
static uint8_t DATA_access_mask[] = {0x77, 0x77, 0x77};

/* Write with key A access bits configuration */
static uint8_t WRITE_with_key_A[] = {0x77, 0x07, 0x00};

/* MAD1 sector structure. Start at block 0x00 */
struct MAD_1 {
	uint8_t man_info[16];
	uint16_t crc_dir;
	uint16_t aids[MAD_V1_AIDS_LEN];
	/* Trailer */
	uint8_t key_A[MAD_KEY_LEN];
	uint8_t access_cond[3];
	uint8_t GPB;
	uint8_t key_B[MAD_KEY_LEN];
} __attribute__((packed));

/* MAD2 sector structure. Start at block 0x40 */
struct MAD_2 {
	uint16_t crc_dir;
	uint16_t aids[MAD_V2_AIDS_LEN];
	/* Trailer */
	uint8_t key_A[MAD_KEY_LEN];
	uint8_t access_cond[3];
	uint8_t GPB;
	uint8_t key_B[MAD_KEY_LEN];
} __attribute__((packed));

struct mifare_cookie {
	uint32_t adapter_idx;
	uint32_t target_idx;
	uint8_t *nfcid1;
	uint8_t nfcid1_len;

	struct near_tag *tag;
	near_tag_io_cb cb;
	near_recv next_far_func;

	/* For MAD access */
	struct MAD_1 *mad_1;
	struct MAD_2 *mad_2;
	GSList *g_sect_list;		/* Global sectors list */

	/* For read and write functions */
	near_recv rws_next_fct;		/* next function */
	int rws_block_start;		/* first block */
	int rws_block_end;		/* last block */
	int rws_completed;		/* read blocks */


	/* For read only */
	int rs_length;			/* read length */
	uint8_t *rs_pmem;		/* Stored read sector */
	int rs_max_length;		/* available size */
	uint8_t *nfc_data;
	size_t nfc_data_length;

	/* For write only */
	struct near_ndef_message *ndef;	/* message to write */
	size_t ndef_length;		/* message length */

	/* For access check */
	int (*acc_check_function)(void *data);	/* acc check fnc */
	uint8_t *acc_bits_mask;			/* blocks to check */
	uint8_t *acc_rights;			/* condition */
	int (*acc_denied_fct)(void *data);/* fnc to call on access denial */
	GSList *acc_sect;		  /* sector from g_sect_list to check */
};

struct type2_cmd {
	uint8_t cmd;
	uint8_t block;
	uint8_t data[];
} __attribute__((packed));

struct mf_write_cmd {
	uint8_t cmd;
	uint8_t block;
	uint8_t data[DEFAULT_BLOCK_SIZE];
} __attribute__((packed));

struct mifare_cmd {
	uint8_t cmd;
	uint8_t block;
	uint8_t key[MAD_KEY_LEN];
	uint8_t nfcid[NFC_NFCID1_MAXSIZE];
} __attribute__((packed));

static int mifare_release(int err, void *data)
{
	struct mifare_cookie *cookie = data;

	DBG("%p", cookie);

	if (!cookie)
		return err;

	if (err < 0 && cookie->cb) {
		cookie->cb(cookie->adapter_idx, cookie->target_idx, err);
		near_adapter_disconnect(cookie->adapter_idx);
	}

	/* Now free allocs */
	g_free(cookie->nfcid1);
	g_slist_free(cookie->g_sect_list);
	g_free(cookie->mad_1);
	g_free(cookie->mad_2);

	if (cookie->ndef)
		g_free(cookie->ndef->data);

	g_free(cookie->ndef);
	g_free(cookie);
	cookie = NULL;

	return err;
}

/*
 * Mifare_generic MAD unlock block function
 * This function send unlock code to the tag, and so, allow access
 * to the complete related sector.
 */
static int mifare_unlock_sector(int block_id,
				near_recv next_far_fct,
				void *data)
{
	struct mifare_cmd cmd;
	struct mifare_cookie *cookie = data;
	uint8_t *key_ref;

	/*
	 * For MADs sectors we use public key A (a0a1a2a3a4a5) but
-	 * for NFC sectors we use NFC_KEY_A (d3f7d3f7d3f7)
	 */
	if ((block_id == MAD1_1ST_BLOCK) || (block_id == MAD2_1ST_BLOCK))
		key_ref = MAD_public_key;
	else
		key_ref = MAD_NFC_key;

	 /* CMD AUTHENTICATION */
	cmd.cmd = MF_CMD_AUTH_KEY_A;

	/* Authenticate will be on the 1st block of the sector */
	cmd.block = block_id;

	/* Store the AUTH KEY */
	memcpy(&cmd.key, key_ref, MAD_KEY_LEN);

	/* add the UID */
	memcpy(&cmd.nfcid, cookie->nfcid1, cookie->nfcid1_len);

	return near_adapter_send(cookie->adapter_idx, (uint8_t *)&cmd,
		sizeof(cmd) - NFC_NFCID1_MAXSIZE + cookie->nfcid1_len,
		next_far_fct, cookie, mifare_release);
}

/*
 * Common MIFARE Block read:
 * Each call will read 16 bytes from tag... so to read 1 sector,
 * it has to be called it 4 times or 16 times
 * (minus 1 or not for the trailer block)
 *
 * data: mifare_cookie *mf_ck
 * mf_ck->read_block: block number to read
 */
static int mifare_read_block(uint8_t block_id,
				void *data,
				near_recv far_func)
{
	struct type2_cmd cmd;
	struct mifare_cookie *mf_ck = data;

	cmd.cmd = MF_CMD_READ; /* MIFARE READ */
	cmd.block = block_id;

	return near_adapter_send(mf_ck->adapter_idx, (uint8_t *) &cmd, 2,
					far_func, mf_ck, mifare_release);
}

/*
 * Check access rights
 * Function processes sector trailer received from tag and checks access rights.
 * In case specified access isn't granted it calls appropriate
 * access denial function.
 * If access is granted, previous action (e.g. read, write) is continued.
 */
static int mifare_check_rights_cb(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;
	uint8_t *c;
	int i;

	if (length < 0) {
		err = length;
		goto out_err;
	}

	/* skip reader byte and key A */
	 c = resp + 1 + MAD_KEY_LEN;

	for (i = 0; i < ACC_BITS_LEN; i++) {
		if ((c[i] & mf_ck->acc_bits_mask[i]) != mf_ck->acc_rights[i]) {
			(*mf_ck->acc_denied_fct)(data);
			return 0;
		}
	}

	/* Continue previous action (read/write) */
	err = (*mf_ck->rws_next_fct)(resp, length, data);

	if (err < 0)
		goto out_err;

	return err;

out_err:
	return mifare_release(err, mf_ck);
}

/* Calls to mifare_read_block to get sector trailer */
static int mifare_check_rights(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;

	err = mifare_read_block(mf_ck->rws_block_start, mf_ck,
			mifare_check_rights_cb);

	if (err < 0)
		return mifare_release(err, mf_ck);

	return err;
}

static int mifare_read_sector_cb(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err = -1;

	if (length < 0) {
		err = length;
		goto out_err;
	}

	/* Save the data */
	length = length - 1; /* ignore first byte - Reader byte */

	/* save the length: */
	mf_ck->rs_length = mf_ck->rs_length + length;

	memcpy(mf_ck->rs_pmem + mf_ck->rws_completed * DEFAULT_BLOCK_SIZE,
			resp + 1,/* ignore reader byte */
			length);

	/* Next block */
	mf_ck->rws_completed = mf_ck->rws_completed + 1;

	if ((mf_ck->rws_block_start + mf_ck->rws_completed)
						< mf_ck->rws_block_end)
		err = mifare_read_block(
				(mf_ck->rws_block_start + mf_ck->rws_completed),
				data,
				mifare_read_sector_cb);
	else {
		/* Now Process the callback ! */
		err = (*mf_ck->rws_next_fct)(mf_ck->rs_pmem,
						mf_ck->rs_length, data);
	}

	if (err < 0)
		goto out_err;
	return err;

out_err:
	return mifare_release(err, mf_ck);
}

static int mifare_read_sector_unlocked(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;

	if (length < 0) {
		err = length;
		goto out_err;
	}
	/* And run the read process on the first block of the sector */
	err = mifare_read_block(mf_ck->rws_block_start, data,
				mifare_read_sector_cb);

	if (err < 0)
		goto out_err;
	return err;

out_err:
	return mifare_release(err, mf_ck);
}

/*
 * This function reads a complete sector, using block per block function.
 * sector sizes can be:
 * Sectors 0 to 31:
 *	48 bytes: 3*16 no trailer
 *	64 bytes: 4*16 with trailer
 * Sectors 32 to 39:
 *	240 bytes: 15*16 no trailer
 *	256 bytes: 16*16 with trailer
 *
 * Unlock is done at the beginning of first sector.
 */
static int mifare_read_sector(void *cookie,
			uint8_t *pmem,		/* memory to fill */
			uint16_t memsize,	/* remaining free size */
			uint8_t	sector_id,	/* sector to read */
			bool trailer,	/* Add trailer or not */
			near_recv next_func)
{
	struct mifare_cookie *mf_ck = cookie;
	int err;
	int blocks_count;

	DBG("");

	/* Prepare call values */
	mf_ck->rs_pmem = pmem;			/* where to store */
	mf_ck->rs_max_length = memsize;		/* max size to store */
	mf_ck->rs_length = 0;			/* no bytes yet */
	mf_ck->rws_completed = 0;		/* blocks read */

	/* According to tag size, compute the correct block offset */
	if (sector_id < T4K_BOUNDARY)
		mf_ck->rws_block_start = sector_id * 4;  /* 1st block to read */
	else
		mf_ck->rws_block_start =
				(sector_id - T4K_BOUNDARY) * 16 + T4K_BLK_OFF;

	/* Find blocks_per_sect, according to position and trailer or not */
	if (sector_id < T4K_BOUNDARY)
		blocks_count = (STD_BLK_PER_SECT + trailer);
	else
		blocks_count = (EXT_BLK_PER_SECT + trailer);

	mf_ck->rws_block_end = mf_ck->rws_block_start + blocks_count;

	mf_ck->rws_next_fct = next_func;		/* leaving function */

	/* Being on the first block of a sector, unlock it */
	err = mifare_unlock_sector(mf_ck->rws_block_start,
			mifare_read_sector_unlocked, mf_ck);

	return err;
}

static int mifare_read_NFC_loop(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err = 0;

	DBG("");

	if (length < 0) {
		err = length;
		goto out_err;
	}

	/* ptr to the next read ptr */
	mf_ck->nfc_data = mf_ck->nfc_data + length;

	/* remaining free mem */
	mf_ck->nfc_data_length = mf_ck->nfc_data_length - length;


	/* Additional sectors to read ? */;
	if (mf_ck->g_sect_list && mf_ck->g_sect_list->next) {

		err = mifare_read_sector(data,	/* cookie */
			mf_ck->nfc_data,		/* where to store */
			(int) mf_ck->nfc_data_length,	/* global length */
			GPOINTER_TO_INT(mf_ck->g_sect_list->data), /* id */
			NO_TRAILER,			/* Trailer ? */
			mifare_read_NFC_loop);		/* next function */

		mf_ck->g_sect_list = g_slist_remove(mf_ck->g_sect_list,
						mf_ck->g_sect_list->data);

		if (err < 0)
			goto out_err;
		return err;
	} else {
		GList *records;
		uint8_t *nfc_data;
		size_t nfc_data_length;

		DBG("Done reading");

		nfc_data = near_tag_get_data(mf_ck->tag, &nfc_data_length);
		if (!nfc_data) {
			err = -ENOMEM;
			goto out_err;
		}

		records = near_tlv_parse(nfc_data, nfc_data_length);
		near_tag_add_records(mf_ck->tag, records, mf_ck->cb, 0);

		err = 0;
	}

out_err:
	return mifare_release(err, mf_ck);
}

/* Prepare read NFC loop */
static int mifare_read_NFC(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;

	/* save tag memory pointer to data_block */
	mf_ck->nfc_data = near_tag_get_data(mf_ck->tag,
					&mf_ck->nfc_data_length);

	/* First read here: */
	err = mifare_read_sector(data,		/* cookie */
		mf_ck->nfc_data,		/* where to store */
		mf_ck->nfc_data_length,		/* global length */
		GPOINTER_TO_INT(mf_ck->g_sect_list->data), /* sector id */
		NO_TRAILER,			/* Don't want Trailer */
		mifare_read_NFC_loop);		/* next function */

	mf_ck->g_sect_list = g_slist_remove(mf_ck->g_sect_list,
						mf_ck->g_sect_list->data);
	if (err < 0)
		goto out_err;
	return err;

out_err:
	return mifare_release(err, mf_ck);
}

static int mifare_process_MADs(void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;
	int i;
	int global_tag_size = 0;
	int ioffset;
	uint8_t *tag_data;
	size_t data_size;

	DBG("");

	/* Parse MAD entries to get the global size and fill the array */
	if (!mf_ck->mad_1) {
		err = -EINVAL;
		goto out_err;
	}

	/* Skip non-NFC sectors at the beginning of the tag, if any */
	for (i = 0 ; i < MAD_V1_AIDS_LEN; i++) {
		if (mf_ck->mad_1->aids[i] == NFC_AID_TAG)
			break;
	}

	/*
	 * NFC sectors have to be continuous,
	 * so only some sectors at the beginning and at the end of tag
	 * can be non-NFC.
	 */
	for (; i < MAD_V1_AIDS_LEN; i++) {
		if (mf_ck->mad_1->aids[i] != NFC_AID_TAG)
			goto done_mad;

		/* Save in the global list */
		mf_ck->g_sect_list = g_slist_append(mf_ck->g_sect_list,
						GINT_TO_POINTER(i + 1));
		global_tag_size += SECTOR_SIZE;
	}

	/* Now MAD 2 */
	ioffset = MAD_V1_AIDS_LEN + 1 + 1; /* skip 0x10 */
	if (!mf_ck->mad_2)
		goto done_mad;

	/*
	 * If all sectors from MAD1 were non-NFC,
	 * skip initial non-NFC sectors from MAD2
	 */
	i = 0;

	if (global_tag_size == 0)
		for (; i < MAD_V2_AIDS_LEN; i++)
			if (mf_ck->mad_2->aids[i] == NFC_AID_TAG)
				break;

	for (; i < MAD_V2_AIDS_LEN; i++) {
		if (mf_ck->mad_2->aids[i] != NFC_AID_TAG)
			goto done_mad;

		mf_ck->g_sect_list = g_slist_append(mf_ck->g_sect_list,
						GINT_TO_POINTER(ioffset + i));
		if (i < EXT_BLK_PER_SECT)
			global_tag_size += SECTOR_SIZE;
		else
			global_tag_size += BIG_SECTOR_SIZE;
	}

done_mad:
	if (global_tag_size == 0) {

		/* no NFC sectors - mark tag as blank */
		near_error("TAG Global size: [%d], not valid NFC tag.",
				global_tag_size);
		return -ENODEV;
	}

	/* n sectors, each sector is 3 blocks, each block is 16 bytes */
	DBG("TAG Global size: [%d]", global_tag_size);

	mf_ck->tag = near_tag_get_tag(mf_ck->adapter_idx, mf_ck->target_idx);
	if (!mf_ck->tag) {
		err = -ENOMEM;
		goto out_err;
	}

	/* don't allocate new data before writing */
	tag_data = near_tag_get_data(mf_ck->tag, &data_size);
	if (!tag_data) {
		err = near_tag_add_data(mf_ck->adapter_idx,
						mf_ck->target_idx,
						NULL, /* Empty */
						global_tag_size);

		if (err < 0)
			goto out_err;
	}

	/* Check access rights */
	err = mf_ck->acc_check_function(data);

	if (err < 0)
		goto out_err;

	return err;

out_err:
	return mifare_release(err, mf_ck);
}

/* Transitional function - async */
static int read_MAD2_complete(uint8_t *empty, int iempty, void *data)
{
	return mifare_process_MADs(data);
}

/* This function reads the MAD2 sector */
static int mifare_read_MAD2(void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err = 0;

	DBG("");

	/* As auth is ok, allocate Mifare Access Directory v1 */
	mf_ck->mad_2 = g_try_malloc0(STD_SECTOR_SIZE);
	if (!mf_ck->mad_2) {
		near_error("Memory allocation failed (MAD2)");
		err = -ENOMEM;
		goto out_err;
	}

	err = mifare_read_sector(data,
			(uint8_t *) mf_ck->mad_2,
			(int) STD_SECTOR_SIZE,
			MAD2_SECTOR,			/* sector 0x10 */
			WITH_TRAILER,			/* Want Trailer */
			read_MAD2_complete);

	if (err < 0)
		goto out_err;
	return err;

out_err:
	return mifare_release(err, mf_ck);
}

/*
 * This function checks, in MAD1, if there's a MAD2 directory
 * available. This is is the case for 2K and 4K tag
 * If MAD2 exists, read it, elsewhere process the current MAD
 */
static int read_MAD1_complete(uint8_t *empty, int iempty, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;

	DBG("");

	/* Check if there's a need to get MAD2 sector */
	if ((mf_ck->mad_1->GPB & 0x03) == MAD2_GPB_BITS)
		err = mifare_read_MAD2(mf_ck);
	else
		err = mifare_process_MADs(data);

	return err;
}

/*
 * Function called to read the first MAD sector
 * MAD is mandatory
 */
static int mifare_read_MAD1(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err = 0;

	DBG("%p %d", data, length);

	if (length < 0) {
		err = length;
		return err;
	}

	/*
	 * As auth is ok, allocate Mifare Access Directory v1
	 * allocated size is also STD_SECTOR_SIZE
	 */
	mf_ck->mad_1 = g_try_malloc0(STD_SECTOR_SIZE);
	if (!mf_ck->mad_1) {
		near_error("Memory allocation failed (MAD1)");
		err = -ENOMEM;
		goto out_err;
	}

	/* Call to mifare_read_sector */
	err = mifare_read_sector(data,
			(uint8_t *)mf_ck->mad_1,	/* where to store */
			(int) STD_SECTOR_SIZE,		/* allocated size */
			MAD1_SECTOR,			/* sector 0 */
			WITH_TRAILER,			/* Want Trailer */
			read_MAD1_complete);

	if (err < 0)
		goto out_err;
	return err;

out_err:
	return mifare_release(err, mf_ck);
}

/* If first NFC sector isn't writable, mark whole tag as read only */
static int is_read_only(void *data)
{
	struct mifare_cookie *mf_ck = data;

	DBG("Tag is read only");

	near_tag_set_ro(mf_ck->tag, TRUE);

	/* Continue previous action (read) */
	(*mf_ck->rws_next_fct)(NULL, 0, data);

	return 0;
}


static int mifare_check_read_only(void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;

	DBG("");

	/*
	 * As authorisation with key B is not supported,
	 * in case writing with key A is not permitted, tag is read-only
	 */
	mf_ck->acc_bits_mask = DATA_access_mask;
	mf_ck->acc_rights = WRITE_with_key_A;

	/* Check acces rights of first NFC sector */
	mf_ck->rws_block_start = NFC_1ST_BLOCK + STD_BLK_PER_SECT;
	/* Afterwards read tag */
	mf_ck->rws_next_fct = mifare_read_NFC;
	/* In case of writing access denial, set read only */
	mf_ck->acc_denied_fct = is_read_only;

	err = mifare_unlock_sector(mf_ck->rws_block_start,
			mifare_check_rights, mf_ck);

	if (err < 0)
		return mifare_release(err, mf_ck);

	return err;
}

/*
 * MIFARE: entry point:
 * Read all the MAD sectors (0x00, 0x10) to get the Application Directory
 * entries.
 * On sector 0x00, App. directory is on block 0x01 & block 0x02
 * On sector 0x10, App. directory is on block 0x40, 0x41 & 0x42
 * On reading, CRC is ignored.
 */
int mifare_read(uint32_t adapter_idx, uint32_t target_idx,
		near_tag_io_cb cb, enum near_tag_sub_type tgt_subtype)
{
	struct mifare_cookie *cookie;
	int err;

	DBG("");

	/*Check supported and tested Mifare type */
	switch (tgt_subtype) {
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_1K:
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_4K:
		break;
	default:
		near_error("Mifare tag type [%d] not supported.", tgt_subtype);
		return -1;
	}

	/* Alloc global cookie */
	cookie = g_try_malloc0(sizeof(struct mifare_cookie));
	if (!cookie)
		return -ENOMEM;

	/* Get the nfcid1 */
	cookie->nfcid1 = near_tag_get_nfcid(adapter_idx, target_idx,
				&cookie->nfcid1_len);
	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;

	/* check access rights - while reading just check read only */
	cookie->acc_check_function = mifare_check_read_only;

	/*
	 * Need to unlock before reading
	 * This will check if public keys are allowed (and, so, NDEF could
	 * be "readable"...
	 */
	err = mifare_unlock_sector(MAD1_1ST_BLOCK,	/* related block */
				mifare_read_MAD1,	/* callback function */
				cookie);		/* target data */
	if (err < 0)
		return mifare_release(err, cookie);

	return 0;
}

static int check_presence(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *cookie = data;
	int err = 0;

	DBG("%d", length);

	if (length < 0) {
		err = -EIO;
		goto out;
	}

	if (cookie->cb)
		cookie->cb(cookie->adapter_idx, cookie->target_idx, err);

out:
	return mifare_release(err, cookie);
}

int mifare_check_presence(uint32_t adapter_idx, uint32_t target_idx,
			near_tag_io_cb cb, enum near_tag_sub_type tgt_subtype)
{
	struct mifare_cmd cmd;
	struct mifare_cookie *cookie;
	uint8_t *key_ref = MAD_public_key;

	DBG("");

	/* Check supported and tested Mifare type */
	switch (tgt_subtype) {
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_1K:
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_4K:
		break;
	default:
		near_error("Mifare tag type %d not supported.", tgt_subtype);
		return -1;
	}

	/* Alloc global cookie */
	cookie = g_try_malloc0(sizeof(struct mifare_cookie));
	if (!cookie)
		return -ENOMEM;

	/* Get the nfcid1 */
	cookie->nfcid1 = near_tag_get_nfcid(adapter_idx, target_idx,
					&cookie->nfcid1_len);
	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;

	/*
	 * To check presence of Mifare Classic Tag,
	 * send authentication command instead of read one
	 */
	cmd.cmd = MF_CMD_AUTH_KEY_A;

	/* Authenticate the 1st block of the MAD sector */
	cmd.block = MAD1_1ST_BLOCK;

	/* Store the AUTH KEY */
	memcpy(&cmd.key, key_ref, MAD_KEY_LEN);

	/* add the UID */
	memcpy(&cmd.nfcid, cookie->nfcid1, cookie->nfcid1_len);

	return near_adapter_send(cookie->adapter_idx,
			(uint8_t *) &cmd,
			sizeof(cmd) - NFC_NFCID1_MAXSIZE + cookie->nfcid1_len,
			check_presence,
			cookie, mifare_release);
}

/*
 * Common MIFARE Block write:
 * Each call will write 16 bytes to tag... so to write 1 sector,
 * it has to be called it 4 or 16 times (minus 1 for the trailer block)
 */
static int mifare_write_block(uint8_t block_id, void *data,
				near_recv far_func)
{
	struct mf_write_cmd cmd;
	struct mifare_cookie *mf_ck = data;

	memset(&cmd, 0, sizeof(cmd));
	cmd.cmd = MF_CMD_WRITE; /* MIFARE WRITE */
	cmd.block = block_id;

	if ((mf_ck->ndef->offset + DEFAULT_BLOCK_SIZE) <
			mf_ck->ndef->length) {
		memcpy(cmd.data, mf_ck->ndef->data +
				mf_ck->ndef->offset, DEFAULT_BLOCK_SIZE);
		mf_ck->ndef->offset += DEFAULT_BLOCK_SIZE;
	} else {
		memcpy(cmd.data, mf_ck->ndef->data + mf_ck->ndef->offset,
				mf_ck->ndef->length - mf_ck->ndef->offset);
		mf_ck->ndef->offset = mf_ck->ndef->length + 1;
	}

	return near_adapter_send(mf_ck->adapter_idx,
				(uint8_t *) &cmd, sizeof(cmd),
				far_func, data, NULL);
}

static int mifare_correct_length_cb(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;

	DBG("Done writing");

	if (mf_ck->cb)
		mf_ck->cb(mf_ck->adapter_idx, mf_ck->target_idx, 0);

	return mifare_release(0, mf_ck);
}

/* After writing ndef message, its length has to be updated */
static int mifare_correct_length(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;

	DBG("");

	/* Correct length field */
	mf_ck->ndef->data[1] = mf_ck->ndef_length;
	/* and ndef offset so it points to the beginning */
	mf_ck->ndef->offset = 0;

	/* Run the write process only on the first block of the sector */
	return mifare_write_block(NFC_1ST_BLOCK, mf_ck,
					mifare_correct_length_cb);
}

static int mifare_write_sector_cb(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;

	/* Next block */
	mf_ck->rws_completed = mf_ck->rws_completed + 1;

	/* Check if it's the last block */
	if ((mf_ck->rws_block_start + mf_ck->rws_completed)
			< mf_ck->rws_block_end)	{
		/* then check if there's still data to write */
		if (mf_ck->ndef->offset < mf_ck->ndef->length)
			err = mifare_write_block(
				mf_ck->rws_block_start + mf_ck->rws_completed,
				data, mifare_write_sector_cb);
		else
			/* No more Data to write */
			/* Correct length of the ndef message */
			err = mifare_unlock_sector(NFC_1ST_BLOCK,
						mifare_correct_length, mf_ck);
	} else {
		/* Process the callback */
		err = (*mf_ck->rws_next_fct)(resp, length, data);
	}

	if (err < 0)
		return mifare_release(err, mf_ck);

	return err;

}

static int mifare_write_sector_unlocked(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;

	if (length < 0) {
		err = length;
		goto out_err;
	}

	/* Run the write process on the first block of the sector */
	err = mifare_write_block(mf_ck->rws_block_start, data,
			mifare_write_sector_cb);

	if (err < 0)
		goto out_err;
	return err;

out_err:
	return mifare_release(err, mf_ck);
}

/*
 * This function writes a complete sector, using block per block function.
 * sector sizes can be:
 * Sectors 0 to 31:
 *	48 bytes: 3*16 (no trailer)
 * Sectors 32 to 39:
 *	240 bytes: 15*16 (no trailer)
 *
 * Unlock is done at the beginning of each sector.
 */
static int mifare_write_sector(void *cookie,
				uint8_t sector_id,	/* sector to write */
				near_recv next_func)
{
	struct mifare_cookie *mf_ck = cookie;
	int blocks_count;

	DBG("");

	/* Prepare call values */

	/* According to tag size, compute the correct block offset */
	if (sector_id < T4K_BOUNDARY)
		mf_ck->rws_block_start = sector_id * STD_BLK_SECT_TRAILER;
	else
		mf_ck->rws_block_start = T4K_BLK_OFF +
			(sector_id - T4K_BOUNDARY) * EXT_BLK_SECT_TRAILER;

	/* Find blocks_per_sect, according to position, no trailer */
	if (sector_id < T4K_BOUNDARY)
		blocks_count = STD_BLK_PER_SECT;
	else
		blocks_count = EXT_BLK_PER_SECT;

	mf_ck->rws_block_end = mf_ck->rws_block_start + blocks_count;
	mf_ck->rws_completed = 0;
	mf_ck->rws_next_fct = next_func;

	/* Being on the first block of the sector, unlock it */
	return mifare_unlock_sector(mf_ck->rws_block_start,
					mifare_write_sector_unlocked, mf_ck);
}

static int mifare_write_NFC_loop(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err = 0;

	if (length < 0 || resp[0] != 0) {
		err = -EIO;
		goto out_err;
	}

	/* Something more to write? */;
	if (mf_ck->ndef->offset < mf_ck->ndef->length) {
		err = mifare_write_sector(data,		/* cookie */
				GPOINTER_TO_INT(mf_ck->g_sect_list->data),
				mifare_write_NFC_loop);	/* next function */

		mf_ck->g_sect_list = g_slist_remove(mf_ck->g_sect_list,
						mf_ck->g_sect_list->data);

		if (err < 0)
			goto out_err;

	} else {
		/* Correct length of an NDEF message */
		err = mifare_unlock_sector(NFC_1ST_BLOCK,
					mifare_correct_length, mf_ck);

		if (err < 0)
			goto out_err;
	}

	return err;
out_err:
	return mifare_release(err, mf_ck);
}

static int mifare_write_NFC(void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;

	DBG("");

	mf_ck->rws_completed = 0;	/* written blocks */

	/* First write here: */
	err = mifare_write_sector(data,		/* cookie */
		GPOINTER_TO_INT(mf_ck->g_sect_list->data), /* sector id */
		mifare_write_NFC_loop);		/* next function */

	mf_ck->g_sect_list = g_slist_remove(mf_ck->g_sect_list,
						mf_ck->g_sect_list->data);

	if (err < 0)
		return mifare_release(err, mf_ck);

	return err;
}

static int mifare_check_rights_loop(uint8_t *resp, int length, void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;
	int sector_id;

	if (mf_ck->acc_sect->next) {

		mf_ck->acc_sect = mf_ck->acc_sect->next;
		sector_id = GPOINTER_TO_INT(mf_ck->acc_sect->data);

		if (sector_id < T4K_BOUNDARY)
			mf_ck->rws_block_start = sector_id * 4
							+ STD_BLK_PER_SECT;
		else
			mf_ck->rws_block_start = T4K_BLK_OFF + EXT_BLK_PER_SECT
				+ (sector_id - T4K_BOUNDARY) * 16;

		err = mifare_unlock_sector(mf_ck->rws_block_start,
				mifare_check_rights, mf_ck);
	} else {
		/* Full access granted, start writing */
		err = mifare_write_NFC(data);
	}

	if (err < 0)
		return mifare_release(err, mf_ck);

	return err;
}


/*
 * If one of NFC sectors isn't writable,
 * tag size for writing is smaller than actual memory size,
 * so calculate it and check if it is enough for ndef message.
 */
static int writing_not_permitted(void *data)
{
	struct mifare_cookie *mf_ck = data;
	unsigned int new_tag_size = 0;
	int sector_id;
	int i;

	sector_id = GPOINTER_TO_INT(mf_ck->acc_sect->data);
	DBG("Writing sector %i not permitted", sector_id);

	/* Read only sector found, calculate new tag size */
	if (sector_id <= MAD_V1_AIDS_LEN) {
		for (i = GPOINTER_TO_INT(mf_ck->g_sect_list->data);
				i < sector_id; i++)
			new_tag_size += SECTOR_SIZE;
	} else {
		/* Start from first NFC sector */
		for (i = GPOINTER_TO_INT(mf_ck->g_sect_list->data);
				i <= MAD_V1_AIDS_LEN; i++)
			new_tag_size += SECTOR_SIZE;

		/*
		 * If any of previous sector was NFC, skip MAD2
		 * If not, leave "i" as it was
		 */
		if (i < MAD2_SECTOR)
			i = MAD2_SECTOR + 1;

		for (; i < sector_id; i++) {
			if (i < T4K_BOUNDARY)
				new_tag_size += SECTOR_SIZE;
			else
				new_tag_size += BIG_SECTOR_SIZE;
		}
	}

	DBG("TAG writable sectors' size: [%d].", new_tag_size);

	/* Check if there's enough space on tag */
	if (new_tag_size < mf_ck->ndef->length) {
		near_error("Not enough space on tag");

		if (mf_ck->cb)
			mf_ck->cb(mf_ck->adapter_idx,
					mf_ck->target_idx, -ENOSPC);

		mifare_release(0, data);
		return -ENOSPC;
	}

	/* Enough space on tag, continue writing */
	mifare_write_NFC(data);

	return 0;
}

static int mifare_check_rights_NFC(void *data)
{
	struct mifare_cookie *mf_ck = data;
	int err;

	DBG("");

	/*
	 * As authorisation with key B is not supported,
	 * in case writing with key A is not permitted, tag is read-only
	 */
	mf_ck->acc_bits_mask = DATA_access_mask;
	mf_ck->acc_rights = WRITE_with_key_A;

	mf_ck->acc_sect = mf_ck->g_sect_list;
	mf_ck->rws_block_start = NFC_1ST_BLOCK + STD_BLK_PER_SECT;
	mf_ck->rws_next_fct = mifare_check_rights_loop;

	mf_ck->acc_denied_fct = writing_not_permitted;
	err = mifare_unlock_sector(mf_ck->rws_block_start,
			mifare_check_rights, mf_ck);

	if (err < 0)
		return mifare_release(err, mf_ck);

	return err;
}

int mifare_write(uint32_t adapter_idx, uint32_t target_idx,
			struct near_ndef_message *ndef,
			near_tag_io_cb cb, enum near_tag_sub_type tgt_subtype)
{
	struct mifare_cookie *cookie;
	struct near_tag *tag;
	size_t tag_size;
	int err;

	DBG("");

	/* Check supported and tested Mifare type */
	switch (tgt_subtype) {
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_1K:
	case NEAR_TAG_NFC_T2_MIFARE_CLASSIC_4K:
		break;
	default:
		near_error("Mifare tag type %d not supported.", tgt_subtype);
		return -1;
	}

	/* Check if there's enough space on tag */
	tag = near_tag_get_tag(adapter_idx, target_idx);
	near_tag_get_data(tag, &tag_size);

	if (tag_size < ndef->length) {
		near_error("Not enough space on tag");
		return -ENOSPC;
	}

	/* Alloc global cookie */
	cookie = g_try_malloc0(sizeof(struct mifare_cookie));
	if (!cookie)
		return -ENOMEM;

	/* Get the nfcid1 */
	cookie->nfcid1 = near_tag_get_nfcid(adapter_idx, target_idx,
			&cookie->nfcid1_len);
	cookie->adapter_idx = adapter_idx;
	cookie->target_idx = target_idx;
	cookie->cb = cb;

	cookie->ndef = ndef;
	/* Save ndef length */
	cookie->ndef_length = cookie->ndef->data[1];
	cookie->ndef->data[1] = 0;

	/*
	 * Check if all sectors are writable
	 * if not, message may be too long to be written
	 */
	cookie->acc_check_function = mifare_check_rights_NFC;

	/*
	 * Mifare Classic Tag needs to be unlocked before writing
	 * This will check if public keys are allowed (NDEF could be "readable")
	 */
	err = mifare_unlock_sector(MAD1_1ST_BLOCK,	/* related block */
					mifare_read_MAD1,	/* callback */
					cookie);	/* target data */

	if (err < 0)
		return mifare_release(err, cookie);

	return 0;
}

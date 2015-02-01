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

#ifndef __NEAR_TAG_H
#define __NEAR_TAG_H

#include <stdint.h>
#include <stdbool.h>

#include <glib.h>

#define NFC_HEADER_SIZE 1

#define NFC_MAX_NFCID1_LEN 10
#define NFC_MAX_ISO15693_DSFID_LEN 1
#define NFC_MAX_ISO15693_UID_LEN 8

enum near_tag_sub_type {
	NEAR_TAG_NFC_T2_MIFARE_ULTRALIGHT = 0,	// SAK 0x00
	NEAR_TAG_NFC_T2_MIFARE_CLASSIC_1K,	// SAK:0x08
	NEAR_TAG_NFC_T2_MIFARE_MINI,		// SAK 0x09
	NEAR_TAG_NFC_T2_MIFARE_CLASSIC_4K,	// SAK:0x18
	NEAR_TAG_NFC_T2_MIFARE_DESFIRE,		// SAK:0x20
	NEAR_TAG_NFC_T2_JCOP30,			// SAK:0x28
	NEAR_TAG_NFC_T2_MIFARE_4K_EMUL,		// SAK:0x38
	NEAR_TAG_NFC_T2_MIFARE_1K_INFINEON,	// SAK:0x88
	NEAR_TAG_NFC_T2_MPCOS,			// SAK:0x98
	NEAR_TAG_NFC_SUBTYPE_UNKNOWN = 0xFF
};

enum near_tag_memory_layout {
	NEAR_TAG_MEMORY_STATIC = 0,
	NEAR_TAG_MEMORY_DYNAMIC,
	NEAR_TAG_MEMORY_OTHER,
	NEAR_TAG_MEMORY_UNKNOWN = 0xFF
};

typedef void (*near_tag_io_cb) (uint32_t adapter_idx, uint32_t target_idx,
								int status);

struct near_ndef_message;

#define NEAR_TAG_PRIORITY_LOW      -100
#define NEAR_TAG_PRIORITY_DEFAULT     0
#define NEAR_TAG_PRIORITY_HIGH      100

struct near_tag_driver {
	uint16_t type;
	int priority;

	int (*read)(uint32_t adapter_idx, uint32_t target_idx,
						near_tag_io_cb cb);
	int (*write)(uint32_t adapter_idx, uint32_t target_idx,
					struct near_ndef_message *ndef,
					near_tag_io_cb cb);
	int (*check_presence)(uint32_t adapter_idx, uint32_t target_idx,
						near_tag_io_cb cb);
	int (*format)(uint32_t adapter_idx, uint32_t target_idx,
					near_tag_io_cb cb);
};

struct near_tag;

struct near_tag *near_tag_get_tag(uint32_t adapter_idx, uint32_t target_idx);
int	near_tag_activate_target(uint32_t adapter_idx, uint32_t target_idx,
					uint32_t protocol);
void near_tag_set_ro(struct near_tag *tag, bool readonly);
void near_tag_set_blank(struct near_tag *tag, bool blank);
bool near_tag_get_blank(struct near_tag *tag);
int near_tag_add_data(uint32_t adapter_idx, uint32_t target_idx,
			uint8_t *data, size_t data_length);
int near_tag_add_records(struct near_tag *tag, GList *records,
				near_tag_io_cb cb, int status);
enum near_tag_sub_type near_tag_get_subtype(uint32_t adapter_idx,
					uint32_t target_idx);
uint8_t *near_tag_get_nfcid(uint32_t adapter_idx, uint32_t target_idx,
					uint8_t *nfcid_len);
int near_tag_set_nfcid(uint32_t adapter_idx, uint32_t target_idx,
					uint8_t *nfcid, size_t nfcid_len);
uint8_t *near_tag_get_iso15693_dsfid(uint32_t adapter_idx, uint32_t target_idx);
uint8_t *near_tag_get_iso15693_uid(uint32_t adapter_idx, uint32_t target_idx);
uint8_t *near_tag_get_data(struct near_tag *tag, size_t *data_length);
size_t near_tag_get_data_length(struct near_tag *tag);
uint32_t near_tag_get_adapter_idx(struct near_tag *tag);
uint32_t near_tag_get_target_idx(struct near_tag *tag);
int near_tag_driver_register(struct near_tag_driver *driver);
void near_tag_driver_unregister(struct near_tag_driver *driver);
void near_tag_set_memory_layout(struct near_tag *tag,
					enum near_tag_memory_layout);
enum near_tag_memory_layout near_tag_get_memory_layout(struct near_tag *tag);
void near_tag_set_max_ndef_size(struct near_tag *tag, uint16_t size);
uint16_t near_tag_get_max_ndef_size(struct near_tag *tag);
void near_tag_set_c_apdu_max_size(struct near_tag *tag, uint16_t size);
uint16_t near_tag_get_c_apdu_max_size(struct near_tag *tag);
void near_tag_set_r_apdu_max_size(struct near_tag *tag, uint16_t size);
uint16_t near_tag_get_r_apdu_max_size(struct near_tag *tag);
void near_tag_set_file_id(struct near_tag *tag, uint16_t file_id);
uint16_t near_tag_get_file_id(struct near_tag *tag);
void near_tag_set_idm(struct near_tag *tag, uint8_t *idm, uint8_t len);
uint8_t *near_tag_get_idm(struct near_tag *tag, uint8_t *len);
void near_tag_set_attr_block(struct near_tag *tag, uint8_t *attr, uint8_t len);
uint8_t *near_tag_get_attr_block(struct near_tag *tag, uint8_t *len);
void near_tag_set_ic_type(struct near_tag *tag, uint8_t ic_type);
uint8_t near_tag_get_ic_type(struct near_tag *tag);
uint8_t near_tag_get_blk_size(struct near_tag *tag);
void near_tag_set_blk_size(struct near_tag *tag, uint8_t blk_size);
uint8_t near_tag_get_num_blks(struct near_tag *tag);
void near_tag_set_num_blks(struct near_tag *tag, uint8_t num_blks);

#endif

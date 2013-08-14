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

#ifndef __NEAR_NDEF_H
#define __NEAR_NDEF_H

#include <stdbool.h>

#include <near/tag.h>

struct near_ndef_record;
struct carrier_data;

struct near_ndef_message {
	size_t length;
	size_t offset;
	uint8_t *data;
};

int near_ndef_count_records(uint8_t *ndef_in, size_t ndef_in_length,
						uint8_t record_type);

int near_ndef_record_length(uint8_t *ndef_in, size_t ndef_in_length);

GList *near_ndef_parse_msg(uint8_t *ndef_data, size_t ndef_length,
					struct near_ndef_message **reply);

void near_ndef_records_free(GList *records);

struct near_ndef_message *near_ndef_prepare_text_record(char *encoding,
					char *language_code, char *text);

struct near_ndef_message *near_ndef_prepare_uri_record(uint8_t identifier,
					 uint32_t field_length, uint8_t *field);

struct near_ndef_message *near_ndef_prepare_handover_record(char* type_name,
					struct near_ndef_record *record,
					uint8_t carriers,
					struct carrier_data *remote);

struct near_ndef_message *
near_ndef_prepare_smartposter_record(uint8_t uri_identifier,
					uint32_t uri_field_length,
					uint8_t *uri_field);

bool near_ndef_record_cmp_id(struct near_ndef_record *rec1,
						struct near_ndef_record *rec2);
bool near_ndef_record_cmp_mime(struct near_ndef_record *rec1,
						struct near_ndef_record *rec2);


size_t near_ndef_data_length(struct near_ndef_record *data);
uint8_t *near_ndef_data_ptr(struct near_ndef_record *data);

struct near_ndef_message *near_ndef_prepare_wsc_record(char *ssid,
							char *passphrase);

#endif

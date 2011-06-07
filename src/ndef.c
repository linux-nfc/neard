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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <glib.h>

#include <gdbus.h>

#include "near.h"

#define RECORD_TNF_EMPTY     0x00
#define RECORD_TNF_WELLKNOWN 0x01
#define RECORD_TNF_MIME      0x02
#define RECORD_TNF_URI       0x03
#define RECORD_TNF_EXTERNAL  0x04
#define RECORD_TNF_UNKNOWN   0x05
#define RECORD_TNF_UNCHANGED 0x06

#define RECORD_MB(record)  (((record)[0] & 0x80) >> 7)
#define RECORD_ME(record)  (((record)[0] & 0x40) >> 6)
#define RECORD_CF(record)  (((record)[0] & 0x20) >> 5)
#define RECORD_SR(record)  (((record)[0] & 0x10) >> 4)
#define RECORD_IL(record)  (((record)[0] & 0x8)  >> 3)
#define RECORD_TNF(record) ((record)[0] & 0x7)

void __near_ndef_destroy(struct near_ndef *ndef)
{
	
}

static gboolean record_sp(uint8_t tnf, uint8_t *type, size_t type_length)
{
	DBG("tnf 0x%x type length %zu", tnf, type_length);

	if (tnf == RECORD_TNF_WELLKNOWN
			&& type_length == 2
	    		&& strncmp((char *)type, "Sp", 2) == 0)
		return TRUE;

	return FALSE;

}

static uint8_t record_type_offset(uint8_t *record, size_t *type_length)
{
	uint8_t sr, tnf, il;
	uint32_t offset = 0;

	sr = RECORD_SR(record);
	il = RECORD_IL(record);
	tnf = RECORD_TNF(record);
	*type_length = record[1];

	/* Record header */
	offset += 1;

	/* Type length */
	offset += 1;

	if (sr == 1)
		offset += 1;
	else
		offset += 4;
	
	if (il == 1)
		offset += 1;

	return offset;
}

static uint8_t record_payload_offset(uint8_t *record, size_t *payload_length)
{
	uint8_t sr, tnf, il, type_length, id_length;
	uint32_t offset = 0;

	sr = RECORD_SR(record);
	il = RECORD_IL(record);
	tnf = RECORD_TNF(record);
	type_length = record[1];

	/* Record header */
	offset += 1;

	/* Type length */
	offset += 1;

	if (sr == 1) {
		*payload_length = record[offset];
		/* Payload length is 1 byte */
		offset += 1;
	} else {
		*payload_length = *((uint32_t *)(record + offset));
		/* Payload length is 4 bytes */
		offset += 4;
	}
	
	if (il == 1) {
		id_length = record[offset];
		offset += id_length;
	} else {
		id_length = 0;
	}	

	/* Type value */
	offset += type_length;

	if (tnf == 0) {
		offset -= type_length;
		offset -= id_length;
	}

	DBG("type length %d payload length %zu id length %d offset %d", type_length, *payload_length, id_length, offset);

	return offset;
}

struct near_ndef *__near_ndef_create(uint8_t *ndef_data, size_t ndef_length)
{
	struct near_ndef *ndef;
	struct near_ndef_record *record;
	uint8_t *raw_record, payload_offset, type_offset;

	ndef = g_try_malloc0(sizeof(struct near_ndef));
	if (ndef == NULL)
		return NULL;

	ndef->n_records = 0;
	raw_record = ndef_data;

	while (1) {
		uint8_t mb, me, sr, tnf, il;
		size_t i, type_length;
	
		mb = RECORD_MB(raw_record);
		me = RECORD_ME(raw_record);
		sr = RECORD_SR(raw_record);
		il = RECORD_IL(raw_record);
		tnf = RECORD_TNF(raw_record);
		DBG("Record MB 0x%x ME 0x%x SR 0x%x IL 0x%x TNF 0x%x", mb, me, sr, il, tnf);

		if (ndef->n_records == 0 && mb != 1)
			return NULL;

		type_offset = record_type_offset(raw_record, &type_length);

		ndef->smart_poster = record_sp(tnf, raw_record + type_offset, type_length);
		if (ndef->smart_poster == TRUE) {
			size_t payload_length;

			DBG("Smart Poster");

			payload_offset = record_payload_offset(raw_record, &payload_length);

			raw_record += payload_offset;

			continue;
		}

		record = g_try_malloc0(sizeof(struct near_ndef_record));
		if (record == NULL) {
			__near_ndef_destroy(ndef);
			return NULL;
		}

		record->tnf = tnf;

		payload_offset = record_payload_offset(raw_record, &record->payload_length);
		record->payload = raw_record + payload_offset;

		type_offset = record_type_offset(raw_record, &record->type_length);
		record->type = raw_record + type_offset;

		for (i = 0; i < record->payload_length; i++)
			DBG("Payload[%d] %c 0x%x", i, record->payload[i], record->payload[i]);

		ndef->n_records += 1;
		ndef->records = g_list_append(ndef->records, record);

		if (me == 1)
			break;

		raw_record = record->payload + record->payload_length;
	}

	return ndef;
}

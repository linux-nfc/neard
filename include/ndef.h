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

struct near_ndef_record {
	uint8_t tnf;
	uint8_t type_length;
	uint8_t payload[];
};

struct near_ndef {
	uint32_t n_records;
	struct near_ndef_record *records;
};

uint8_t near_ndef_record_tnf(struct near_ndef_record *ndef);

uint8_t *near_ndef_record_type(struct near_ndef_record *ndef,
					uint8_t *type_length);
uint8_t *near_ndef_record_id(struct near_ndef *ndef,
					uint8_t *id_length);
uint8_t *near_ndef_record_payload(struct near_ndef *ndef,
					uint8_t *payload_length);

#endif

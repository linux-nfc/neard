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

#ifndef __NEAR_TLV_H
#define __NEAR_TLV_H

#define TLV_NULL 0x00
#define TLV_LOCK 0x01
#define TLV_MEM  0x02
#define TLV_NDEF 0x03
#define TLV_PROP 0xfd
#define TLV_END  0xfe

#define TLV_SIZE 2

uint16_t near_tlv_length(uint8_t *tlv);
uint8_t *near_tlv_next(uint8_t *tlv);
uint8_t *near_tlv_data(uint8_t *tlv);
GList *near_tlv_parse(uint8_t *tlv, size_t tlv_length);

#endif

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

#include "near.h"

#define TLV_NULL 0x00
#define TLV_LOCK 0x01
#define TLV_MEM  0x02
#define TLV_NDEF 0x03
#define TLV_PROP 0xfd
#define TLV_END  0xfe

uint16_t near_tlv_length(uint8_t *tlv)
{
	uint16_t length;

	if (tlv[0] == TLV_NULL || tlv[0] == TLV_END)
		length = 0;
	else if (tlv[1] == 0xff)
		length = *(uint16_t *)(tlv + 2);
	else
		length = tlv[1];

	return length;
}

uint8_t *near_tlv_next(uint8_t *tlv)
{
	uint16_t length;
	uint8_t l_length;

	length = near_tlv_length(tlv);
	if (length > 0xfe)
		l_length = 3;
	else if (length == 0)
		l_length = 0;
	else
		l_length = 1;

	/* T (1 byte) + L (1 or 3 bytes) + V */
	return tlv + 1 + l_length + length;
}

uint8_t *near_tlv_data(uint8_t *tlv)
{
	uint16_t length;
	uint8_t l_length;

	length = near_tlv_length(tlv);
	if (length > 0xfe)
		l_length = 3;
	else if (length == 0)
		l_length = 0;
	else
		l_length = 1;

	/* T (1 byte) + L (1 or 3 bytes) */
	return tlv + 1 + l_length;
}

/*
 *
 *  seeld - Secure Element Manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "seel.h"

struct iso7816_apdu {
	uint8_t class;
	uint8_t instruction;
	uint8_t param1;
	uint8_t param2;
	uint8_t body[];
} __attribute__((packed));

struct iso7816_apdu_resp {
	uint8_t sw1;
	uint8_t sw2;
} __attribute__((packed));

struct seel_apdu {
	struct iso7816_apdu *apdu;
	size_t length;
} __attribute__((packed));

#define MAX_AID_LENGTH 16
#define MIN_AID_LENGTH 5

#define CLA_CHANNEL_STANDARD 0x0
#define CLA_CHANNEL_EXTENDED 0x1
#define CLA_PROPRIETARY_CMD  0x80
#define CLA_PPS_CMD          0xF0

#define INS_MANAGE_CHANNEL 0x70
#define INS_SELECT_FILE    0xA4
#define INS_GET_GP_DATA    0xCA

#define P1_SELECT_FILE_DF_NAME 0x4

#define APDU_RESP_TRAILER_LENGTH 0x2 /* SW1, SW2 */

#define CLA_CHANNEL_MASK 0xFF

static struct seel_apdu *alloc_apdu(uint8_t class, uint8_t channel,
				uint8_t instruction,
				uint8_t param1, uint8_t param2,
				uint8_t data_length, uint8_t *data,
				int resp_length)
{
	struct seel_apdu *apdu;
	struct iso7816_apdu *iso_apdu;
	size_t iso_apdu_length;
	uint32_t body_ptr;

	if (channel > 3)
		return NULL;

	apdu = g_try_malloc(sizeof(struct seel_apdu));
	if (apdu == NULL)
		return apdu;

	iso_apdu_length = sizeof(struct iso7816_apdu);
	if (data_length > 0)
		iso_apdu_length += 1 + data_length;

	if (resp_length >= 0)
		iso_apdu_length += 1;

	apdu->apdu = g_try_malloc(iso_apdu_length);
	if (apdu->apdu == NULL) {
		g_free(apdu);
		return NULL;
	}

	iso_apdu = apdu->apdu;
	iso_apdu->class = class | channel;
	iso_apdu->instruction = instruction;
	iso_apdu->param1 = param1;
	iso_apdu->param2 = param2;

	body_ptr = 0;
	if (data_length > 0) {
		iso_apdu->body[0] = data_length;
		memcpy(&iso_apdu->body[1], data, data_length);
		body_ptr += data_length + 1;
	}

	if (resp_length >= 0)
		iso_apdu->body[body_ptr] = resp_length;

	apdu->length = iso_apdu_length;

	return apdu;
}

struct seel_apdu *__seel_apdu_build(uint8_t *apdu, size_t length, uint8_t channel)
{
	struct seel_apdu *_apdu;
	struct iso7816_apdu *iso_apdu;

	_apdu = g_try_malloc(sizeof(struct seel_apdu));
	if (!_apdu)
		return NULL;

	_apdu->apdu = g_try_malloc(length);
	if (_apdu->apdu == NULL) {
		g_free(_apdu);
		return NULL;
	}

	if (channel > 3) {
		DBG("Invalid channel number %d", channel);
		channel = 0;
	}

	iso_apdu = (struct iso7816_apdu *) apdu;
	/* We add the channel iff CLA is not PPS */
	if ((iso_apdu->class & CLA_PPS_CMD) != CLA_PPS_CMD)
		iso_apdu->class |= channel;

	_apdu->length = length;
	memcpy(_apdu->apdu, apdu, length);

	return _apdu;
}

void __seel_apdu_dump(uint8_t *apdu, size_t length)
{
	size_t i;
	char *str;

	str = g_try_malloc0((3 * length) + 1);
	if (str == NULL)
		return;

	for (i = 0; i < length; i++)
		sprintf(str + (3 * i), "%02X ", apdu[i]);
	str[3 * length] = 0;

	DBG("[%zd] %s", length, str);

	g_free(str);
}

void __seel_apdu_free(struct seel_apdu *apdu)
{
	g_free(apdu->apdu);
	g_free(apdu);
}

size_t __seel_apdu_length(struct seel_apdu *apdu)
{
	return apdu->length;
}

uint8_t *__seel_apdu_data(struct seel_apdu *apdu)
{
	return (uint8_t *) apdu->apdu;
}

struct seel_apdu *__seel_apdu_open_logical_channel(void)
{
	return alloc_apdu(CLA_CHANNEL_STANDARD, 0, INS_MANAGE_CHANNEL, 0, 0,
								0, NULL, 1);
}

struct seel_apdu *__seel_apdu_close_logical_channel(uint8_t channel)
{
	DBG("%d", channel);

	return alloc_apdu(CLA_CHANNEL_STANDARD, 0, INS_MANAGE_CHANNEL, 0x80,
							channel, 0, NULL, -1);
}

struct seel_apdu *__seel_apdu_select_aid(uint8_t channel,
						uint8_t *aid, size_t aid_length)
{
	DBG("%zd", aid_length);

	if (aid_length < MIN_AID_LENGTH ||
			aid_length > MAX_AID_LENGTH)
		return NULL;

	return alloc_apdu(CLA_CHANNEL_STANDARD, channel, INS_SELECT_FILE,
					P1_SELECT_FILE_DF_NAME, 0,
					aid_length, aid, -1);
}

struct seel_apdu *__seel_apdu_get_all_gp_data(void)
{
	DBG("");

	return alloc_apdu(CLA_PROPRIETARY_CMD, 0, INS_GET_GP_DATA,
						0xFF, 0x40, 0, NULL, 0);
}

struct seel_apdu *__seel_apdu_get_next_gp_data(size_t length)
{
	DBG("");

	return alloc_apdu(CLA_PROPRIETARY_CMD, 0, INS_GET_GP_DATA,
						0xFF, 0x60, 0, NULL, length);
}

struct seel_apdu *__seel_apdu_get_refresh_gp_data(void)
{
	DBG("");

	return alloc_apdu(CLA_PROPRIETARY_CMD, 0, INS_GET_GP_DATA,
						0xDF, 0x20, 0, NULL, 0xB);
}

static int apdu_trailer_status(struct iso7816_apdu_resp *trailer)
{
	DBG("SW1 0x%x SW2 0x%x", trailer->sw1, trailer->sw2);

	/*
	 * SIMAlliance_OpenMobileAPI3_0_release1_FINAL.pdf
	 *
	 * The API shall handle received status word as follows:
	 * If the status word indicates that the SE was able to open
	 * a channel (e.g status word '90 00' or status words
	 * referencing a warning in ISO-7816-4: '62 XX' or '63 XX')
	 * the API shall keep the channel opened and the next
	 * getSelectResponse() shall return the received status word.
	 */
	switch (trailer->sw1) {
	case 0x90:
		if (trailer->sw2 == 0)
			return 0;
	case 0x63:
	case 0x62:
		return 0;
	default:
		return -EIO;
	}
}

int __seel_apdu_resp_status(uint8_t *apdu, size_t apdu_length)
{
	struct iso7816_apdu_resp *resp;

	if (apdu_length < APDU_RESP_TRAILER_LENGTH)
		return -EINVAL;

	__seel_apdu_dump(apdu, apdu_length);

	resp = (struct iso7816_apdu_resp *)(apdu + apdu_length - APDU_RESP_TRAILER_LENGTH);

	return apdu_trailer_status(resp);
}

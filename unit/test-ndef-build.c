/*
 *  neard - Near Field Communication manager
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "src/near.h"
#include "include/ndef.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

/* 'hello' - UTF-8 - en-US Text NDEF */
static uint8_t text[] = {0xd1, 0x1, 0xb, 0x54, 0x5,  0x65, 0x6e, 0x2d,
			 0x55, 0x53, 0x68, 0x65, 0x6c, 0x6c, 0x6f};

/* SSID - 'TestSSID', Passphrase - 'Testpass'  WSC MIME NDEF */
static uint8_t wsc[] = {0xD2, 0x17, 0x1E, 0x61, 0x70, 0x70, 0x6C, 0x69,
			0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x76,
			0x6E, 0x64, 0x2E, 0x77, 0x66, 0x61, 0x2E, 0x77,
			0x73, 0x63, 0x10, 0x45, 0x00, 0x08, 0x54, 0x65,
			0x73, 0x74, 0x53, 0x53, 0x49, 0x44, 0x10, 0x03,
			0x00, 0x02, 0x00, 0x22, 0x10, 0x27, 0x00, 0x08,
			0x54, 0x65, 0x73, 0x74, 0x70, 0x61, 0x73, 0x73};

/* SSID - 'TestSSID'  WSC MIME NDEF */
static uint8_t wsc_wo[] = {0xD2, 0x17, 0x12, 0x61, 0x70, 0x70, 0x6C, 0x69,
			0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x76,
			0x6E, 0x64, 0x2E, 0x77, 0x66, 0x61, 0x2E, 0x77,
			0x73, 0x63, 0x10, 0x45, 0x00, 0x08, 0x54, 0x65,
			0x73, 0x74, 0x53, 0x53, 0x49, 0x44, 0x10, 0x03,
			0x00, 0x02, 0x00, 0x01};

static void test_ndef_text_build(void)
{
	struct near_ndef_message *ndef;

	ndef = near_ndef_prepare_text_record("UTF-8", "en-US", "hello");

	g_assert(ndef);
	g_assert(ndef->length == ARRAY_SIZE(text));
	g_assert(!memcmp(ndef->data, text, ARRAY_SIZE(text)));
}

static void test_ndef_wsc_with_passphrase_build(void)
{
	struct near_ndef_message *ndef;

	ndef = near_ndef_prepare_wsc_record("TestSSID", "Testpass");

	g_assert(ndef);
	g_assert(ndef->length == ARRAY_SIZE(wsc));
	g_assert(!memcmp(ndef->data, wsc, ARRAY_SIZE(wsc)));
}

static void test_ndef_wsc_with_out_passphrase_build(void)
{
	struct near_ndef_message *ndef;

	ndef = near_ndef_prepare_wsc_record("TestSSID", NULL);

	g_assert(ndef);
	g_assert(ndef->length == ARRAY_SIZE(wsc_wo));
	g_assert(!memcmp(ndef->data, wsc_wo, ARRAY_SIZE(wsc_wo)));
}

static void test_ndef_wsc_with_out_ssid_build(void)
{
	struct near_ndef_message *ndef;

	ndef = near_ndef_prepare_wsc_record(NULL, NULL);

	g_assert(!ndef);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/testNDEF-build/Test Text NDEF", test_ndef_text_build);
	g_test_add_func("/testNDEF-build/Test WSC with SSID and Passphrase NDEF"
				, test_ndef_wsc_with_passphrase_build);
	g_test_add_func("/testNDEF-build/Test WSC with only SSID NDEF",
				test_ndef_wsc_with_out_passphrase_build);
	g_test_add_func("/testNDEF-build/Test WSC with out SSID NDEF",
				test_ndef_wsc_with_out_ssid_build);

	return g_test_run();
}

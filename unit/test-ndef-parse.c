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

#include <near/ndef.h>
#include <src/near.h>
#include <src/ndef-private.h>

/* http://www.intel.com URI NDEF */
static uint8_t test_uri[] = {0xd1, 0x1, 0xa, 0x55, 0x1, 0x69, 0x6e, 0x74,
			0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d};

/* 'hello żółw' - UTF-8 - en-US Text NDEF */
static uint8_t text_utf8[] = {0xd1, 0x1, 0x13, 0x54, 0x5, 0x65, 0x6e, 0x2d,
			0x55, 0x53, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0xc5,
			0xbc, 0xc3, 0xb3, 0xc5, 0x82, 0x77};

/* 'hello żółw' - UTF-16 - en-US Text NDEF UTF-16 malformed*/
static uint8_t text_utf16_invalid[] = {0xd1, 0x1, 0x19, 0x54, 0x85,
			/* en-US */
			0x65, 0x6e, 0x2d, 0x55, 0x53,
			/* hello żółw */
			0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00,
			/* Missing last byte */
			0x20, 0x00, 0x7c, 0x01, 0xf3, 0x00, 0x42, 0x01, 0x77};

/* Smart poster with a http://intel.com URI record */
static uint8_t single_sp[] = {0xd1, 0x2, 0xe, 0x53, 0x70, 0xd1, 0x1, 0xa,
			      0x55, 0x3, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x2e,
			      0x63, 0x6f, 0x6d};

/* Smart poster with a http://intel.com URI record and a 'Intel' title */
static uint8_t title_sp[] = {0xd1, 0x2, 0x1a, 0x53, 0x70, 0x91, 0x1, 0xa,
			     0x55, 0x3, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x2e,
			     0x63, 0x6f, 0x6d, 0x51, 0x1, 0x8, 0x54, 0x2,
			     0x65, 0x6e, 0x49, 0x6e, 0x74, 0x65, 0x6c};

/* AAR record with a "com.example.aar" package name */
static uint8_t aar[] = {0xd4, 0xf, 0xf, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69,
			0x64, 0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x70, 0x6b, 0x67,
			0x63, 0x6f, 0x6d, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
			0x6c, 0x65, 0x2e, 0x61, 0x61, 0x72};

/* Sample Bluetooth Handover Select Message on an NFC Forum Tag */
static uint8_t ho_hs_bt[] = {0x91, 0x02, 0x0A, 0x48, 0x73, 0x12, 0xD1, 0x02,
			      0x04, 0x61, 0x63, 0x03, 0x01, 0x30, 0x00, 0x5A,
			      0x20, 0x1F, 0x01, 0x61, 0x70, 0x70, 0x6C, 0x69,
			      0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x76,
			      0x6E, 0x64, 0x2E, 0x62, 0x6C, 0x75, 0x65, 0x74,
			      0x6F, 0x6F, 0x74, 0x68, 0x2E, 0x65, 0x70, 0x2E,
			      0x6F, 0x6F, 0x62, 0x30, 0x1F, 0x00, 0x03, 0x07,
			      0x80, 0x88, 0xbf, 0x01, 0x04, 0x0D, 0x80, 0x06,
			      0x04, 0x05, 0x03, 0x18, 0x11, 0x23, 0x11, 0x0B,
			      0x09, 0x44, 0x65, 0x79, 0x69, 0x63, 0x65, 0x4e,
			      0x61, 0x6d, 0x65};

static void test_ndef_uri(void)
{
	GList *records;
	struct near_ndef_record *record;

	records = near_ndef_parse_msg(test_uri, sizeof(test_uri), NULL);

	g_assert(records);
	g_assert_cmpuint(g_list_length(records), ==, 1);

	record = (struct near_ndef_record *)(records->data);

	g_assert_cmpuint(record->header->rec_type, ==, RECORD_TYPE_WKT_URI);
	g_assert_cmpuint(record->header->mb, ==, 1);
	g_assert_cmpuint(record->header->me, ==, 1);

	g_assert(record->uri);
	g_assert_cmpuint(record->uri->field_length, ==, strlen("intel.com"));
	g_assert(strncmp((char *) record->uri->field, "intel.com",
					record->uri->field_length) == 0);

	if (g_test_verbose())
		g_print("NDEF URI field: %s\n", record->uri->field);

	near_ndef_records_free(records);
}

static void test_ndef_text(void)
{
	GList *records;
	struct near_ndef_record *record;

	records = near_ndef_parse_msg(text_utf8, sizeof(text_utf8), NULL);

	g_assert(records);
	g_assert_cmpuint(g_list_length(records), ==, 1);

	record = (struct near_ndef_record *)(records->data);

	g_assert_cmpuint(record->header->rec_type, ==, RECORD_TYPE_WKT_TEXT);
	g_assert_cmpuint(record->header->mb, ==, 1);
	g_assert_cmpuint(record->header->me, ==, 1);

	g_assert(record->text);
	g_assert_cmpstr(record->text->data, ==, "hello żółw");
	g_assert_cmpstr(record->text->encoding,==,  "UTF-8");
	g_assert_cmpstr(record->text->language_code, ==, "en-US");

	if (g_test_verbose()) {
		g_print("NDEF Text data: %s\n", record->text->data);
		g_print("NDEF Text Encoding: %s\n", record->text->encoding);
		g_print("NDEF Text Language: %s\n",
						record->text->language_code);
	}

	near_ndef_records_free(records);
}

static void test_ndef_text_invalid_utf16(void)
{
	GList *records;

	records = near_ndef_parse_msg(text_utf16_invalid, sizeof(text_utf16_invalid), NULL);

	g_assert_null(records);
}

static void test_ndef_single_sp(void)
{
	GList *records;
	struct near_ndef_record *record;
	struct near_ndef_uri_payload *uri;

	records = near_ndef_parse_msg(single_sp, sizeof(single_sp), NULL);

	g_assert(records);
	g_assert_cmpuint(g_list_length(records), ==, 1);

	record = (struct near_ndef_record *) records->data;

	g_assert_cmpuint(record->header->rec_type, ==, RECORD_TYPE_WKT_SMART_POSTER);
	g_assert_cmpuint(record->header->mb, ==, 1);
	g_assert_cmpuint(record->header->me, ==, 1);

	g_assert(record->sp);
	g_assert_cmpuint(record->sp->number_of_title_records, ==, 0);
	g_assert_null(record->sp->type);
	g_assert_null(record->sp->action);
	g_assert_cmpuint(record->sp->size, ==, 0);
	g_assert(record->sp->uri);

	uri = (struct near_ndef_uri_payload *) record->sp->uri;

	g_assert_cmpuint(uri->field_length, ==, strlen("intel.com"));
	g_assert(strncmp((char *) uri->field, "intel.com",
					uri->field_length) == 0);

	if (g_test_verbose())
		g_print("NDEF SP URI field: %.*s\n", (int)uri->field_length,
			(char *) uri->field);

	near_ndef_records_free(records);
}

static void test_ndef_title_sp(void)
{
	GList *records;
	struct near_ndef_record *record;
	struct near_ndef_uri_payload *uri;
	struct near_ndef_text_payload *text;


	records = near_ndef_parse_msg(title_sp, sizeof(title_sp), NULL);

	g_assert(records);
	g_assert_cmpuint(g_list_length(records), ==, 1);

	record = (struct near_ndef_record *) records->data;

	g_assert_cmpuint(record->header->rec_type, ==, RECORD_TYPE_WKT_SMART_POSTER);
	g_assert_cmpuint(record->header->mb, ==, 1);
	g_assert_cmpuint(record->header->me, ==, 1);

	g_assert(record->sp);
	g_assert_cmpuint(record->sp->number_of_title_records, ==, 1);
	g_assert_null(record->sp->type);
	g_assert_null(record->sp->action);
	g_assert_cmpuint(record->sp->size, ==, 0);
	g_assert(record->sp->uri);
	g_assert(record->sp->title_records[0]);

	uri = (struct near_ndef_uri_payload *) record->sp->uri;
	text = (struct near_ndef_text_payload *) record->sp->title_records[0];

	g_assert_cmpuint(uri->field_length, ==, strlen("intel.com"));
	g_assert(strncmp((char *) uri->field, "intel.com",
					uri->field_length) == 0);

	if (g_test_verbose())
		g_print("NDEF SP URI field: %.*s\n", (int)uri->field_length,
			(char *) uri->field);

	g_assert_cmpstr(text->data, ==, "Intel");
	g_assert_cmpstr(text->encoding, ==, "UTF-8");
	g_assert_cmpstr(text->language_code, ==, "en");

	if (g_test_verbose()) {
		g_print("NDEF SP Title data: %s\n", text->data);
		g_print("NDEF SP Title Encoding: %s\n", text->encoding);
		g_print("NDEF SP Title Language: %s\n", text->language_code);
	}

	near_ndef_records_free(records);
}

static void test_ndef_aar(void)
{
	GList *records;
	struct near_ndef_record *record;

	records = near_ndef_parse_msg(aar, sizeof(aar), NULL);

	g_assert(records);
	g_assert_cmpuint(g_list_length(records), ==, 1);

	record = (struct near_ndef_record *)(records->data);

	g_assert_cmpuint(record->header->rec_type, ==, RECORD_TYPE_EXT_AAR);
	g_assert_cmpuint(record->header->mb, ==, 1);
	g_assert_cmpuint(record->header->me, ==, 1);

	g_assert(record->aar);
	g_assert(record->aar->package);
	g_assert_cmpstr((char *) record->aar->package, ==, "com.example.aar");


	if (g_test_verbose())
		g_print("NDEF AAR package: %s\n", record->aar->package);

	near_ndef_records_free(records);
}

static void test_ndef_ho_hs_bt(void)
{
	GList *records;
	struct near_ndef_record *record;
	struct near_ndef_ho_payload *ho;
	struct near_ndef_ac_payload *ac;

	/* TODO
	 * It is not possible to run HO code as unit test now as this code does
	 * both parsing and acting (eg. trying to access HO agent) in same run.
	 * Don't enable this test until it is fixed.
	 */
	return;

	records = near_ndef_parse_msg(ho_hs_bt, sizeof(ho_hs_bt), NULL);

	g_assert(records);
	g_assert_cmpuint(g_list_length(records), ==, 2);

	record = records->data;
	ho = record->ho;

	g_assert_cmpuint(ho->number_of_ac_payloads, ==, 1);

	ac = ho->ac_payloads[0];

	g_assert_cmpuint(ac->cdr_len, ==, 1);
	g_assert_cmpmem(ac->cdr, ac->cdr_len, "0", sizeof("0"));

	records = g_list_next(records);
	record = records->data;
	g_assert_cmpstr(record->type, ==, BT_MIME_STRING_2_1);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/testNDEF-parse/Test URI NDEF", test_ndef_uri);
	g_test_add_func("/testNDEF-parse/Test Text NDEF", test_ndef_text);
	g_test_add_func("/testNDEF-parse/Test Text NDEF UTF-16 malformed", test_ndef_text_invalid_utf16);
	g_test_add_func("/testNDEF-parse/Test Single record SmartPoster NDEF",
							test_ndef_single_sp);
	g_test_add_func("/testNDEF-parse/Test Title record SmartPoster NDEF",
							test_ndef_title_sp);
	g_test_add_func("/testNDEF-parse/Android Application Record NDEF",
							test_ndef_aar);
	g_test_add_func("/testNDEF-parse/Test Handover Select NDEF",
							test_ndef_ho_hs_bt);

	return g_test_run();
}

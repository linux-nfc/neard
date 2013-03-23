/*
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2013 Intel Corporation. All rights reserved.
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

#include "test-utils.h"

void test_ndef_free_record(struct near_ndef_record *record)
{
	g_free(record->header);
	g_free(record->type);
	g_free(record->data);
	g_free(record);
}

struct near_ndef_message *test_ndef_create_test_record(const char *str)
{
	struct near_ndef_message *ndef;

	ndef = near_ndef_prepare_text_record("UTF-8", "en-US", (char *) str);
	g_assert(ndef);
	g_assert(ndef->data);

	return ndef;
}

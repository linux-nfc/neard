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

static void test_ndef_text_build(void)
{
	struct near_ndef_message *ndef;

	ndef = near_ndef_prepare_text_record("UTF-8", "en-US", "hello");

	g_assert(ndef);
	g_assert(ndef->length == ARRAY_SIZE(text));
	g_assert(!memcmp(ndef->data, text, ARRAY_SIZE(text)));
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/testNDEF-build/Test Text NDEF", test_ndef_text_build);

	return g_test_run();
}

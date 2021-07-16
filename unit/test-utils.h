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

#ifndef UNIT_TEST_UTILS_H
#define UNIT_TEST_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <near/device.h>
#include <near/types.h>
#include <near/ndef.h>
#include <glib.h>
#include <glib/gprintf.h>

/* SNEP specific types */
struct snep_fragment {
	uint32_t len;
	uint8_t *data;
};

struct p2p_snep_put_req_data {
	uint8_t fd;
	uint32_t adapter_idx;
	uint32_t target_idx;
	near_device_io_cb cb;
	guint watch;

	GSList *fragments;
};

struct p2p_snep_req_frame {
	uint8_t version;
	uint8_t request;
	uint32_t length;
	uint8_t ndef[];
} __attribute__((packed));

struct p2p_snep_resp_frame {
	uint8_t version;
	uint8_t response;
	uint32_t length;
	uint8_t info[];
} __attribute__((packed));

struct near_ndef_message *test_ndef_create_test_record(const char *str);

#endif

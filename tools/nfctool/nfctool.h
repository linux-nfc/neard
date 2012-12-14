/*
 *
 *  Near Field Communication nfctool
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#ifndef __NFCTOOL_H
#define __NFCTOOL_H

#ifdef DEBUG
#define DBG(fmt, ...) fprintf(stdout, "%s: " fmt "\n", __func__, ## __VA_ARGS__)
#else
#define DBG(fmt, ...)
#endif

#define print_error(fmt, ...) fprintf(stderr, fmt"\n", ## __VA_ARGS__)

#define INVALID_ADAPTER_IDX 0xFFFFFFFF

#define TARGET_TYPE_TAG		0
#define TARGET_TYPE_DEVICE	1

struct nfc_target {
	guint32 idx;
	guint8 type;
};

struct nfc_adapter {
	guint32 idx;
	guint32 protocols;
	guint8 powered;
	GSList *tags;
	GSList *devices;
};

struct nfctool_options {
	gboolean list;
	gchar *device_name;
	guint32 adapter_idx;
};

extern struct nfctool_options opts;

extern GSList *adapters;

#endif /* __NFCTOOL_H */

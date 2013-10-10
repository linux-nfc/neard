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

#include "display.h"

#ifdef DEBUG
#define DBG(fmt, ...) fprintf(stdout, "%s: " fmt "\n", __func__, ## __VA_ARGS__)
#else
#define DBG(fmt, ...)
#endif

#define LLCP_COLOR COLOR_CYAN
#define LLCP_HEADER_INDENT 0
#define LLCP_MSG_INDENT    4

#define SNEP_COLOR COLOR_YELLOW
#define SNEP_HEADER_INDENT 4
#define SNEP_MSG_INDENT    6

#define NDEF_COLOR COLOR_BLUE
#define NDEF_HEADER_INDENT 6
#define NDEF_MSG_INDENT    8
#define NDEF_HEX_INDENT    9

#define print_error(fmt, ...) fprintf(stderr, fmt"\n", ## __VA_ARGS__)

#define POLLING_MODE_INITIATOR	0x01
#define POLLING_MODE_TARGET	0x02
#define POLLING_MODE_BOTH	0x03

#define INVALID_ADAPTER_IDX 0xFFFFFFFF

#define TARGET_TYPE_TAG		0
#define TARGET_TYPE_DEVICE	1

#define SNIFFER_SHOW_TIMESTAMP_NONE	0
#define SNIFFER_SHOW_TIMESTAMP_DELTA	1
#define SNIFFER_SHOW_TIMESTAMP_ABS	2

struct nfctool_options {
	gboolean show_version;
	gboolean list;
	gboolean poll;
	guint8 poll_mode;
	gchar *device_name;
	guint32 adapter_idx;
	gboolean enable_dev;
	gboolean disable_dev;
	gchar *fw_filename;
	gboolean set_param;
	gint32 lto;
	gint32 rw;
	gint32 miux;
	gboolean need_netlink;
	gboolean snl;
	GSList *snl_list;
	gboolean sniff;
	gsize snap_len;
	gboolean dump_symm;
	guint8 show_timestamp;
	guint8 snep_sap;
	guint8 handover_sap;
	gchar *pcap_filename;
};

struct nfc_snl {
	gchar *uri;
	gsize uri_size;
	guint8 sap;
};

struct nfc_snl *nfctool_snl_alloc(gsize uri_size);

void nfctool_sdres_free(struct nfc_snl *snl);

extern struct nfctool_options opts;


#endif /* __NFCTOOL_H */

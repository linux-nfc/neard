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

#ifndef __SNIFFER_H
#define __SNIFFER_H

#ifndef AF_NFC
#define AF_NFC 39
#endif

struct sniffer_packet {
	guint8 adapter_idx;
	guint8 direction;

	struct {
		guint8 ptype;
		guint8 local_sap;
		guint8 remote_sap;

		guint8 send_seq;
		guint8 recv_seq;

		guint8 *data;
		guint32 data_len;
	} llcp;

	struct {
		guint8 version;

		guint8 rcode;

		guint32 acceptable_len;

		guint8 *data;
		guint32 data_len;
		guint32 real_len;
	} snep;
};

int sniffer_init(void);

void sniffer_cleanup(void);

void sniffer_print_hexdump(FILE *file, guint8 *data, guint32 len,
			   guint8 indent, bool print_len);

#endif /* __SNIFFER_H */

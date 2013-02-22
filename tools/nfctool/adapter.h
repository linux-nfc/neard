/*
 *
 *  Near Field Communication nfctool
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

#ifndef __ADAPTER_H
#define __ADAPTER_H

struct nfc_adapter {
	guint32 idx;
	guint32 protocols;
	guint8 powered;
	guint8 polling;
	guint8 rf_mode;
	GSList *tags;
	GSList *devices;
	gint32 param_lto;
	gint32 param_rw;
	gint32 param_miux;
};

int adapter_init(void);

void adapter_cleanup(void);

struct nfc_adapter *adapter_add(guint32 idx, guint32 protocols,
				guint8 powered, guint8 rf_mode);

void adapter_free(struct nfc_adapter *adapter);

void adapter_add_target(struct nfc_adapter *adapter, guint8 type, guint32 idx);

struct nfc_adapter *adapter_get(guint32 adapter_idx);

int adapter_all_get_devices(void);

void adapter_idx_print_info(guint32 idx);

void adapter_print_info(struct nfc_adapter *adapter);

void adpater_print_targets(struct nfc_adapter *adapter, gchar *prefix);

#endif /* __ADAPTER_H */

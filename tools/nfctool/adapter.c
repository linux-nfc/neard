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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <glib.h>

#include <near/nfc_copy.h>

#include "adapter.h"
#include "nfctool.h"
#include "netlink.h"

static GSList *adapters;

static struct nfc_adapter *selected_adapter;

static void adapter_get_devices(struct nfc_adapter *adapter)
{
	if (adapter->rf_mode == NFC_RF_INITIATOR)
		nl_get_targets(adapter);

	nl_get_params(adapter);
}

int adapter_all_get_devices(void)
{
	int err;

	err = nl_get_devices();
	if (err)
		return err;

	g_slist_foreach(adapters, (GFunc)adapter_get_devices, NULL);

	return 0;
}

static void adapter_print_target(guint32 idx, gchar *type)
{
	printf("%s%d ", type, idx);
}

void adpater_print_targets(struct nfc_adapter *adapter, gchar *prefix)
{
	printf("%sTags: [ ", prefix);

	g_slist_foreach(adapter->tags, (GFunc)adapter_print_target, "tag");

	printf("]\n");

	printf("%sDevices: [ ", prefix);

	g_slist_foreach(adapter->devices,
			(GFunc)adapter_print_target, "device");

	printf("]\n");
}

void adapter_print_info(struct nfc_adapter *adapter)
{
	gchar *rf_mode_str;

	if (!adapter)
		return;

	printf("nfc%d:\n", adapter->idx);

	adpater_print_targets(adapter, "          ");

	printf("          Protocols: [ ");

	if (adapter->protocols & NFC_PROTO_FELICA_MASK)
		printf("Felica ");

	if (adapter->protocols & NFC_PROTO_MIFARE_MASK)
		printf("MIFARE ");

	if (adapter->protocols & NFC_PROTO_JEWEL_MASK)
		printf("Jewel ");

	if ((adapter->protocols & NFC_PROTO_ISO14443_MASK) ||
	    (adapter->protocols & NFC_PROTO_ISO14443_B_MASK))
		printf("ISO-DEP ");

	if (adapter->protocols & NFC_PROTO_NFC_DEP_MASK)
		printf("NFC-DEP ");

	if (adapter->protocols & NFC_PROTO_ISO15693_MASK)
		printf("ISO-15693 ");

	printf("]\n");

	printf("          Powered: %s\n",
		adapter->powered ? "Yes" : "No");

	if (adapter->rf_mode == NFC_RF_INITIATOR)
		rf_mode_str = "Initiator";
	else if (adapter->rf_mode == NFC_RF_TARGET)
		rf_mode_str = "Target";
	else
		rf_mode_str = "None";

	printf("          RF Mode: %s\n", rf_mode_str);

	printf("          lto: %d\n", adapter->param_lto);
	printf("          rw: %d\n", adapter->param_rw);
	printf("          miux: %d\n", adapter->param_miux);

	printf("\n");
}

void adapter_idx_print_info(guint32 idx)
{
	if (idx != INVALID_ADAPTER_IDX)
		adapter_print_info(adapter_get(idx));
	else
		g_slist_foreach(adapters, (GFunc)adapter_print_info, NULL);
}

static gint adapter_compare_idx(struct nfc_adapter *adapter, guint32 idx)
{
	return (gint)adapter->idx - (gint)idx;
}

struct nfc_adapter *adapter_get(guint32 idx)
{
	GSList *elem;

	if (idx == opts.adapter_idx)
		return selected_adapter;

	elem = g_slist_find_custom(adapters, GINT_TO_POINTER(idx),
				   (GCompareFunc)adapter_compare_idx);

	if (elem)
		return elem->data;

	return NULL;
}

void adapter_add_target(struct nfc_adapter *adapter, guint8 type, guint32 idx)
{
	DBG("adapter_idx: %d, target_type: %d, target_idx: %d",
	    adapter->idx, type, idx);

	if (type == TARGET_TYPE_TAG)
		adapter->tags = g_slist_append(adapter->tags,
					       GINT_TO_POINTER(idx));
	else
		adapter->devices = g_slist_append(adapter->devices,
						  GINT_TO_POINTER(idx));
}

void adapter_free(struct nfc_adapter *adapter)
{
	g_slist_free(adapter->tags);
	g_slist_free(adapter->devices);

	g_free(adapter);
}

struct nfc_adapter *adapter_add(guint32 idx, guint32 protocols,
				guint8 powered, guint8 rf_mode)
{
	struct nfc_adapter *adapter;

	adapter = g_malloc0(sizeof(struct nfc_adapter));

	adapter->idx = idx;
	adapter->protocols = protocols;
	adapter->powered = powered;
	adapter->rf_mode = rf_mode;

	if (rf_mode == NFC_RF_TARGET)
		adapter_add_target(adapter, TARGET_TYPE_DEVICE, 0);

	adapters = g_slist_append(adapters, adapter);

	if (idx == opts.adapter_idx)
		selected_adapter = adapter;

	return adapter;
}

void adapter_cleanup(void)
{
	g_slist_free_full(adapters, (GDestroyNotify)adapter_free);
}

int adapter_init(void)
{
	adapters = NULL;
	selected_adapter = NULL;

	return 0;
}

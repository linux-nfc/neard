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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/nfc.h>
#include <glib.h>

#include "nfctool.h"
#include "netlink.h"

GSList *adapters = NULL;

static void nfctool_print_target(guint32 idx, gchar *type)
{
	printf("%s%d ", type, idx);
}

static void nfctool_print_targets(struct nfc_adapter *adapter, gchar *prefix)
{
	printf("%sTags: [ ", prefix);

	g_slist_foreach(adapter->tags, (GFunc)nfctool_print_target, "tag");

	printf("]\n");

	printf("%sDevices: [ ", prefix);

	g_slist_foreach(adapter->devices,
			(GFunc)nfctool_print_target, "device");

	printf("]\n");
}

static void nfctool_print_adapter_info(struct nfc_adapter *adapter)
{
	printf("nfc%d:\n", adapter->idx);

	nfctool_print_targets(adapter, "          ");

	printf("          Protocols: [ ");

	if (adapter->protocols & NFC_PROTO_FELICA_MASK)
		printf("Felica ");

	if (adapter->protocols & NFC_PROTO_MIFARE_MASK)
		printf("MIFARE ");

	if (adapter->protocols & NFC_PROTO_JEWEL_MASK)
		printf("Jewel ");

	if (adapter->protocols & NFC_PROTO_ISO14443_MASK)
		printf("ISO-DEP ");

	if (adapter->protocols & NFC_PROTO_NFC_DEP_MASK)
		printf("NFC-DEP ");

	printf("]\n");

	printf("          Powered: %s\n",
		adapter->powered ? "Yes" : "No");

	printf("\n");
}

static void nfctool_list_adapter(struct nfc_adapter *adapter, guint32 idx)
{
	if (idx == INVALID_ADAPTER_IDX || idx == adapter->idx)
		nfctool_print_adapter_info(adapter);
}

static void nfctool_list_adapters(void)
{
	g_slist_foreach(adapters, (GFunc)nfctool_list_adapter,
					GINT_TO_POINTER(opts.adapter_idx));
}

static void nfctool_adapter_free(struct nfc_adapter *adapter)
{
	g_slist_free(adapter->tags);
	g_slist_free(adapter->devices);

	g_free(adapter);
}

static void nfctool_get_device(struct nfc_adapter *adapter)
{
	nl_get_targets(adapter);
}

static int nfctool_get_devices(void)
{
	int err;

	err = nl_get_devices();
	if (err)
		return err;

	g_slist_foreach(adapters, (GFunc)nfctool_get_device, NULL);

	return 0;
}

struct nfctool_options opts = {
	.list = FALSE,
	.device_name = NULL,
	.adapter_idx = INVALID_ADAPTER_IDX,
};

static GOptionEntry option_entries[] = {
	{ "list", 'l', 0, G_OPTION_ARG_NONE, &opts.list,
	  "list attached NFC devices", NULL },
	{ "device", 'd', 0, G_OPTION_ARG_STRING, &opts.device_name,
	  "specify a nfc device", "nfcX" },
	{ NULL }
};

static int nfctool_options_parse(int argc, char **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	gchar *start, *end;
	int err = -EINVAL;

	context = g_option_context_new("- A small NFC tool box");

	g_option_context_add_main_entries(context, option_entries, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		print_error("%s: %s", argv[0], error->message);

		g_error_free(error);

		goto exit;
	}

	if (opts.device_name != NULL) {
		if (strncmp("nfc", opts.device_name, 3) != 0) {
			print_error("Invalid device name: %s",
							opts.device_name);

			goto exit;
		}

		start = opts.device_name + 3;

		opts.adapter_idx = strtol(start, &end, 10);
		if (start == end) {
			print_error("Invalid NFC adapter %s", opts.device_name);

			goto exit;
		}
	}

	if (!opts.list) {
		printf("%s", g_option_context_get_help(context, TRUE, NULL));

		goto exit;
	}

	err = 0;

exit:
	g_option_context_free(context);

	return err;
}

static void nfctool_options_cleanup(void)
{
	if (opts.device_name != NULL)
		g_free(opts.device_name);
}

int main(int argc, char **argv)
{
	int err;

	err = nfctool_options_parse(argc, argv);
	if (err)
		goto exit_err;

	err = nl_init();
	if (err)
		goto exit_err;

	err = nfctool_get_devices();
	if (err)
		goto exit_err;

	if (opts.list)
		nfctool_list_adapters();

	err = 0;

exit_err:
	g_slist_free_full(adapters, (GDestroyNotify)nfctool_adapter_free);

	nl_cleanup();

	nfctool_options_cleanup();

	return err;
}

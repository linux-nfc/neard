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

static GMainLoop *main_loop = NULL;

static gint nfctool_compare_adapter_idx(struct nfc_adapter *adapter,
								guint32 idx)
{
	if (adapter->idx < idx)
		return -1;

	if (adapter->idx > idx)
		return 1;

	return 0;
}

static struct nfc_adapter *nfctool_find_adapter(guint32 adapter_idx)
{
	GSList *elem;

	elem = g_slist_find_custom(adapters, GINT_TO_POINTER(adapter_idx),
				(GCompareFunc)nfctool_compare_adapter_idx);

	if (elem)
		return elem->data;

	return NULL;
}

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
	gchar *rf_mode_str;

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

	if (adapter->rf_mode == NFC_RF_INITIATOR)
		rf_mode_str = "Initiator";
	else if (adapter->rf_mode == NFC_RF_TARGET)
		rf_mode_str = "Target";
	else
		rf_mode_str = "None";

	printf("          RF Mode: %s\n", rf_mode_str);

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

static gchar *nfctool_poll_mode_str(int mode)
{
	if (mode == POLLING_MODE_TARGET)
		return "target";

	if (mode == POLLING_MODE_BOTH)
		return "both initiator and target";

	return "initiator";
}

static int nfctool_start_poll(void)
{
	int err;

	struct nfc_adapter *adapter;

	adapter = nfctool_find_adapter(opts.adapter_idx);

	if (adapter == NULL) {
		print_error("Invalid adapter index: %d", opts.adapter_idx);

		return -ENODEV;
	}

	err = nl_start_poll(adapter, opts.poll_mode);

	if (err == 0) {
		printf("Start polling on nfc%d as %s\n\n",
			adapter->idx, nfctool_poll_mode_str(opts.poll_mode));
		return 0;
	}

	if (err != -EBUSY)
		return err;

	if (adapter->rf_mode == NFC_RF_NONE)
		printf("nfc%d already in polling mode\n\n", adapter->idx);
	else
		printf("nfc%d already activated\n\n", adapter->idx);

	return err;
}

static void nfctool_get_device(struct nfc_adapter *adapter)
{
	if (adapter->rf_mode == NFC_RF_INITIATOR)
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

static int nfctool_tm_activated(void)
{
	printf("Target mode activated\n");

	g_main_loop_quit(main_loop);

	return 0;
}

static void nfctool_send_dep_link_up(guint32 target_idx, guint32 adapter_idx)
{
	nl_send_dep_link_up(adapter_idx, target_idx);
}

static int nfctool_targets_found(guint32 adapter_idx)
{
	int err;
	struct nfc_adapter *adapter;

	DBG("adapter_idx: %d", adapter_idx);

	if (adapter_idx == INVALID_ADAPTER_IDX)
		return -ENODEV;

	adapter = nfctool_find_adapter(adapter_idx);

	if (adapter == NULL)
		return -ENODEV;

	err = nl_get_targets(adapter);
	if (err) {
		print_error("Error getting targets\n");
		goto exit;
	}

	printf("Targets found for nfc%d\n", adapter_idx);
	nfctool_print_targets(adapter, "  ");

	if (adapter->polling) {
		g_slist_foreach(adapter->devices,
				(GFunc)nfctool_send_dep_link_up,
				GINT_TO_POINTER(adapter_idx));

		adapter->polling = FALSE;
	}

exit:
	g_main_loop_quit(main_loop);

	return err;
}

static int nfc_event_cb(guint8 cmd, guint32 idx)
{
	int err = 0;

	switch (cmd) {
	case NFC_EVENT_TARGETS_FOUND:
		DBG("Targets found");
		err = nfctool_targets_found(idx);
		break;
	case NFC_EVENT_TM_ACTIVATED:
		DBG("Target mode activated");
		err = nfctool_tm_activated();
		break;
	}

	return err;
}

static volatile sig_atomic_t __terminated = 0;

static void sig_term(int sig)
{
	if (__terminated > 0)
		return;

	__terminated = 1;

	DBG("Terminating");

	g_main_loop_quit(main_loop);
}

struct nfctool_options opts = {
	.list = FALSE,
	.poll = FALSE,
	.poll_mode = POLLING_MODE_INITIATOR,
	.device_name = NULL,
	.adapter_idx = INVALID_ADAPTER_IDX,
};

static gboolean opt_parse_poll_arg(const gchar *option_name, const gchar *value,
				   gpointer data, GError **error)
{
	opts.poll = TRUE;

	opts.poll_mode = POLLING_MODE_INITIATOR;

	if (value != NULL) {
		if (*value == 't' || *value == 'T')
			opts.poll_mode = POLLING_MODE_TARGET;
		else if (*value == 'b' || *value == 'B')
			opts.poll_mode = POLLING_MODE_BOTH;
	}

	return TRUE;
}

static GOptionEntry option_entries[] = {
	{ "list", 'l', 0, G_OPTION_ARG_NONE, &opts.list,
	  "list attached NFC devices", NULL },
	{ "device", 'd', 0, G_OPTION_ARG_STRING, &opts.device_name,
	  "specify a nfc device", "nfcX" },
	{ "poll", 'p', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,
	  opt_parse_poll_arg, "start polling as initiator, target, or both; "
	  "default mode is initiator", "[Initiator|Target|Both]" },
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

	if (!opts.poll && !opts.list) {
		printf("%s", g_option_context_get_help(context, TRUE, NULL));

		goto exit;
	}

	if (opts.poll && opts.adapter_idx == INVALID_ADAPTER_IDX) {
		print_error("Please specify a device with -d nfcX option");

		goto exit;
	}

	err = 0;

exit:
	g_option_context_free(context);

	return err;
}

static void nfctool_main_loop_start(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	main_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(main_loop);
}

static void nfctool_options_cleanup(void)
{
	if (opts.device_name != NULL)
		g_free(opts.device_name);
}

static void nfctool_main_loop_clean(void)
{
	if (main_loop != NULL)
		g_main_loop_unref(main_loop);
}

int main(int argc, char **argv)
{
	int err;

	err = nfctool_options_parse(argc, argv);
	if (err)
		goto exit_err;

	err = nl_init(nfc_event_cb);
	if (err)
		goto exit_err;

	err = nfctool_get_devices();
	if (err)
		goto exit_err;

	if (opts.list)
		nfctool_list_adapters();

	if (opts.poll) {
		err = nfctool_start_poll();
		if (err)
			goto exit_err;

		nfctool_main_loop_start();
	}

	err = 0;

exit_err:
	nfctool_main_loop_clean();

	g_slist_free_full(adapters, (GDestroyNotify)nfctool_adapter_free);

	nl_cleanup();

	nfctool_options_cleanup();

	return err;
}

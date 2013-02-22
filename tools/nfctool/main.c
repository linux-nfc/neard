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
#include <glib.h>

#include <near/nfc_copy.h>

#include "nfctool.h"
#include "adapter.h"
#include "netlink.h"
#include "sniffer.h"

#define LLCP_MAX_LTO  0xff
#define LLCP_MAX_RW   0x0f
#define LLCP_MAX_MIUX 0x7ff

static GMainLoop *main_loop = NULL;

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

	adapter = adapter_get(opts.adapter_idx);

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

static int nfctool_set_params(void)
{
	struct nfc_adapter *adapter;
	int err;

	adapter = adapter_get(opts.adapter_idx);
	if (!adapter)
		return -ENODEV;

	err = nl_set_params(adapter, opts.lto, opts.rw, opts.miux);
	if (err) {
		print_error("Error setting one of the parameters.");
		goto exit;
	}

	nl_get_params(adapter);

	adapter_print_info(adapter);

exit:
	return err;
}

static int nfctool_tm_activated(void)
{
	printf("Target mode activated\n");

	if (!opts.sniff)
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

	adapter = adapter_get(adapter_idx);

	if (adapter == NULL)
		return -ENODEV;

	err = nl_get_targets(adapter);
	if (err) {
		print_error("Error getting targets\n");
		goto exit;
	}

	printf("Targets found for nfc%d\n", adapter_idx);
	adpater_print_targets(adapter, "  ");

	if (adapter->polling) {
		g_slist_foreach(adapter->devices,
				(GFunc)nfctool_send_dep_link_up,
				GINT_TO_POINTER(adapter_idx));

		adapter->polling = FALSE;
	}

exit:
	if (!opts.sniff)
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
	.set_param = FALSE,
	.lto = -1,
	.rw = -1,
	.miux = -1,
	.need_netlink = FALSE,
	.sniff = FALSE,
	.snap_len = 0,
	.dump_symm = FALSE,
	.show_timestamp = SNIFFER_SHOW_TIMESTAMP_NONE,
	.pcap_filename = NULL,
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

static gboolean opt_parse_set_param_arg(const gchar *option_name,
					const gchar *value,
					gpointer data, GError **error)
{
	gchar **params = NULL, **keyval = NULL;
	gchar *end;
	gint i, intval;
	gboolean result;

	params = g_strsplit(value, ",", -1);

	i = 0;
	while (params[i] != NULL) {
		keyval = g_strsplit(params[i], "=", 2);

		if (keyval[0] == NULL || keyval[1] == NULL) {
			result = FALSE;
			goto exit;
		}

		intval = strtol(keyval[1], &end, 10);
		if (keyval[1] == end) {
			result = FALSE;
			goto exit;
		}

		if (g_ascii_strcasecmp(keyval[0], "lto") == 0) {
			if (intval < 0 || intval > LLCP_MAX_LTO) {
				print_error("Bad value: max lto value is %d",
								LLCP_MAX_LTO);
				result = FALSE;
				goto exit;
			}

			opts.lto = intval;
		} else if (g_ascii_strcasecmp(keyval[0], "rw") == 0) {
			if (intval < 0 || intval > LLCP_MAX_RW) {
				print_error("Bad value: max rw value is %d",
								LLCP_MAX_RW);
				result = FALSE;
				goto exit;
			}

			opts.rw = intval;
		} else if (g_ascii_strcasecmp(keyval[0], "miux") == 0) {
			if (intval < 0 || intval > LLCP_MAX_MIUX) {
				print_error("Bad value: max miux value is %d",
								LLCP_MAX_MIUX);
				result = FALSE;
				goto exit;
			}

			opts.miux = intval;
		} else {
			result = FALSE;
			goto exit;
		}

		opts.set_param = TRUE;

		g_strfreev(keyval);
		keyval = NULL;

		i++;
	}

	result = TRUE;

exit:
	if (params)
		g_strfreev(params);

	if (keyval)
		g_strfreev(keyval);

	return result;
}

static gboolean opt_parse_show_timestamp_arg(const gchar *option_name,
					     const gchar *value,
					     gpointer data, GError **error)
{
	if (value != NULL && (*value == 'a' || *value == 'A'))
		opts.show_timestamp = SNIFFER_SHOW_TIMESTAMP_ABS;
	else
		opts.show_timestamp = SNIFFER_SHOW_TIMESTAMP_DELTA;

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
	{ "set-param", 's', 0, G_OPTION_ARG_CALLBACK, opt_parse_set_param_arg,
	  "set lto, rw, and/or miux parameters", "lto=150,rw=1,miux=100" },
	{ "sniff", 'n', 0, G_OPTION_ARG_NONE, &opts.sniff,
	  "start LLCP sniffer on the specified device", NULL },
	{ "snapshot-len", 'a', 0, G_OPTION_ARG_INT, &opts.snap_len,
	  "packet snapshot length (in bytes); only relevant with -n", "1024" },
	{ "dump-symm", 'y', 0, G_OPTION_ARG_NONE, &opts.dump_symm,
	  "dump SYMM packets to stdout (flooding); only relevant with -n",
	  NULL },
	{ "show-timestamp", 't', G_OPTION_FLAG_OPTIONAL_ARG,
	  G_OPTION_ARG_CALLBACK, opt_parse_show_timestamp_arg,
	  "show packet timestamp as the delta from first frame (default) "
	  "or absolute value; only relevant with -n", "[delta|abs]" },
	{ "pcap-file", 'f', 0, G_OPTION_ARG_STRING, &opts.pcap_filename,
	  "specify a filename to save traffic in pcap format; "
	  "only relevant with -n", "filename" },
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

	opts.need_netlink = opts.list || opts.poll || opts.set_param;

	if (!opts.need_netlink && !opts.sniff) {
		printf("%s", g_option_context_get_help(context, TRUE, NULL));

		goto exit;
	}

	if ((opts.poll || opts.set_param || opts.sniff) &&
	    opts.adapter_idx == INVALID_ADAPTER_IDX) {
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

	if (opts.pcap_filename != NULL)
		g_free(opts.pcap_filename);
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

	adapter_init();

	if (opts.need_netlink) {
		err = nl_init(nfc_event_cb);
		if (err)
			goto exit_err;

		err = adapter_all_get_devices();
		if (err)
			goto exit_err;

		if (opts.list && !opts.set_param)
			adapter_idx_print_info(opts.adapter_idx);

		if (opts.set_param) {
			err = nfctool_set_params();
			if (err)
				goto exit_err;
		}

		if (opts.poll) {
			err = nfctool_start_poll();

			if (err == -EBUSY && opts.sniff)
				err = 0;

			if (err)
				goto exit_err;
		}
	}

	if (opts.sniff) {
		err = sniffer_init();
		if (err)
			goto exit_err;
	}

	if (opts.poll || opts.sniff)
		nfctool_main_loop_start();

	err = 0;

exit_err:
	nfctool_main_loop_clean();

	adapter_cleanup();

	nl_cleanup();

	sniffer_cleanup();

	nfctool_options_cleanup();

	return err;
}

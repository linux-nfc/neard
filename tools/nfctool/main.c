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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <glib.h>

#include <netlink/genl/genl.h>

#include <near/nfc_copy.h>

#include "nfctool.h"
#include "adapter.h"
#include "netlink.h"
#include "sniffer.h"

#define LLCP_MAX_LTO  0xff
#define LLCP_MAX_RW   0x0f
#define LLCP_MAX_MIUX 0x7ff

static GMainLoop *main_loop = NULL;

static int nfctool_poll_cb(guint8 cmd, guint32 idx, gpointer data);
static int nfctool_snl_cb(guint8 cmd, guint32 idx, gpointer data);

static void nfctool_quit(bool force);

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

	if (!adapter) {
		print_error("Invalid adapter index: %d", opts.adapter_idx);

		return -ENODEV;
	}

	nl_add_event_handler(NFC_EVENT_TARGETS_FOUND, nfctool_poll_cb);
	nl_add_event_handler(NFC_EVENT_TM_ACTIVATED, nfctool_poll_cb);

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

	/* Don't fail if there is a pending SNL request */
	if (opts.snl)
		return 0;

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

static int nfctool_snl_send_request(struct nfc_adapter *adapter)
{
	int err;

	nl_add_event_handler(NFC_EVENT_LLC_SDRES, nfctool_snl_cb);

	err = nl_send_sdreq(adapter, opts.snl_list);
	if (err)
		print_error("Can't send SNL request: %s", strerror(-err));

	return err;
}

static int nfctool_set_powered(bool powered)
{
	struct nfc_adapter *adapter;
	int err;

	adapter = adapter_get(opts.adapter_idx);
	if (!adapter)
		return -ENODEV;

	err = nl_set_powered(adapter, powered);

	if (err == 0)
		adapter->powered = powered;

	return err;
}

static int nfctool_fw_download_cb(guint8 cmd, guint32 adapter_idx,
				  gpointer data)
{
	int err;
	gchar *fw_filename;
	struct nlattr **nl_attr = data;

	if (nl_attr[NFC_ATTR_FIRMWARE_DOWNLOAD_STATUS] != NULL)
		err = nla_get_u32(nl_attr[NFC_ATTR_FIRMWARE_DOWNLOAD_STATUS]);
	else
		err = -ENOTSUP;

	if (nl_attr[NFC_ATTR_FIRMWARE_NAME] != NULL)
		fw_filename = nla_get_string(nl_attr[NFC_ATTR_FIRMWARE_NAME]);
	else
		fw_filename = "UNKNOWN";

	printf("Firmware download operation for %s terminated with status %s\n",
	       fw_filename, err ? strerror(-err) : "OK");

	nfctool_quit(false);

	return 0;
}

static int nfctool_fw_download(gchar *fw_filename)
{
	struct nfc_adapter *adapter;
	int err;

	adapter = adapter_get(opts.adapter_idx);
	if (!adapter)
		return -ENODEV;

	nl_add_event_handler(NFC_CMD_FW_DOWNLOAD, nfctool_fw_download_cb);

	err = nl_fw_download(adapter, fw_filename);
	if (err)
		print_error("Firmware download failed: %s", strerror(-err));

	return err;
}

static int nfctool_dep_link_up_cb(guint8 cmd, guint32 idx, gpointer data)
{
	struct nfc_adapter *adapter;

	printf("Link is UP for adapter nfc%d\n\n", idx);

	if (idx != opts.adapter_idx)
		return -ENODEV;

	adapter = adapter_get(idx);
	if (!adapter)
		return -ENODEV;

	nfctool_snl_send_request(adapter);

	return 0;
}

static int nfctool_dep_link_down_cb(guint8 cmd, guint32 idx, gpointer data)
{
	if (idx != opts.adapter_idx)
		return -ENODEV;

	printf("Link is DOWN for adapter nfc%d\n\n", idx);

	opts.snl = false;

	nfctool_quit(false);

	return 0;
}

static int nfctool_snl(void)
{
	struct nfc_adapter *adapter;

	adapter = adapter_get(opts.adapter_idx);
	if (!adapter)
		return -ENODEV;

	if (adapter->polling) {
		/* Delay netlink message until the link is established */
		nl_add_event_handler(NFC_CMD_DEP_LINK_UP,
						nfctool_dep_link_up_cb);

		nl_add_event_handler(NFC_CMD_DEP_LINK_DOWN,
						nfctool_dep_link_down_cb);

		return 0;
	}

	if (adapter->rf_mode == NFC_RF_NONE) {
		print_error("Can't send SNL request: No active link");

		opts.snl = false;

		return -ENOLINK;
	}

	return nfctool_snl_send_request(adapter);
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

	if (!adapter)
		return -ENODEV;

	err = nl_get_targets(adapter);
	if (err) {
		print_error("Error getting targets\n");
		goto exit;
	}

	printf("Targets found for nfc%d\n", adapter_idx);
	adpater_print_targets(adapter, "  ");
	printf("\n");

	if (adapter->polling) {
		g_slist_foreach(adapter->devices,
				(GFunc)nfctool_send_dep_link_up,
				GINT_TO_POINTER(adapter_idx));

		adapter->polling = FALSE;
	}

exit:
	return err;
}

static int nfctool_poll_cb(guint8 cmd, guint32 idx, gpointer data)
{
	int err = 0;

	DBG("cmd: %d, idx: %d", cmd, idx);

	switch (cmd) {
	case NFC_EVENT_TARGETS_FOUND:
		err = nfctool_targets_found(idx);
		break;
	case NFC_EVENT_TM_ACTIVATED:
		printf("Target mode activated\n");
		break;
	}

	nfctool_quit(false);

	return err;
}

static void nfctool_print_and_remove_snl(struct nfc_snl *sdres,
					 guint32 adapter_idx)
{
	GSList *elem;

	printf(" uri: %s - sap: %d\n", sdres->uri, sdres->sap);

	if (adapter_idx == opts.adapter_idx) {
		elem = g_slist_find_custom(opts.snl_list, sdres->uri,
					   (GCompareFunc)g_strcmp0);

		if (elem) {
			g_free(elem->data);
			opts.snl_list = g_slist_delete_link(opts.snl_list,
							    elem);
		}
	}
}

static int nfctool_snl_cb(guint8 cmd, guint32 idx, gpointer data)
{
	GSList *sdres_list = (GSList *)data;

	printf("nfc%d: Service Name lookup:\n", idx);

	g_slist_foreach(sdres_list, (GFunc)nfctool_print_and_remove_snl,
			GINT_TO_POINTER(idx));

	printf("\n");

	if (!opts.snl_list) {
		opts.snl = false;
		nfctool_quit(false);
	}

	return 0;
}

struct nfc_snl *nfctool_snl_alloc(gsize uri_size)
{
	struct nfc_snl *snl;

	snl = g_malloc(sizeof(struct nfc_snl));

	snl->uri = g_malloc0(uri_size);
	snl->uri_size = uri_size;
	snl->sap = 0;

	return snl;
}

void nfctool_sdres_free(struct nfc_snl *snl)
{
	if (snl->uri_size)
		g_free(snl->uri);

	g_free(snl);
}

static volatile sig_atomic_t __terminated = 0;

static void sig_term(int sig)
{
	if (__terminated > 0)
		return;

	__terminated = 1;

	DBG("Terminating");

	nfctool_quit(true);
}

struct nfctool_options opts = {
	.show_version = FALSE,
	.list = FALSE,
	.poll = FALSE,
	.poll_mode = POLLING_MODE_INITIATOR,
	.device_name = NULL,
	.adapter_idx = INVALID_ADAPTER_IDX,
	.enable_dev = FALSE,
	.disable_dev = FALSE,
	.set_param = FALSE,
	.lto = -1,
	.rw = -1,
	.miux = -1,
	.need_netlink = FALSE,
	.snl = FALSE,
	.snl_list = NULL,
	.sniff = FALSE,
	.snap_len = 0,
	.dump_symm = FALSE,
	.show_timestamp = SNIFFER_SHOW_TIMESTAMP_NONE,
	.snep_sap = 0x04,
	.pcap_filename = NULL,
};

static bool opt_parse_poll_arg(const gchar *option_name, const gchar *value,
				   gpointer data, GError **error)
{
	opts.poll = true;

	opts.poll_mode = POLLING_MODE_INITIATOR;

	if (value) {
		if (*value == 't' || *value == 'T')
			opts.poll_mode = POLLING_MODE_TARGET;
		else if (*value == 'b' || *value == 'B')
			opts.poll_mode = POLLING_MODE_BOTH;
	}

	return true;
}

static bool opt_parse_set_param_arg(const gchar *option_name,
					const gchar *value,
					gpointer data, GError **error)
{
	gchar **params = NULL, **keyval = NULL;
	gchar *end;
	gint i, intval;
	bool result;

	params = g_strsplit(value, ",", -1);

	i = 0;
	while (params[i]) {
		keyval = g_strsplit(params[i], "=", 2);

		if (!keyval[0] || !keyval[1]) {
			result = false;
			goto exit;
		}

		intval = strtol(keyval[1], &end, 10);
		if (keyval[1] == end) {
			result = false;
			goto exit;
		}

		if (g_ascii_strcasecmp(keyval[0], "lto") == 0) {
			if (intval < 0 || intval > LLCP_MAX_LTO) {
				print_error("Bad value: max lto value is %d",
								LLCP_MAX_LTO);
				result = false;
				goto exit;
			}

			opts.lto = intval;
		} else if (g_ascii_strcasecmp(keyval[0], "rw") == 0) {
			if (intval < 0 || intval > LLCP_MAX_RW) {
				print_error("Bad value: max rw value is %d",
								LLCP_MAX_RW);
				result = false;
				goto exit;
			}

			opts.rw = intval;
		} else if (g_ascii_strcasecmp(keyval[0], "miux") == 0) {
			if (intval < 0 || intval > LLCP_MAX_MIUX) {
				print_error("Bad value: max miux value is %d",
								LLCP_MAX_MIUX);
				result = false;
				goto exit;
			}

			opts.miux = intval;
		} else {
			result = false;
			goto exit;
		}

		opts.set_param = true;

		g_strfreev(keyval);
		keyval = NULL;

		i++;
	}

	result = true;

exit:
	if (params)
		g_strfreev(params);

	if (keyval)
		g_strfreev(keyval);

	return result;
}

static bool opt_parse_show_timestamp_arg(const gchar *option_name,
					     const gchar *value,
					     gpointer data, GError **error)
{
	if (value && (*value == 'a' || *value == 'A'))
		opts.show_timestamp = SNIFFER_SHOW_TIMESTAMP_ABS;
	else
		opts.show_timestamp = SNIFFER_SHOW_TIMESTAMP_DELTA;

	return true;
}

static bool opt_parse_snl_arg(const gchar *option_name, const gchar *value,
				  gpointer data, GError **error)
{
	gchar *uri;

	opts.snl = true;

	uri = g_strdup(value);

	opts.snl_list = g_slist_prepend(opts.snl_list, uri);

	return true;
}

static GOptionEntry option_entries[] = {
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &opts.show_version,
	  "show version information and exit" },
	{ "list", 'l', 0, G_OPTION_ARG_NONE, &opts.list,
	  "list attached NFC devices", NULL },
	{ "device", 'd', 0, G_OPTION_ARG_STRING, &opts.device_name,
	  "specify a nfc device", "nfcX" },
	{ "poll", 'p', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,
	  opt_parse_poll_arg, "start polling as initiator, target, or both; "
	  "default mode is initiator", "[Initiator|Target|Both]" },
	{ "enable", '1', 0, G_OPTION_ARG_NONE, &opts.enable_dev,
	  "enable device", NULL },
	{ "disable", '0', 0, G_OPTION_ARG_NONE, &opts.disable_dev,
	  "disable device", NULL },
	{ "fw-download", 'w', 0, G_OPTION_ARG_STRING, &opts.fw_filename,
	  "Put the device in firmware download mode", "fw_filename" },
	{ "set-param", 's', 0, G_OPTION_ARG_CALLBACK, opt_parse_set_param_arg,
	  "set lto, rw, and/or miux parameters", "lto=150,rw=1,miux=100" },
	{ "snl", 'k', 0, G_OPTION_ARG_CALLBACK, &opt_parse_snl_arg,
	  "Send a Service Name Lookup request", "urn:nfc:sn:snep"},
	{ "sniff", 'n', 0, G_OPTION_ARG_NONE, &opts.sniff,
	  "start LLCP sniffer on the specified device", NULL },
	{ "snapshot-len", 'a', 0, G_OPTION_ARG_INT, &opts.snap_len,
	  "packet snapshot length (in bytes); only relevant with -n", "1024" },
	{ "dump-symm", 'y', 0, G_OPTION_ARG_NONE, &opts.dump_symm,
	  "dump SYMM packets to stdout (flooding); only relevant with -n",
	  NULL },
	{ "snep-sap", 'e', 0, G_OPTION_ARG_INT, &opts.snep_sap,
	  "Specify the sap number to be used for snep decoding; "
	  "only relevant with -n", "0x04" },
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

	if (opts.show_version) {
		printf("%s\n", VERSION);
		goto done;
	}

	if (opts.device_name) {
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

	if (opts.enable_dev || opts.disable_dev)
		opts.list = true;

	if (opts.poll)
		opts.enable_dev = true;

	opts.need_netlink = opts.list || opts.poll || opts.set_param ||
			    opts.snl || opts.fw_filename;

	if (!opts.need_netlink && !opts.sniff) {
		printf("%s", g_option_context_get_help(context, TRUE, NULL));

		goto exit;
	}

	if ((opts.poll || opts.set_param || opts.sniff || opts.snl ||
	    opts.enable_dev || opts.disable_dev || opts.fw_filename) &&
	    opts.adapter_idx == INVALID_ADAPTER_IDX) {
		print_error("Please specify a device with -d nfcX option");

		goto exit;
	}

done:
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
	if (opts.device_name)
		g_free(opts.device_name);

	if (opts.pcap_filename)
		g_free(opts.pcap_filename);

	if (opts.fw_filename != NULL)
		g_free(opts.fw_filename);

	g_slist_free_full(opts.snl_list, g_free);
}

static void nfctool_main_loop_clean(void)
{
	if (main_loop)
		g_main_loop_unref(main_loop);
}

static void nfctool_quit(bool force)
{
	if (force || (!opts.sniff && !opts.snl))
		g_main_loop_quit(main_loop);
}

int main(int argc, char **argv)
{
	int err;

	err = nfctool_options_parse(argc, argv);
	if (err)
		goto exit_err;

	if (opts.show_version)
		goto done;

	adapter_init();

	if (opts.need_netlink) {
		err = nl_init();
		if (err)
			goto exit_err;

		err = adapter_all_get_devices();
		if (err)
			goto exit_err;
	}

	if (opts.fw_filename) {
		err = nfctool_fw_download(opts.fw_filename);
		if (err)
			goto exit_err;

		goto start_loop;
	}

	if (opts.sniff) {
		err = sniffer_init();
		if (err)
			goto exit_err;
	}

	if (opts.enable_dev || opts.disable_dev) {
		err = nfctool_set_powered(opts.enable_dev);

		if (err && err != -EALREADY)
			goto exit_err;

		err = 0;
	}

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

	if (opts.snl)
		nfctool_snl();

start_loop:
	if (opts.poll || opts.sniff || opts.snl || opts.fw_filename)
		nfctool_main_loop_start();

done:
	err = 0;

exit_err:
	nfctool_main_loop_clean();

	adapter_cleanup();

	nl_cleanup();

	sniffer_cleanup();

	nfctool_options_cleanup();

	if (err)
		print_error("%s", strerror(-err));

	return err;
}

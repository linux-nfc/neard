/*
 *
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
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
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>

#include <gdbus.h>

#include "near.h"

static struct {
	bool constant_poll;
	bool default_powered;
	bool reset_on_error;
} near_settings  = {
	.constant_poll = FALSE,
	.default_powered = FALSE,
	.reset_on_error = TRUE,
};

static GKeyFile *load_config(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		if (err->code != G_FILE_ERROR_NOENT) {
			near_error("Parsing %s failed: %s", file,
								err->message);
		}

		g_error_free(err);
		g_key_file_free(keyfile);
		return NULL;
	}

	return keyfile;
}

static void parse_config(GKeyFile *config)
{
	GError *error = NULL;
	bool boolean;

	if (!config)
		return;

	DBG("parsing main.conf");

	boolean = g_key_file_get_boolean(config, "General",
						"ConstantPoll", &error);
	if (!error)
		near_settings.constant_poll = boolean;

	boolean = g_key_file_get_boolean(config, "General",
						"DefaultPowered", &error);
	if (!error)
		near_settings.default_powered = boolean;

	boolean = g_key_file_get_boolean(config, "General",
						"ResetOnError", &error);
	if (!error)
		near_settings.reset_on_error = boolean;

	g_clear_error(&error);
}

static GMainLoop *main_loop = NULL;

static volatile sig_atomic_t __terminated = 0;

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		if (__terminated == 0) {
			near_info("Terminating");
			g_main_loop_quit(main_loop);
		}

		__terminated = 1;
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static void disconnect_callback(DBusConnection *conn, void *user_data)
{
	near_error("D-Bus disconnect");

	g_main_loop_quit(main_loop);
}

static gchar *option_debug = NULL;
static gchar *option_plugin = NULL;
static gchar *option_noplugin = NULL;
static gboolean option_detach = TRUE;
static gboolean option_version = FALSE;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return true;
}

static GOptionEntry options[] = {
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't fork daemon to background" },
	{ "plugin", 'p', 0, G_OPTION_ARG_STRING, &option_plugin,
				"Specify plugins to load", "NAME,..." },
	{ "noplugin", 'P', 0, G_OPTION_ARG_STRING, &option_noplugin,
				"Specify plugins not to load", "NAME,..." },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ NULL },
};

bool near_setting_get_bool(const char *key)
{
	if (g_str_equal(key, "ConstantPoll"))
		return near_settings.constant_poll;

	if (g_str_equal(key, "DefaultPowered"))
		return near_settings.default_powered;

	if (g_str_equal(key, "ResetOnError"))
		return near_settings.reset_on_error;

	return false;
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	DBusConnection *conn;
	DBusError err;
	GKeyFile *config;
	guint signal;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version) {
		printf("%s\n", VERSION);
		exit(0);
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	signal = setup_signalfd();

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NFC_SERVICE, &err);
	if (!conn) {
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with system bus\n");
		exit(1);
	}

	g_dbus_set_disconnect_function(conn, disconnect_callback, NULL, NULL);

	__near_log_init(option_debug, option_detach);
	__near_dbus_init(conn);

	config = load_config(CONFIGDIR "/main.conf");

	parse_config(config);

	if (__near_netlink_init() < 0) {
		near_error("*** NETLINK INITIALIZATION FAILED ***");
		exit(1);
	}

	__near_agent_init();
	__near_tag_init();
	__near_device_init();
	__near_adapter_init();
	__near_ndef_init();
	__near_snep_core_init();
	__near_manager_init(conn);
	__near_bluetooth_init();

	__near_plugin_init(option_plugin, option_noplugin);

	if (option_detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	g_main_loop_run(main_loop);

	g_source_remove(signal);

	__near_plugin_cleanup();

	__near_bluetooth_cleanup();
	__near_manager_cleanup();
	__near_ndef_cleanup();
	__near_snep_core_cleanup();
	__near_adapter_cleanup();
	__near_device_cleanup();
	__near_tag_cleanup();
	__near_agent_cleanup();
	__near_netlink_cleanup();

	__near_dbus_cleanup();
	__near_log_cleanup();

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	if (config)
		g_key_file_free(config);

	return 0;
}

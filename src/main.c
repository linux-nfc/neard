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

#include <gdbus.h>

#include "near.h"

static struct {
	near_bool_t constant_poll;
} near_settings  = {
	.constant_poll = FALSE,
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
	gboolean boolean;

	if (config == NULL)
		return;

	DBG("parsing main.conf");

	boolean = g_key_file_get_boolean(config, "General",
						"ConstantPoll", &error);
	if (error == NULL)
		near_settings.constant_poll = boolean;

	g_clear_error(&error);
}

static GMainLoop *main_loop = NULL;

static volatile sig_atomic_t __terminated = 0;

static void sig_term(int sig)
{
	if (__terminated > 0)
		return;

	__terminated = 1;

	near_info("Terminating");

	g_main_loop_quit(main_loop);
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

static gboolean parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return TRUE;
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

near_bool_t near_setting_get_bool(const char *key)
{
	if (g_str_equal(key, "ConstantPoll") == TRUE)
		return near_settings.constant_poll;

	return FALSE;
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	DBusConnection *conn;
	DBusError err;
	GKeyFile *config;
	struct sigaction sa;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &error) == FALSE) {
		if (error != NULL) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version == TRUE) {
		printf("%s\n", VERSION);
		exit(0);
	}

	if (option_detach == TRUE) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NFC_SERVICE, &err);
	if (conn == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
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

	__near_netlink_init();
	__near_tag_init();
	__near_device_init();
	__near_adapter_init();
	__near_ndef_init();
	__near_manager_init(conn);
	__near_bluetooth_init();

	__near_plugin_init(option_plugin, option_noplugin);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	__near_plugin_cleanup();

	__near_bluetooth_cleanup();
	__near_manager_cleanup();
	__near_ndef_cleanup();
	__near_adapter_cleanup();
	__near_device_cleanup();
	__near_tag_cleanup();
	__near_netlink_cleanup();

	__near_dbus_cleanup();
	__near_log_cleanup();

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	if (config)
		g_key_file_free(config);

	return 0;
}

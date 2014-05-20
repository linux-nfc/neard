/*
 *
 *  seeld - Secure Element Manager
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#include <gdbus.h>
#include <string.h>

#include <glib.h>

#include "package-manager.h"
#include "pkgmgr-info.h"
#include "aul.h"

#include <near/log.h>
#include <near/plugin.h>
#include <near/driver.h>
#include <near/dbus.h>

#define TELEPHONY_SERVICE		"org.tizen.telephony"
#define TELEPHONY_DEFAULT_PATH		"/org/tizen/telephony"

#define MANAGER_INTERFACE		TELEPHONY_SERVICE ".Manager"
#define SIM_INTERFACE			TELEPHONY_SERVICE ".Sim"

/* signals */
#define SIM_STATUS			"Status"

/* commands */
#define GET_MODEMS			"GetModems"
#define GET_INIT_STATUS			"GetInitStatus"
#define TRANSFER_APDU			"TransferAPDU"

#define SIM_INIT_COMPLETED		0x03
#define MAX_CERT_TYPE			9

static DBusConnection *connection;

struct tapi_modem {
	char *path;
	bool sim_available;
};
static struct tapi_modem *default_modem;
static GHashTable *modem_hash;
static GHashTable *cert_hash;

static void check_sim_status_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	struct tapi_modem *modem = user_data;
	int status;
	bool changed;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		DBG("%s", error.message);
		dbus_error_free(&error);
		goto done;
	}

	if (!dbus_message_get_args(reply, NULL, DBUS_TYPE_INT32, &status,
					DBUS_TYPE_BOOLEAN, &changed,
					DBUS_TYPE_INVALID))
		goto done;

	DBG("sim status %d changed %d", status, changed);
	if (status == SIM_INIT_COMPLETED)
		modem->sim_available = true;

	if (default_modem == NULL && modem->sim_available == true)
		default_modem = modem;

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void check_sim_status(gpointer key, gpointer value, gpointer user_data)
{
	DBusMessage *message;
	DBusPendingCall *call;
	struct tapi_modem *modem = value;

	DBG("");

	if (modem == NULL)
		return;

	message = dbus_message_new_method_call(TELEPHONY_SERVICE,
					modem->path, SIM_INTERFACE,
					GET_INIT_STATUS);
	if (message == NULL)
		return;

	if (dbus_connection_send_with_reply(connection, message,
					       &call, -1) == FALSE) {
		DBG("Failed to call GetInitStatus()");
		dbus_message_unref(message);
		return;
	}

	if (call == NULL) {
		DBG("D-Bus connection not available");
		dbus_message_unref(message);
		return;
	}

	dbus_pending_call_set_notify(call, check_sim_status_reply,
					modem, NULL);

	dbus_message_unref(message);
}

static void add_modem(const char *path)
{
	struct tapi_modem *modem;

	DBG("modem_path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem != NULL)
		return;

	modem = g_try_new0(struct tapi_modem, 1);
	if (modem == NULL)
		return;

	modem->path = g_strdup(path);
	modem->sim_available = false;

	g_hash_table_insert(modem_hash, g_strdup(modem->path), modem);
}

static void remove_modem(gpointer user_data)
{
	struct tapi_modem *modem = user_data;

	g_free(modem->path);
	g_free(modem);
}

static void get_modems_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter array, entry;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		DBG("%s", error.message);
		dbus_error_free(&error);
		goto done;
	}

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &entry);
	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *name, *path;

		dbus_message_iter_get_basic(&entry, &name);

		path = g_strdup_printf("%s/%s", TELEPHONY_DEFAULT_PATH, name);
		if (path != NULL) {
			add_modem(path);
			g_free(path);
		}

		dbus_message_iter_next(&entry);
	}

	g_hash_table_foreach(modem_hash, check_sim_status, NULL);

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static int get_modems(void)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("");

	message = dbus_message_new_method_call(TELEPHONY_SERVICE,
					TELEPHONY_DEFAULT_PATH,
					MANAGER_INTERFACE, GET_MODEMS);
	if (message == NULL)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message,
					       &call, -1) == FALSE) {
		DBG("Failed to call GetModems()");
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		DBG("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, get_modems_reply,
					NULL, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static void remove_cert_list(gpointer user_data)
{
	g_free(user_data);
}

static void remove_cert(gpointer user_data)
{
	GSList *cert_list = user_data;

	g_slist_free_full(cert_list, remove_cert_list);
}

static void tapi_connect(DBusConnection *conn, void *user_data)
{
	DBG("");

	modem_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, remove_modem);
	if (modem_hash == NULL)
		return;

	cert_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, remove_cert);
	if (cert_hash == NULL)
		return;

	get_modems();
}

static void tapi_disconnect(DBusConnection *conn, void *user_data)
{
	DBG("connection %p", connection);

	if (modem_hash == NULL)
		return;

	g_hash_table_destroy(modem_hash);
	modem_hash = NULL;

	if (cert_hash == NULL)
		return;

	g_hash_table_destroy(cert_hash);
	cert_hash = NULL;

}

static gboolean sim_changed(DBusConnection *conn, DBusMessage *message,
					void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct tapi_modem *modem;
	int status;

	DBG("modem_path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return TRUE;

	if (!dbus_message_get_args(message, NULL, DBUS_TYPE_INT32, &status,
					DBUS_TYPE_INVALID))
		return TRUE;

	DBG("sim status %d", status);
	if (status == SIM_INIT_COMPLETED)
		modem->sim_available = true;
	else
		modem->sim_available = false;

	if (default_modem == modem && modem->sim_available == false)
		default_modem = NULL;

	if (default_modem == NULL && modem->sim_available == true)
		default_modem = modem;

	return TRUE;
}

struct tapi_transceive_context {
	void *context;
	transceive_cb_t cb;
};

static void tapi_transfer_apdu_reply(DBusPendingCall *call, void *user_data)
{
	struct tapi_transceive_context *ctx = user_data;
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter iter, array, entry;
	uint8_t *apdu = NULL;
	int result = -EIO, apdu_length = 0;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		DBG("%s", error.message);
		dbus_error_free(&error);
		goto done;
	}

	if (dbus_message_iter_init(reply, &iter) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INT32)
		goto done;

	dbus_message_iter_get_basic(&iter, &result);

	dbus_message_iter_next(&iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		goto done;

	dbus_message_iter_recurse(&iter, &array);

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &entry);
	dbus_message_iter_get_fixed_array(&entry, &apdu, &apdu_length);

	if (apdu_length == 0 || apdu == NULL)
		DBG("data is NULL");

	DBG("apdu_length %d", apdu_length);

done:
	ctx->cb(ctx->context, apdu, apdu_length, result);
	g_free(ctx);

	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static int tapi_transceive(uint8_t ctrl_idx, uint32_t se_idx,
			  uint8_t *apdu, size_t apdu_length,
			  transceive_cb_t cb, void *context)
{
	DBusMessage *message;
	DBusMessageIter iter;
	DBusMessageIter value, array;
	DBusPendingCall *call;
	struct tapi_transceive_context *ctx;
	int err;

	DBG("%zd APDU %p", apdu_length, apdu);

	if (default_modem == NULL) {
		err = -EIO;
		goto fail;
	}

	ctx = g_try_malloc0(sizeof(struct tapi_transceive_context));
	if (ctx == NULL) {
		err = -ENOMEM;
		goto fail;
	}

	ctx->context = context;
	ctx->cb = cb;

	message = dbus_message_new_method_call(TELEPHONY_SERVICE,
					default_modem->path,
					SIM_INTERFACE, TRANSFER_APDU);

	if (message == NULL) {
		err = -ENOMEM;
		goto fail;
	}

	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_TYPE_BYTE_AS_STRING,
					&value);
	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING,
					&array);
	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
					&apdu, apdu_length);
	dbus_message_iter_close_container(&value, &array);
	dbus_message_iter_close_container(&iter, &value);

	if (dbus_connection_send_with_reply(connection, message,
					       &call, -1) == FALSE) {
		DBG("Failed to Transfer APDU through UICC");
		dbus_message_unref(message);
		err = -EINVAL;
		goto fail;
	}

	if (call == NULL) {
		DBG("D-Bus connection not available");
		dbus_message_unref(message);
		err = -EINVAL;
		goto fail;
	}

	dbus_pending_call_set_notify(call, tapi_transfer_apdu_reply,
					ctx, NULL);
	dbus_message_unref(message);

	return 0;

fail:
	cb(context, NULL, 0, err);
	if (ctx != NULL)
		g_free(ctx);

	return err;
}

static struct seel_io_driver tizen_io_driver = {
	.type = SEEL_SE_UICC,
	.transceive = tapi_transceive,
};

static uint8_t *digest_cert(const char *cert, int length)
{
	GChecksum *checksum;
	uint8_t *hash;
	gsize digest_len;

	if (cert == NULL || length < 0)
		return NULL;

	digest_len = g_checksum_type_get_length(G_CHECKSUM_SHA1);
	hash = g_try_malloc(digest_len);
	if (hash == NULL)
		return NULL;

	checksum = g_checksum_new(G_CHECKSUM_SHA1);
	if (checksum == NULL) {
		g_free(hash);
		return NULL;
	}

	g_checksum_update(checksum, cert, length);

	g_checksum_get_digest(checksum, hash, &digest_len);

	DBG("Digest is: ");
	__seel_apdu_dump(hash, digest_len);

	g_checksum_free(checksum);

	return hash;
}

static GSList *tizen_get_hashes(pid_t pid)
{
	char pkg_name[256] = { 0, };
	pkgmgrinfo_appinfo_h appinfo;
	pkgmgr_certinfo_h certinfo;
	GSList *cert_list = NULL;
	char *pkgid;
	int i;

	DBG("");

	if (aul_app_get_pkgname_bypid(pid, pkg_name, sizeof(pkg_name)) < 0)
		return NULL;

	if (pkgmgrinfo_appinfo_get_appinfo(pkg_name, &appinfo) < 0)
		return NULL;

	if (pkgmgrinfo_appinfo_get_pkgid(appinfo, &pkgid) < 0)
		goto destroy_appinfo;

	DBG("Package ID %s", pkgid);

	cert_list = g_hash_table_lookup(cert_hash, pkgid);
	if (cert_list != NULL)
		return cert_list;

	if (pkgmgr_pkginfo_create_certinfo(&certinfo) < 0)
		goto destroy_appinfo;

	if (pkgmgr_pkginfo_load_certinfo(pkgid, certinfo) < 0)
		goto destroy_certinfo;

	for (i = 0; i < MAX_CERT_TYPE; i++) {
		const char *cert_64 = NULL;
		const char *cert_bin = NULL;
		uint8_t *hash = NULL;
		gsize length;

		if (pkgmgr_pkginfo_get_cert_value(certinfo,
				(pkgmgr_cert_type)i, &cert_64) < 0)
			continue;

		if (cert_64 != NULL && strlen(cert_64) > 0) {
			cert_bin = g_base64_decode(cert_64, &length);

			if (cert_bin != NULL && length > 0)
				hash = digest_cert(cert_bin, length);

			if (hash != NULL)
				cert_list = g_slist_append(cert_list, hash);
		}
	}

	if (cert_list != NULL)
		g_hash_table_insert(cert_hash, g_strdup(pkgid), cert_list);

destroy_certinfo:
	pkgmgr_pkginfo_destroy_certinfo(certinfo);

destroy_appinfo:
	pkgmgrinfo_appinfo_destroy_appinfo(appinfo);

	return cert_list;
}

static struct seel_cert_driver tizen_cert_driver = {
	.get_hashes = tizen_get_hashes,
};


static guint watch;
static guint sim_watch;

static int tapi_init(void)
{
	int err;

	DBG("");

	connection = near_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	watch = g_dbus_add_service_watch(connection, TELEPHONY_SERVICE,
					tapi_connect, tapi_disconnect,
					NULL, NULL);

	sim_watch = g_dbus_add_signal_watch(connection, TELEPHONY_SERVICE,
					NULL, SIM_INTERFACE, SIM_STATUS,
					sim_changed, NULL, NULL);

	if (watch == 0 || sim_watch == 0) {
		err = -EIO;
		goto remove;
	}

	err = seel_io_driver_register(&tizen_io_driver);
	if (err < 0)
		goto remove;

	err = seel_cert_driver_register(&tizen_cert_driver);
	if (err < 0) {
		seel_io_driver_unregister(&tizen_io_driver);
		goto remove;
	}

	return 0;

remove:
	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, sim_watch);

	dbus_connection_unref(connection);

	return err;
}

static void tapi_exit(void)
{
	DBG("");

	seel_io_driver_unregister(&tizen_io_driver);
	seel_cert_driver_unregister(&tizen_cert_driver);

	if (modem_hash != NULL) {
		g_hash_table_destroy(modem_hash);
		modem_hash = NULL;
	}

	if (cert_hash != NULL) {
		g_hash_table_destroy(cert_hash);
		cert_hash = NULL;
	}

	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, sim_watch);

	dbus_connection_unref(connection);
}

SEEL_PLUGIN_DEFINE(tizen, "Tizen telephony plugin", VERSION,
			SEEL_PLUGIN_PRIORITY_HIGH, tapi_init, tapi_exit)

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
#include <errno.h>

#include <glib.h>

#include <gdbus.h>

#include <linux/nfc.h>

#include "near.h"

struct near_target {
	char *path;

	guint32 idx;
	guint32 adapter_idx;
	guint32 protocols;
	enum near_target_type type;
};

static DBusConnection *connection = NULL;

static GHashTable *target_hash;

static void free_target(gpointer data)
{
	struct near_target *target = data;

	g_free(target->path);
	g_free(target);
}

const char *__near_target_get_path(struct near_target *target)

{
	DBG("");

	if (target == NULL)
		return NULL;

	return target->path;
}

static void append_protocols(DBusMessageIter *iter, void *user_data)
{
	struct near_target *target = user_data;
	const char *str;

	DBG("protocols 0x%x", target->protocols);

	if (target->protocols & NFC_PROTO_FELICA) {
		str = "Felica";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->protocols & NFC_PROTO_MIFARE) {
		str = "MIFARE";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->protocols & NFC_PROTO_JEWEL) {
		str = "Jewel";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->protocols & NFC_PROTO_ISO14443_4) {
		str = "ISO-DEP";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->protocols & NFC_PROTO_NFC_DEP) {
		str = "NFC-DEP";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_adapter *target = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	near_dbus_dict_open(&array, &dict);

	near_dbus_dict_append_array(&dict, "Protocols",
				DBUS_TYPE_STRING, append_protocols, target);

	near_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("conn %p", conn);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable target_methods[] = {
	{ "GetProperties",     "",      "a{sv}", get_properties     },
	{ "SetProperty",       "sv",    "",      set_property       },
	{ },
};

static GDBusSignalTable target_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ }
};

int __near_target_add(guint32 adapter_idx, guint32 target_idx,
			guint32 protocols, enum near_target_type type)
{
	struct near_target *target;

	if (g_hash_table_lookup(target_hash,
			GINT_TO_POINTER(target_idx)) != NULL)
		return -EEXIST;

	target = g_try_malloc0(sizeof(struct near_target));
	if (target == NULL)
		return -ENOMEM;

	target->path = g_strdup_printf("%s/nfc%d/target%d", NFC_PATH,
					adapter_idx, target_idx);
	if (target->path == NULL) {
		g_free(target);
		return -ENOMEM;
	}

	target->idx = target_idx;
	target->adapter_idx = adapter_idx;
	target->protocols = protocols;
	target->type = type;

	g_hash_table_insert(target_hash, GINT_TO_POINTER(target_idx), target);

	DBG("connection %p", connection);

	g_dbus_register_interface(connection, target->path,
					NFC_TARGET_INTERFACE,
					target_methods, target_signals,
							NULL, target, NULL);

	return 0;
}

void __near_target_remove(guint32 target_idx)
{
	struct near_target *target;

	target = g_hash_table_lookup(target_hash, GINT_TO_POINTER(target_idx));
	if (target == NULL)
		return;

	free_target(target);
}

int __near_target_init(void)
{
	DBG("");

	target_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_target);

	return 0;
}

void __near_target_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(target_hash);
	target_hash = NULL;
}

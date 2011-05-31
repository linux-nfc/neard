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

#include "near.h"

struct near_target {
	char *path;

	uint32_t idx;
	uint32_t adapter_idx;
	uint32_t protocols;
	enum near_target_type type;

	uint16_t tag_type;
	struct near_tag *tag;
};

static DBusConnection *connection = NULL;

static GHashTable *target_hash;

static void free_target(gpointer data)
{
	struct near_target *target = data;

	if (target->tag != NULL)
		__near_tag_free(target->tag);
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

uint16_t __near_target_get_tag_type(struct near_target *target)
{
	return target->tag_type;
}

uint32_t __near_target_get_idx(struct near_target *target)
{
	return target->idx;
}

uint32_t __near_target_get_adapter_idx(struct near_target *target)
{
	return target->adapter_idx;
}

uint32_t __near_target_get_protocols(struct near_target *target)
{
	return target->protocols;
}

static void append_protocols(DBusMessageIter *iter, void *user_data)
{
	struct near_target *target = user_data;
	const char *str;

	DBG("protocols 0x%x", target->protocols);

	if (target->protocols & NFC_PROTO_FELICA_MASK) {
		str = "Felica";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->protocols & NFC_PROTO_MIFARE_MASK) {
		str = "MIFARE";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->protocols & NFC_PROTO_JEWEL_MASK) {
		str = "Jewel";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->protocols & NFC_PROTO_ISO14443_MASK) {
		str = "ISO-DEP";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->protocols & NFC_PROTO_NFC_DEP_MASK) {
		str = "NFC-DEP";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}
}

static void append_tag_type(DBusMessageIter *iter, void *user_data)
{
	struct near_target *target = user_data;
	const char *str;

	DBG("tag 0x%x", target->tag_type);

	if (target->tag_type & NEAR_TAG_NFC_TYPE1) {
		str = "Type 1";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->tag_type & NEAR_TAG_NFC_TYPE2) {
		str = "Type 2";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->tag_type & NEAR_TAG_NFC_TYPE3) {
		str = "Type 3";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->tag_type & NEAR_TAG_NFC_TYPE4) {
		str = "Type 4";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}

	if (target->tag_type & NEAR_TAG_NFC_DEP) {
		str = "NFC-DEP";

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);
	}
}

static const char *type2string(enum near_target_type type)
{
	DBG("");

	switch (type) {
	case NEAR_TARGET_TYPE_TAG:
		return "Tag";
	case NEAR_TARGET_TYPE_DEVICE:
		return "Device";
	}

	return NULL;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_target *target = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *type;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	type = type2string(target->type);

	dbus_message_iter_init_append(reply, &array);

	near_dbus_dict_open(&array, &dict);

	near_dbus_dict_append_basic(&dict, "Type",
				    DBUS_TYPE_STRING, &type);

	if (target->type == NEAR_TARGET_TYPE_DEVICE)
		near_dbus_dict_append_array(&dict, "Protocols",
				DBUS_TYPE_STRING, append_protocols, target);

	if (target->type == NEAR_TARGET_TYPE_TAG)
		near_dbus_dict_append_array(&dict, "TagType",
				DBUS_TYPE_STRING, append_tag_type, target);

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

#define NFC_TAG_A (NFC_PROTO_ISO14443_MASK | NFC_PROTO_NFC_DEP_MASK | \
						NFC_PROTO_MIFARE_MASK)
#define NFC_TAG_A_TYPE2      0x00
#define NFC_TAG_A_TYPE4      0x01
#define NFC_TAG_A_NFC_DEP    0x02
#define NFC_TAG_A_TYPE4_DEP  0x03

#define NFC_TAG_A_SEL_PROT(sel_res) (((sel_res) & 0x60) >> 5)

static void find_tag_type(struct near_target *target,
				uint16_t sens_res, uint8_t sel_res)
{
	DBG("protocols 0x%x sens_res 0x%x sel_res 0x%x", target->protocols,
							sens_res, sel_res);

	if (target->type != NEAR_TARGET_TYPE_TAG) {
		target->tag_type = NEAR_TAG_NFC_UNKNOWN;
		return;
	}

	if (target->protocols & NFC_TAG_A) {
		uint8_t proto = NFC_TAG_A_SEL_PROT(sel_res);

		DBG("proto 0x%x", proto);

		switch(proto) {
		case NFC_TAG_A_TYPE2:
			target->tag_type = NEAR_TAG_NFC_TYPE2;
			break;
		case NFC_TAG_A_TYPE4:
			target->tag_type = NEAR_TAG_NFC_TYPE4;
			break;
		case NFC_TAG_A_NFC_DEP:
			target->tag_type = NEAR_TAG_NFC_DEP;
			break;
		case NFC_TAG_A_TYPE4_DEP:
			target->tag_type = NEAR_TAG_NFC_TYPE4 |
						NEAR_TAG_NFC_DEP;
			break;
		}

	} else {
		target->tag_type = NEAR_TAG_NFC_UNKNOWN;
	}

	DBG("tag type 0x%x", target->tag_type);
}

int __near_target_add(uint32_t adapter_idx, uint32_t target_idx,
			uint32_t protocols, enum near_target_type type,
			uint16_t sens_res, uint8_t sel_res)
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
	find_tag_type(target, sens_res, sel_res);

	g_hash_table_insert(target_hash, GINT_TO_POINTER(target_idx), target);

	DBG("connection %p", connection);

	g_dbus_register_interface(connection, target->path,
					NFC_TARGET_INTERFACE,
					target_methods, target_signals,
							NULL, target, NULL);

	return __near_adapter_add_target(adapter_idx, target);
}

void __near_target_remove(uint32_t target_idx)
{
	struct near_target *target;

	target = g_hash_table_lookup(target_hash, GINT_TO_POINTER(target_idx));
	if (target == NULL)
		return;

	__near_adapter_remove_target(target->adapter_idx, target);

	g_dbus_unregister_interface(connection, target->path,
						NFC_TARGET_INTERFACE);

	g_hash_table_remove(target_hash, GINT_TO_POINTER(target_idx));
}

struct near_tag *near_target_get_tag(uint32_t target_idx)
{
	struct near_target *target;

	target = g_hash_table_lookup(target_hash, GINT_TO_POINTER(target_idx));
	if (target == NULL)
		return NULL;

	if (target->tag != NULL)
		return target->tag;

	target->tag = __near_tag_new(target->adapter_idx, target_idx);
	if (target->tag == NULL)
		return NULL;

	/* TODO reference the tag, or add tag reference count API */
	return target->tag;
}

int __near_target_init(void)
{
	DBG("");

	connection = near_dbus_get_connection();

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

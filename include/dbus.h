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

#include <dbus/dbus.h>

#define NFC_SERVICE     "org.neard"
#define NFC_PATH	"/org/neard"

#define NFC_ERROR_INTERFACE		NFC_SERVICE ".Error"
#define NFC_AGENT_MANAGER_INTERFACE	NFC_SERVICE ".AgentManager"
#define NFC_NDEF_AGENT_INTERFACE	NFC_SERVICE ".NDEFAgent"
#define NFC_HANDOVER_AGENT_INTERFACE	NFC_SERVICE ".HandoverAgent"

#define NFC_ADAPTER_INTERFACE		NFC_SERVICE ".Adapter"
#define NFC_DEVICE_INTERFACE		NFC_SERVICE ".Device"
#define NFC_TAG_INTERFACE		NFC_SERVICE ".Tag"
#define NFC_RECORD_INTERFACE		NFC_SERVICE ".Record"

#define SEEL_SERVICE     "org.neard.se"
#define SEEL_PATH       "/org/neard/se"

#define SEEL_ERROR_INTERFACE            SEEL_SERVICE ".Error"

#define SEEL_MANAGER_INTERFACE          SEEL_SERVICE ".Manager"
#define SEEL_MANAGER_PATH               "/"

#define SEEL_SE_INTERFACE               SEEL_SERVICE ".SecureElement"
#define SEEL_CHANNEL_INTERFACE          SEEL_SERVICE ".Channel"

typedef void (* near_dbus_append_cb_t) (DBusMessageIter *iter,
							void *user_data);

DBusConnection *near_dbus_get_connection(void);

void near_dbus_property_append_basic(DBusMessageIter *iter,
					const char *key, int type, void *val);
void near_dbus_property_append_dict(DBusMessageIter *iter, const char *key,
			near_dbus_append_cb_t function, void *user_data);
void near_dbus_property_append_array(DBusMessageIter *iter,
						const char *key, int type,
			near_dbus_append_cb_t function, void *user_data);
void near_dbus_property_append_fixed_array(DBusMessageIter *iter,
				const char *key, int type, void *val, int len);

dbus_bool_t near_dbus_property_changed_basic(const char *path,
				const char *interface, const char *key,
							int type, void *val);
dbus_bool_t near_dbus_property_changed_dict(const char *path,
				const char *interface, const char *key,
			near_dbus_append_cb_t function, void *user_data);
dbus_bool_t near_dbus_property_changed_array(const char *path,
			const char *interface, const char *key, int type,
			near_dbus_append_cb_t function, void *user_data);

dbus_bool_t near_dbus_setting_changed_basic(const char *owner,
				const char *path, const char *key,
				int type, void *val);
dbus_bool_t near_dbus_setting_changed_dict(const char *owner,
				const char *path, const char *key,
				near_dbus_append_cb_t function,
				void *user_data);
dbus_bool_t near_dbus_setting_changed_array(const char *owner,
				const char *path, const char *key, int type,
				near_dbus_append_cb_t function,
				void *user_data);

static inline void near_dbus_dict_open(DBusMessageIter *iter,
							DBusMessageIter *dict)
{
	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, dict);
}

static inline void near_dbus_dict_close(DBusMessageIter *iter,
							DBusMessageIter *dict)
{
	dbus_message_iter_close_container(iter, dict);
}

static inline void near_dbus_dict_append_basic(DBusMessageIter *dict,
					const char *key, int type, void *val)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	near_dbus_property_append_basic(&entry, key, type, val);
	dbus_message_iter_close_container(dict, &entry);
}

static inline void near_dbus_dict_append_dict(DBusMessageIter *dict,
			const char *key, near_dbus_append_cb_t function,
							void *user_data)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	near_dbus_property_append_dict(&entry, key, function, user_data);
	dbus_message_iter_close_container(dict, &entry);
}

static inline void near_dbus_dict_append_array(DBusMessageIter *dict,
		const char *key, int type, near_dbus_append_cb_t function,
							void *user_data)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	near_dbus_property_append_array(&entry, key,
						type, function, user_data);
	dbus_message_iter_close_container(dict, &entry);
}

static inline void near_dbus_dict_append_fixed_array(DBusMessageIter *dict,
				const char *key, int type, void *val, int len)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	near_dbus_property_append_fixed_array(&entry, key, type, val, len);
	dbus_message_iter_close_container(dict, &entry);
}

dbus_bool_t near_dbus_validate_ident(const char *ident);
char *near_dbus_encode_string(const char *value);

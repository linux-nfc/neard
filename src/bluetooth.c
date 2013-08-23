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
#include <string.h>
#include <errno.h>
#include <gdbus.h>

#include "near.h"

#define BLUEZ_SERVICE			"org.bluez"
#define MANAGER_INTF			BLUEZ_SERVICE ".Manager"
#define ADAPTER_INTF			BLUEZ_SERVICE ".Adapter"
#define OOB_INTF			BLUEZ_SERVICE ".OutOfBand"
#define DEFAULT_ADAPTER			"DefaultAdapter"
#define ADAPTER_REMOVED			"AdapterRemoved"
#define DEFAULT_ADAPTER_CHANGED		"DefaultAdapterChanged"
#define ADAPTER_PROPERTY_CHANGED	"PropertyChanged"
#define MANAGER_PATH			"/"
#define OOB_AGENT			"/org/neard/agent/neard_oob"

#define BT_NOINPUTOUTPUT		"NoInputNoOutput"
#define BT_DISPLAY_YESNO		"DisplayYesNo"

#define DBUS_MANAGER_INTF		"org.freedesktop.DBus.ObjectManager"
#define AGENT_REGISTER_TIMEOUT	2

/* BT EIR list */
#define EIR_UUID128_ALL		0x07 /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT		0x08 /* shortened local name */
#define EIR_NAME_COMPLETE	0x09 /* complete local name */

/* Specific OOB EIRs */
#define EIR_CLASS_OF_DEVICE	0x0D  /* class of device */
#define EIR_SP_HASH		0x0E  /* simple pairing hash C */
#define EIR_SP_RANDOMIZER	0x0F  /* simple pairing randomizer R */
/* Optional EIRs */
#define EIR_DEVICE_ID		0x10  /* device ID */
#define EIR_SECURITY_MGR_FLAGS	0x11  /* security manager flags */

#define EIR_SIZE_LEN		1
#define EIR_HEADER_LEN		(EIR_SIZE_LEN + 1)
#define BT_ADDRESS_SIZE		6
#define COD_SIZE		3
#define OOB_SP_SIZE		16
#define EIR_SIZE_MAX		255

struct near_oob_data {
	char *def_adapter;

	char *bd_addr;		/* oob mandatory */

	/* optional */
	char *bt_name;			/* short or long name */
	uint8_t bt_name_len;
	int class_of_device;		/* Class of device */
	bool powered;
	bool pairable;
	bool discoverable;
	uint8_t *uuids;
	int uuids_len;

	uint8_t *spair_hash;			/* OOB hash Key */
	uint8_t *spair_randomizer;		/* OOB randomizer key */
	uint8_t authentication[OOB_SP_SIZE];	/* On BT 2.0 */
	uint8_t security_manager_oob_flags;	/* see BT Core 4.0 */
};

static DBusConnection *bt_conn;
static struct near_oob_data bt_def_oob_data;

static guint watch;
static guint removed_watch;
static guint adapter_watch;
static guint adapter_props_watch;

static guint register_bluez_timer;

static void __bt_eir_free(struct near_oob_data *oob)
{
	DBG("");

	if (oob->def_adapter) {
		g_free(oob->def_adapter);
		oob->def_adapter = NULL;
	}

	if (oob->bd_addr) {
		g_free(oob->bd_addr);
		oob->bd_addr = NULL;
	}

	if (oob->bt_name) {
		g_free(oob->bt_name);
		oob->bt_name = NULL;
	}

	if (oob->spair_hash) {
		g_free(oob->spair_hash);
		oob->spair_hash = NULL;
	}

	if (oob->spair_randomizer) {
		g_free(oob->spair_randomizer);
		oob->spair_randomizer = NULL;
	}
}

static void bt_eir_free(struct near_oob_data *oob)
{
	__bt_eir_free(oob);

	g_free(oob);
}

/* D-Bus helper functions */
static int bt_generic_call(DBusConnection *conn,
		struct near_oob_data *oob,		/* user data */
		const char *dest,			/* method call */
		const char *path,
		const char *interface,
		const char *method,
		DBusPendingCallNotifyFunction bt_cb,	/* callback */
		int type, ...)				/* params */
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	va_list args;
	int err;

	DBG("%s", method);

	msg = dbus_message_new_method_call(dest, path, interface, method);

	if (!msg) {
		near_error("Unable to allocate new D-Bus %s message", method);
		return -ENOMEM;
	}

	va_start(args, type);

	if (!dbus_message_append_args_valist(msg, type, args)) {
		va_end(args);
		err = -EIO;
		goto error_done;
	}
	va_end(args);

	if (!dbus_connection_send_with_reply(conn, msg, &pending, -1)) {
		near_error("Sending %s failed", method);
		err = -EIO;
		goto error_done;
	}

	if (!pending) {
		near_error("D-Bus connection not available");
		err = -EIO;
		goto error_done;
	}

	/* Prepare for notification */
	dbus_pending_call_set_notify(pending, bt_cb, oob, NULL);
	err = 0 ;

error_done:
	dbus_message_unref(msg);
	return err;
}

static void bt_create_paired_device_cb(DBusPendingCall *pending,
					void *user_data)
{
	DBusMessage *reply;
	DBusError   error;
	struct near_oob_data *oob = user_data;

	DBG("");

	reply = dbus_pending_call_steal_reply(pending);
	if (!reply)
		return;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		near_error("%s", error.message);
		dbus_error_free(&error);
		goto cb_done;
	}

	DBG("Successful pairing");

cb_done:
	/* task completed - clean memory*/
	bt_eir_free(oob);

	dbus_message_unref(reply);
	dbus_pending_call_unref(pending);
}

static int bt_create_paired_device(DBusConnection *conn,
						struct near_oob_data *oob,
						const char *capabilities)
{
	const char *agent_path = OOB_AGENT;

	return bt_generic_call(bt_conn, oob, BLUEZ_SERVICE,
			oob->def_adapter, ADAPTER_INTF, "CreatePairedDevice",
			bt_create_paired_device_cb,
			/* params */
			DBUS_TYPE_STRING, &oob->bd_addr,
			DBUS_TYPE_OBJECT_PATH, &agent_path,
			DBUS_TYPE_STRING, &capabilities,
			DBUS_TYPE_INVALID);
}

static void bt_oob_add_remote_data_cb(DBusPendingCall *pending, void *user_data)
{
	DBusMessage *reply;
	DBusError   error;
	struct near_oob_data *oob = user_data;

	DBG("");

	reply = dbus_pending_call_steal_reply(pending);
	if (!reply)
		return;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply))
		goto cb_fail;

	near_info("OOB data added");

	dbus_message_unref(reply);
	dbus_pending_call_unref(pending);

	/* Jump to the next: Pairing !!!*/
	DBG("Try to pair devices...");
	bt_create_paired_device(bt_conn, oob, BT_DISPLAY_YESNO);
	return;

cb_fail:
	near_error("%s", error.message);
	dbus_error_free(&error);

	bt_eir_free(oob);

	dbus_message_unref(reply);
	dbus_pending_call_unref(pending);
}

static int bt_oob_add_remote_data(DBusConnection *conn,
						struct near_oob_data *oob)
{
	int16_t hash_len = 16;
	int16_t rdm_len = 16;

	return bt_generic_call(bt_conn, oob, BLUEZ_SERVICE,
			oob->def_adapter, OOB_INTF, "AddRemoteData",
			bt_oob_add_remote_data_cb,
			/* params */
			DBUS_TYPE_STRING, &oob->bd_addr,
			DBUS_TYPE_ARRAY,
				DBUS_TYPE_BYTE, &oob->spair_hash, hash_len,
			DBUS_TYPE_ARRAY,
				DBUS_TYPE_BYTE, &oob->spair_randomizer, rdm_len,
			DBUS_TYPE_INVALID);
}

/* Pairing: JustWorks or OOB  */
static int bt_do_pairing(struct near_oob_data *oob)
{
	int err = 0;

	DBG("%s", oob->bd_addr);

	/* Is this a *real* oob pairing or a "JustWork" */
	if ((oob->spair_hash) && (oob->spair_randomizer))
		err = bt_oob_add_remote_data(bt_conn, oob);
	else
		err = bt_create_paired_device(bt_conn, oob,
				BT_NOINPUTOUTPUT);

	if (err < 0)
		near_error("Pairing failed. Err[%d]", err);

	return err;
}

/*
 */
static int extract_properties(DBusMessage *reply, struct near_oob_data *oob)
{
	char *data = NULL;
	int idata;
	int i, j;

	DBusMessageIter array, dict;

	if (!dbus_message_iter_init(reply, &array))
		return -1;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		return -1;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Address")) {
			dbus_message_iter_get_basic(&value, &data);

			/* Now, fill the local struct */
			oob->bd_addr = g_try_malloc0(BT_ADDRESS_SIZE);
			if (!oob->bd_addr)
				return -ENOMEM;

			/* Address is like: "ff:ee:dd:cc:bb:aa" */
			for (i = 5, j = 0 ; i >= 0; i--, j += 3)
				oob->bd_addr[i] = strtol(data + j, NULL, 16);
			DBG("local address: %s", data);

		} else if (g_str_equal(key, "Name")) {
			dbus_message_iter_get_basic(&value, &data);
			oob->bt_name = g_strdup(data);
			if (oob->bt_name) {
				oob->bt_name_len = strlen(oob->bt_name);
				DBG("local name: %s", oob->bt_name);
			}

		} else if (g_str_equal(key, "Class")) {
			dbus_message_iter_get_basic(&value, &idata);
			oob->class_of_device = idata;

		} else if (g_str_equal(key, "Powered")) {
			dbus_message_iter_get_basic(&value, &idata);
			oob->powered = idata;

		} else if (g_str_equal(key, "Discoverable")) {
			dbus_message_iter_get_basic(&value, &idata);
			oob->discoverable = idata;

		} else if (g_str_equal(key, "Pairable")) {
			dbus_message_iter_get_basic(&value, &idata);
			oob->pairable = idata;

		} else if (g_str_equal(key, "UUIDs")) {
			oob->uuids_len = sizeof(value);
			oob->uuids = g_try_malloc0(oob->uuids_len);
			if (!oob->uuids)
				return -ENOMEM;
			memcpy(oob->uuids, &value, oob->uuids_len);
		}

		dbus_message_iter_next(&dict);
	}

	return 0;
}

static int bt_parse_properties(DBusMessage *reply, void *user_data)
{
	struct near_oob_data *bt_props = user_data;

	DBG("");

	/* Free datas */
	g_free(bt_props->bd_addr);
	g_free(bt_props->bt_name);

	/* Grab properties from dbus */
	if (extract_properties(reply, bt_props) < 0)
		goto fail;

	return 0;

fail:
	g_free(bt_props->bd_addr);
	bt_props->bd_addr = NULL;

	g_free(bt_props->bt_name);
	bt_props->bt_name = NULL;

	return -ENOMEM;
}

static gboolean bt_adapter_property_changed(DBusConnection *conn,
							DBusMessage *message,
							void *user_data)
{
	DBusMessageIter iter;
	DBusMessageIter var;
	const char *property;

	if (!dbus_message_iter_init(message, &iter))
		return TRUE;

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return TRUE;

	dbus_message_iter_recurse(&iter, &var);

	if (g_str_equal(property, "Name")) {
		const char *name;

		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_STRING)
			return TRUE;

		dbus_message_iter_get_basic(&var, &name);

		g_free(bt_def_oob_data.bt_name);
		bt_def_oob_data.bt_name = g_strdup(name);

		if (bt_def_oob_data.bt_name)
			bt_def_oob_data.bt_name_len = strlen(name);
		else
			bt_def_oob_data.bt_name_len = 0;

		DBG("%s: %s", property, name);
	} else if (g_str_equal(property, "Class")) {
		int class;

		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_UINT32)
			return TRUE;

		dbus_message_iter_get_basic(&var, &class);
		bt_def_oob_data.class_of_device = class;

		DBG("%s: %x", property, bt_def_oob_data.class_of_device);
	} else if (g_str_equal(property, "Powered")) {
		dbus_bool_t powered;

		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_BOOLEAN)
			return TRUE;

		dbus_message_iter_get_basic(&var, &powered);
		bt_def_oob_data.powered = powered;

		DBG("%s: %u", property, bt_def_oob_data.powered);
	}

	return TRUE;
}

/* Get default local adapter properties */
static void bt_get_properties_cb(DBusPendingCall *pending, void *user_data)
{
	struct near_oob_data *bt_props = user_data;
	DBusMessage *reply;
	DBusError   error;
	int err;

	DBG("");

	reply = dbus_pending_call_steal_reply(pending);
	if (!reply)
		return;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply))
		goto cb_fail;

	err = bt_parse_properties(reply, bt_props);
	if (err < 0)
		near_error("Problem parsing local properties %d", err);
	else
		DBG("Get Properties complete: %s", bt_props->def_adapter);

	adapter_props_watch = g_dbus_add_signal_watch(bt_conn, NULL, NULL,
						ADAPTER_INTF,
						ADAPTER_PROPERTY_CHANGED,
						bt_adapter_property_changed,
						NULL, NULL);

	/* clean */
	dbus_message_unref(reply);
	dbus_pending_call_unref(pending);
	return;

cb_fail:
	near_error("%s", error.message);
	dbus_error_free(&error);

	dbus_message_unref(reply);
	dbus_pending_call_unref(pending);
}

static void bt_get_default_adapter_cb(DBusPendingCall *pending, void *user_data)
{
	struct near_oob_data *bt_props = user_data;
	DBusMessage *reply;
	DBusError   error;
	gchar *path;

	DBG("");

	reply = dbus_pending_call_steal_reply(pending);
	if (!reply)
		return;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply))
		goto cb_fail;

	if (!dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH,
					&path, DBUS_TYPE_INVALID))
		goto cb_fail;

	/* Save the default adapter */
	bt_props->def_adapter = g_strdup(path);
	DBG("Using default adapter %s", bt_props->def_adapter);

	/* clean */
	dbus_message_unref(reply);
	dbus_pending_call_unref(pending);

	/* Jump on getAdapterProperties */
	bt_generic_call(bt_conn, bt_props,
			BLUEZ_SERVICE,
			bt_props->def_adapter,
			ADAPTER_INTF, "GetProperties",
			bt_get_properties_cb,
			DBUS_TYPE_INVALID);
	return;

cb_fail:
	near_error("Could not get Bluetooth default adapter %s", error.message);
	dbus_error_free(&error);

	dbus_message_unref(reply);
	dbus_pending_call_unref(pending);
}

static int bt_refresh_adapter_props(DBusConnection *conn, void *user_data)
{
	DBG("%p %p", conn, user_data);

	return bt_generic_call(conn, user_data,
			BLUEZ_SERVICE,
			MANAGER_PATH, MANAGER_INTF,
			DEFAULT_ADAPTER,
			bt_get_default_adapter_cb,
			DBUS_TYPE_INVALID);
}

/* Parse and fill the bluetooth oob information block */
static void bt_parse_eir(uint8_t *eir_data, uint16_t eir_data_len,
				struct near_oob_data *oob, uint16_t *props)
{
	char *tmp;
	uint16_t len = 0;

	DBG("total len: %u", eir_data_len);

	while (len < eir_data_len - 1) {
		uint8_t eir_len = eir_data[0];	/* EIR field length */
		uint8_t eir_code;		/* EIR field type*/
		uint8_t data_len;		/* EIR data length */
		uint8_t *data;

		/* check for early termination */
		if (eir_len == 0)
			break;

		len += eir_len + 1;

		/* Do not continue EIR Data parsing if got incorrect length */
		if (len > eir_data_len)
			break;

		data_len = eir_len - 1;

		eir_code = eir_data[1]; /* EIR code */
		data = &eir_data[2];

		DBG("type 0x%.2X data_len %u", eir_code, data_len);

		switch (eir_code) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			oob->bt_name = g_try_malloc0(data_len + 1); /* eos */
			if (oob->bt_name) {
				oob->bt_name_len = data_len;
				memcpy(oob->bt_name, data, oob->bt_name_len);
				oob->bt_name[data_len] = 0;	/* end str*/
			}
			break;

		case EIR_CLASS_OF_DEVICE:
			tmp = g_strdup_printf("%02X%02X%02X",
					*data, *(data + 1), *(data + 2));
			if (tmp) {
				oob->class_of_device = strtol(tmp, NULL, 16);
				*props |= OOB_PROPS_COD;
			}
			g_free(tmp);
			break;

		case EIR_SP_HASH:
			oob->spair_hash = g_try_malloc0(OOB_SP_SIZE);
			if (oob->spair_hash) {
				memcpy(oob->spair_hash, data, OOB_SP_SIZE);
				*props |= OOB_PROPS_SP_HASH;
			}
			break;

		case EIR_SP_RANDOMIZER:
			oob->spair_randomizer = g_try_malloc0(OOB_SP_SIZE);
			if (oob->spair_randomizer) {
				memcpy(oob->spair_randomizer,
						data, OOB_SP_SIZE);
				*props |= OOB_PROPS_SP_RANDOM;
			}
			break;

		case EIR_SECURITY_MGR_FLAGS:
			oob->security_manager_oob_flags = *data;
			break;

		case EIR_UUID128_ALL:
			/* TODO: Process uuids128
			 * */
			break;

		default:	/* ignore and skip */
			near_error("Unknown EIR x%02x (len: %d)", eir_code,
								eir_len);
			break;
		}
		/* Next eir */
		eir_data += eir_len + 1;
	}
}

/*
 * Because of some "old" implementation, "version" will help
 * to determine the record data structure.
 * Some specifications are proprietary (eg. "short mode")
 * and are not fully documented.
 * mime_properties is a bitmask and should reflect the fields found in
 * the incoming oob.
 */
int __near_bluetooth_parse_oob_record(struct carrier_data *data,
						uint16_t *mime_properties,
						bool pair)
{
	struct near_oob_data *oob;
	uint16_t bt_oob_data_size;
	uint8_t *ptr = data->data;
	uint8_t	marker;
	char *tmp;

	DBG("");

	oob = g_try_malloc0(sizeof(struct near_oob_data));

	if (data->type == BT_MIME_V2_1) {
		/*
		 * Total OOB data size (including size bytes)
		 * Some implementations (e.g. Android 4.1) stores
		 * the data_size in big endian but NDEF forum spec (BT Secure
		 * Simple Pairing) requires a little endian. At the same time,
		 * the NDEF forum NDEF spec define a payload length as single
		 * byte (and the payload size IS the oob data size).
		 */
		bt_oob_data_size = near_get_le16(ptr);
		if (bt_oob_data_size > 0xFF)	/* Big Endian */
			bt_oob_data_size = GUINT16_FROM_BE(bt_oob_data_size);

		bt_oob_data_size -= 2 ; /* remove oob datas size len */

		/* First item: BD_ADDR (mandatory) */
		ptr = &data->data[2];
		oob->bd_addr = g_strdup_printf("%02X:%02X:%02X:%02X:%02X:%02X",
				ptr[5],	ptr[4], ptr[3], ptr[2], ptr[1], ptr[0]);

		/* Skip to the next element (optional) */
		ptr += BT_ADDRESS_SIZE;
		bt_oob_data_size -= BT_ADDRESS_SIZE ;

		if (bt_oob_data_size)
			bt_parse_eir(ptr, bt_oob_data_size, oob,
							mime_properties);
	} else if (data->type == BT_MIME_V2_0) {
		marker = *ptr++;	/* could be '$' */

		oob->bd_addr = g_strdup_printf(
				"%02X:%02X:%02X:%02X:%02X:%02X",
				ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
		ptr = ptr + BT_ADDRESS_SIZE;

		/* Class of device */
		tmp = g_strdup_printf("%02X%02X%02X",
				*ptr, *(ptr + 1), *(ptr + 2));
		if (tmp)
			oob->class_of_device = strtol(tmp, NULL, 16);
		g_free(tmp);

		ptr = ptr + 3;

		/* "Short mode" seems to use a 4 bytes code
		 * instead of 16 bytes...
		 */
		if (marker == '$') {   /* Short NFC */
			memcpy(oob->authentication, ptr, 4);
			ptr = ptr + 4;
		} else {
			memcpy(oob->authentication, ptr, 16);
			ptr = ptr + 16;
		}

		/* get the device name */
		oob->bt_name_len = *ptr++;
		oob->bt_name = g_try_malloc0(oob->bt_name_len+1);
		if (oob->bt_name) {
			memcpy(oob->bt_name, ptr, oob->bt_name_len);
			oob->bt_name[oob->bt_name_len+1] = 0;
		}
		ptr = ptr + oob->bt_name_len;
	} else {
		bt_eir_free(oob);
		return -EINVAL;
	}

	if (!pair) {
		bt_eir_free(oob);
		return 0;
	}

	/* check and get the default adapter */
	oob->def_adapter = g_strdup(bt_def_oob_data.def_adapter);
	if (!oob->def_adapter) {
		near_error("bt_get_default_adapter failed");
		bt_eir_free(oob);
		return -EIO;
	}

	return  bt_do_pairing(oob);
}

int __near_bluetooth_pair(void *data)
{
	struct near_oob_data *oob = data;

	/* check and get the default adapter */
	oob->def_adapter = g_strdup(bt_def_oob_data.def_adapter);
	if (!oob->bt_name) {
		near_error("bt_get_default_adapter failed: %d", -EIO);
		bt_eir_free(oob);
		return -EIO;
	}

	return bt_do_pairing(oob);
}

/* This function is synchronous as oob datas change on each session */
static int bt_sync_oob_readlocaldata(DBusConnection *conn, char *adapter_path,
							char *spair_hash,
							char *spair_randomizer)
{
	DBusMessage *message, *reply;
	DBusError error;
	int hash_len, rndm_len;

	message = dbus_message_new_method_call(BLUEZ_SERVICE, adapter_path,
			OOB_INTF, "ReadLocalData");
	if (!message)
		return 0;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn,
			message, -1, &error);

	dbus_message_unref(message);

	if (!reply) {
		if (dbus_error_is_set(&error)) {
			near_error("%s", error.message);
			dbus_error_free(&error);
		} else {
			near_error("Failed to set property");
		}
		return 0;
	}

	if (!dbus_message_get_args(reply, NULL, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE, spair_hash,
					&hash_len, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE, spair_randomizer,
					&rndm_len, DBUS_TYPE_INVALID))
		goto done;

	if ((hash_len != OOB_SP_SIZE) || (rndm_len != OOB_SP_SIZE)) {
		DBG("no OOB data found !");
		goto done;
	}

	dbus_message_unref(reply);
	DBG("OOB data found");
	return hash_len;

done:
	dbus_message_unref(reply);
	return 0;
}

/*
 * External API to get bt properties
 * Prepare a "real" oob datas block
 * mime_props is a bitmask we use to add or not specific fields in the
 * oob frame (e.g.: OOB keys)
 * */
struct carrier_data *__near_bluetooth_local_get_properties(uint16_t mime_props)
{
	struct carrier_data *data = NULL;
	uint8_t offset;

	char hash[OOB_SP_SIZE];
	char random[OOB_SP_SIZE];

	/* Check adapter datas */
	if (!bt_def_oob_data.def_adapter) {
		near_error("No bt adapter info");
		goto fail;
	}

	data = g_try_malloc0(sizeof(*data));
	if (!data)
		goto fail;

	data->size = sizeof(uint16_t)	/* stored oob size */
			+ BT_ADDRESS_SIZE;	/* device address */

	offset = sizeof(uint16_t); /* Skip size...will be filled later */

	/* Now prepare data frame */
	memcpy(data->data + offset, bt_def_oob_data.bd_addr, BT_ADDRESS_SIZE);
	offset += BT_ADDRESS_SIZE;

	/* CoD */
	data->size += COD_SIZE +  EIR_HEADER_LEN;

	data->data[offset++] = COD_SIZE + EIR_SIZE_LEN;
	data->data[offset++] = EIR_CLASS_OF_DEVICE;

	memcpy(data->data + offset,
			(uint8_t *)&bt_def_oob_data.class_of_device, COD_SIZE);
	offset += COD_SIZE;

	/*
	 * The following data are generated dynamically so we have to read the
	 * local oob data. Only add OOB pairing keys if needed.
	 */
	if ((mime_props & OOB_PROPS_SP) != 0 &&
			bt_sync_oob_readlocaldata(bt_conn,
					bt_def_oob_data.def_adapter,
					hash, random) == OOB_SP_SIZE) {
		data->size += 2 * (OOB_SP_SIZE + EIR_HEADER_LEN);

		/* OOB datas */
		data->data[offset++] = OOB_SP_SIZE + EIR_SIZE_LEN;
		data->data[offset++] = EIR_SP_HASH;
		memcpy(data->data + offset, hash, OOB_SP_SIZE);
		offset += OOB_SP_SIZE;

		data->data[offset++] = OOB_SP_SIZE + EIR_SIZE_LEN;
		data->data[offset++] = EIR_SP_RANDOMIZER;
		memcpy(data->data + offset, random, OOB_SP_SIZE);
		offset += OOB_SP_SIZE;
	}

	/* bt name */
	if (bt_def_oob_data.bt_name) {
		int name_len;

		data->size += EIR_HEADER_LEN;

		if (data->size + bt_def_oob_data.bt_name_len
				> EIR_SIZE_MAX) {
			name_len = EIR_SIZE_MAX - data->size;
			data->data[offset++] = name_len + EIR_SIZE_LEN;
			/* EIR data type */
			data->data[offset++] = EIR_NAME_COMPLETE;
		} else {
			name_len = bt_def_oob_data.bt_name_len;
			data->data[offset++] = name_len + EIR_SIZE_LEN;
			/* EIR data type */
			data->data[offset++] = EIR_NAME_SHORT;
		}

		data->size += name_len;
		memcpy(data->data + offset, bt_def_oob_data.bt_name, name_len);
		offset += name_len;
	}

	data->data[0] = data->size ;

	if (bt_def_oob_data.powered)
		data->state = CPS_ACTIVE;
	else
		data->state = CPS_INACTIVE;

	return data;

fail:
	g_free(data);
	return NULL;
}

/* BT adapter removed handler */
static gboolean bt_adapter_removed(DBusConnection *conn, DBusMessage *message,
							void *user_data)
{
	DBusMessageIter iter;
	struct near_oob_data *bt_props = user_data;
	const char *adapter_path;

	DBG("");

	if (!bt_props->def_adapter)
		return TRUE;

	g_dbus_remove_watch(bt_conn, adapter_props_watch);
	adapter_props_watch = 0;

	if (!dbus_message_iter_init(message, &iter))
		return TRUE;

	dbus_message_iter_get_basic(&iter, &adapter_path);

	if (g_strcmp0(adapter_path, bt_props->def_adapter) == 0) {
		near_info("Remove the default adapter [%s]", adapter_path);

		__bt_eir_free(bt_props);
		bt_props->def_adapter = NULL;
	}

	return TRUE;
}

/* BT default adapter changed handler */
static gboolean bt_default_adapter_changed(DBusConnection *conn,
					DBusMessage *message,
					void *user_data)
{
	struct near_oob_data *bt_props = user_data;
	DBusMessageIter iter;
	const char *adapter_path;

	DBG("");

	if (!dbus_message_iter_init(message, &iter))
		return TRUE;

	g_dbus_remove_watch(bt_conn, adapter_props_watch);
	adapter_props_watch = 0;

	dbus_message_iter_get_basic(&iter, &adapter_path);
	DBG("New default adapter [%s]", adapter_path);

	/* Disable the old one */
	__bt_eir_free(bt_props);
	bt_props->def_adapter = NULL;

	/* Refresh */
	bt_refresh_adapter_props(conn, user_data);

	return TRUE;
}

static void bt_dbus_disconnect_cb(DBusConnection *conn, void *user_data)
{
	near_error("D-Bus disconnect (BT)");
	bt_conn = NULL;
}

static gboolean register_bluez(gpointer user_data)
{
	DBG("");

	register_bluez_timer = 0;

	removed_watch = g_dbus_add_signal_watch(bt_conn, NULL, NULL,
						MANAGER_INTF,
						ADAPTER_REMOVED,
						bt_adapter_removed,
						&bt_def_oob_data, NULL);


	adapter_watch = g_dbus_add_signal_watch(bt_conn, NULL, NULL,
						MANAGER_INTF,
						DEFAULT_ADAPTER_CHANGED,
						bt_default_adapter_changed,
						&bt_def_oob_data, NULL);

	if (removed_watch == 0 || adapter_watch == 0) {
		near_error("BlueZ event handlers failed to register.");
		g_dbus_remove_watch(bt_conn, removed_watch);
		g_dbus_remove_watch(bt_conn, adapter_watch);

		return FALSE;
	}

	if (bt_refresh_adapter_props(bt_conn, user_data) < 0)
		near_error("Failed to get BT adapter properties");

	return FALSE;
}

static void bt_connect(DBusConnection *conn, void *data)
{
	DBG("connection %p with %p", conn, data);

	if (__near_agent_handover_registered(HO_AGENT_BT)) {
		DBG("Agent already registered");
		return;
	}

	/*
	 * BlueZ 5 will register itself as HandoverAgent, give it some time
	 * to do it before going legacy way.
	 */
	register_bluez_timer = g_timeout_add_seconds(AGENT_REGISTER_TIMEOUT,
							register_bluez, data);
}

static void bt_disconnect(DBusConnection *conn, void *user_data)
{
	DBG("%p", conn);

	/* If timer is running no BlueZ watchers were registered yet */
	if (register_bluez_timer > 0) {
		g_source_remove(register_bluez_timer);
		register_bluez_timer = 0;
		return;
	}

	__bt_eir_free(user_data);

	g_dbus_remove_watch(bt_conn, removed_watch);
	removed_watch = 0;

	g_dbus_remove_watch(bt_conn, adapter_watch);
	adapter_watch = 0;

	g_dbus_remove_watch(bt_conn, adapter_props_watch);
	adapter_props_watch = 0;
}

static int bt_prepare_handlers(DBusConnection *conn)
{
	if (__near_agent_handover_registered(HO_AGENT_BT))
		return 0;

	watch = g_dbus_add_service_watch(bt_conn, BLUEZ_SERVICE,
						bt_connect,
						bt_disconnect,
						&bt_def_oob_data, NULL);
	if (watch == 0) {
		near_error("BlueZ service watch handler failed to register.");
		g_dbus_remove_watch(bt_conn, watch);
		return -EIO;
	}

	return 0;
}

void __near_bluetooth_legacy_start(void)
{
	DBG("");

	bt_prepare_handlers(bt_conn);
}

void __near_bluetooth_legacy_stop(void)
{
	DBG("");

	g_dbus_remove_watch(bt_conn, watch);
	watch = 0;

	bt_disconnect(bt_conn, &bt_def_oob_data);
}

/* Bluetooth exiting function */
void __near_bluetooth_cleanup(void)
{
	DBG("");

	if (!bt_conn)
		return;

	__near_bluetooth_legacy_stop();

	dbus_connection_unref(bt_conn);
}

/*
 * Bluetooth initialization function.
 *	Allocate bt local settings storage
 *	and setup event handlers
 */
int __near_bluetooth_init(void)
{
	DBusError err;

	DBG("");

	dbus_error_init(&err);

	/* save the dbus connection */
	bt_conn = near_dbus_get_connection();
	if (!bt_conn) {
		if (dbus_error_is_set(&err)) {
			near_error("%s", err.message);
			dbus_error_free(&err);
		} else
			near_error("Can't register with system bus\n");
		return -EIO;
	}

	/* dbus disconnect callback */
	g_dbus_set_disconnect_function(bt_conn, bt_dbus_disconnect_cb,
						NULL, NULL);

	/* Set bluez event handlers */
	return bt_prepare_handlers(bt_conn);
}

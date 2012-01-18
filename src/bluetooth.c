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
#define MANAGER_PATH			"/"
#define OOB_AGENT			"/org/neard/agent/neard_oob"

#define BT_NOINPUTOUTPUT		"NoInputNoOutput"
#define BT_DISPLAY_YESNO		"DisplayYesNo"

/* BT EIR list */
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
#define BT_ADDRESS_SIZE		6
#define OOB_SP_SIZE		16

struct near_oob_data {
	char *def_adapter;

	char *bd_addr;		/* oob mandatory */

	/* optional */
	uint8_t *bt_name;			/* short or long name */
	uint8_t bt_name_len;
	uint8_t class_of_device[3];		/* Class of device */
	uint8_t *spair_hash;			/* OOB hash Key */
	uint8_t *spair_randomizer;		/* OOB randomizer key */
	uint8_t authentication[16];		/* On BT 2.0 */
	uint8_t security_manager_oob_flags;	/* see BT Core 4.0 */
};

static DBusConnection *bt_conn;

static int bt_do_pairing(struct near_oob_data *oob);

static void bt_eir_free(struct near_oob_data *oob)
{
	DBG("");

	g_free(oob->def_adapter);
	g_free(oob->bd_addr);
	g_free(oob->bt_name);
	g_free(oob->spair_hash);
	g_free(oob->spair_randomizer);

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

	if (msg == NULL) {
		near_error("Unable to allocate new D-Bus %s message", method);
		err = -ENOMEM;
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

	if (pending == NULL) {
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
	if (reply == NULL)
		return;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		near_error("%s", error.message);
		dbus_error_free(&error);
		goto cb_done;
	}

	near_info("Pairing done successfully !");

cb_done:
	/* task completed - clean memory*/
	bt_eir_free(oob);

	dbus_message_unref(reply);
	dbus_pending_call_unref(pending);

	return;
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
	if (reply == NULL)
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

	return;
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

static void bt_get_default_adapter_cb(DBusPendingCall *pending, void *user_data)
{
	DBusMessage *reply;
	DBusError   error;
	gchar *path;
	struct near_oob_data *oob = user_data;

	DBG("");

	reply = dbus_pending_call_steal_reply(pending);
	if (reply == NULL)
		return;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply))
		goto cb_fail;

	if (dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH,
					&path, DBUS_TYPE_INVALID) == FALSE)
		goto cb_fail;

	/* Save the default adapter */
	oob->def_adapter = g_strdup(path);
	DBG("Using default adapter %s", oob->def_adapter);

	/* clean */
	dbus_message_unref(reply);
	dbus_pending_call_unref(pending);

	/* check if device is already registered */
	bt_do_pairing(oob);

	return;

cb_fail:
	near_error("%s", error.message);
	dbus_error_free(&error);

	bt_eir_free(oob);
	dbus_message_unref(reply);
	dbus_pending_call_unref(pending);

	return;
}

static int bt_get_default_adapter(DBusConnection *conn,
					struct near_oob_data *oob)
{
	DBG("");

	return bt_generic_call(bt_conn, oob, BLUEZ_SERVICE,
			MANAGER_PATH, MANAGER_INTF, "DefaultAdapter",
			bt_get_default_adapter_cb,
			DBUS_TYPE_INVALID);
}

/* Parse and fill the bluetooth oob information block */
static int bt_parse_eir(uint8_t *ptr, uint16_t bt_oob_data_size,
		struct near_oob_data *oob)
{
	uint8_t	eir_code;
	uint8_t eir_length;

	DBG("");

	while (bt_oob_data_size) {
		eir_length = *ptr++;	/* EIR length */
		eir_code = *ptr++;	/* EIR code */

		bt_oob_data_size = bt_oob_data_size - eir_length;

		/* check for early termination */
		if (eir_length == 0) {
			bt_oob_data_size = 0;
			continue;
		}

		eir_length -= EIR_SIZE_LEN;

		switch (eir_code) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			oob->bt_name = g_try_malloc0(eir_length+1);
			if (oob->bt_name) {
				oob->bt_name_len = eir_length ;
				memcpy(oob->bt_name, ptr, eir_length);
				oob->bt_name[eir_length] = 0;	/* end str*/
			}
			ptr = ptr + eir_length;
			break;

		case EIR_CLASS_OF_DEVICE:
			memcpy(oob->class_of_device, ptr, eir_length);
			ptr = ptr + eir_length;
			break;

		case EIR_SP_HASH:
			oob->spair_hash = g_try_malloc0(OOB_SP_SIZE);
			if (oob->spair_hash)
				memcpy(oob->spair_hash,
						ptr, OOB_SP_SIZE);
			ptr = ptr + eir_length;
			break;

		case EIR_SP_RANDOMIZER:
			oob->spair_randomizer = g_try_malloc0(OOB_SP_SIZE);
			if (oob->spair_randomizer)
				memcpy(oob->spair_randomizer,
						ptr, OOB_SP_SIZE);
			ptr = ptr + eir_length;
			break;

		case EIR_SECURITY_MGR_FLAGS:
			oob->security_manager_oob_flags = *ptr;
			ptr = ptr + eir_length;
			break;

		default:	/* ignore and skip */
			ptr = ptr + eir_length;
			break;
		}
	}

	return 0;
}

/*
 * Because of some "old" implementation, "version" will help
 * to determine the record data structure.
 * Some specifications are proprietary (eg. "short mode")
 * and are not fully documented.
 */
int __near_bt_parse_oob_record(uint8_t version, uint8_t *bt_data)
{
	struct near_oob_data *oob;
	uint16_t bt_oob_data_size;
	uint8_t	*ptr = bt_data;
	uint8_t	marker;
	int err;

	DBG("");

	oob = g_try_malloc0(sizeof(struct near_oob_data));

	if (version == BT_MIME_V2_1) {
		/* Total OOB data size (including size bytes)*/
		bt_oob_data_size = *((uint16_t *)(bt_data));
		bt_oob_data_size -= 2 ; /* remove oob datas size len */

		/* First item: BD_ADDR (mandatory) */
		ptr = &bt_data[2];
		oob->bd_addr = g_strdup_printf("%02X:%02X:%02X:%02X:%02X:%02X",
				ptr[5],	ptr[4], ptr[3], ptr[2], ptr[1], ptr[0]);

		/* Skip to the next element (optional) */
		ptr += BT_ADDRESS_SIZE;
		bt_oob_data_size -= BT_ADDRESS_SIZE ;

		if (bt_oob_data_size)
			bt_parse_eir(ptr, bt_oob_data_size, oob);
	} else if (version == BT_MIME_V2_0) {
		marker = *ptr++;	/* could be '$' */

		oob->bd_addr = g_strdup_printf(
				"%02X:%02X:%02X:%02X:%02X:%02X",
				ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
		ptr = ptr + BT_ADDRESS_SIZE;

		/* Class of device */
		memcpy(oob->class_of_device, ptr, 3);
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
		return -EINVAL;
	}

	/* check and get the default adapter */
	err = bt_get_default_adapter(bt_conn, oob);
	if (err  < 0) {
		near_error("bt_get_default_adapter failed: %d", err);
		bt_eir_free(oob);
		return err;
	}

	return 0;
}

static void bt_disconnect_callback(DBusConnection *conn, void *user_data)
{
	near_error("D-Bus disconnect (BT)");
	bt_conn = NULL;
}

void __near_bluetooth_cleanup(void)
{
	DBG("");
	if (bt_conn)
		dbus_connection_unref(bt_conn);
	return;
}

int __near_bluetooth_init(void)
{
	DBusError err;

	DBG("");

	dbus_error_init(&err);

	/* save the dbus connection */
	bt_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, &err);
	if (bt_conn == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			near_error("%s", err.message);
			dbus_error_free(&err);
		} else
			near_error("Can't register with system bus\n");
		return -1;
	}

	g_dbus_set_disconnect_function(bt_conn, bt_disconnect_callback,
				NULL, NULL);

	return 0;
}

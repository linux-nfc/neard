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

#include <stdint.h>
#include <sys/socket.h>

#include <linux/socket.h>
#include <linux/nfc.h>

#include <glib.h>

#include <near/types.h>

struct near_adapter;

#include <near/log.h>

int __near_log_init(const char *debug, gboolean detach);
void __near_log_cleanup(void);

#include <near/dbus.h>

int __near_dbus_init(DBusConnection *conn);
void __near_dbus_cleanup(void);

DBusMessage *__near_error_failed(DBusMessage *msg, int errnum);
DBusMessage *__near_error_invalid_arguments(DBusMessage *msg);
DBusMessage *__near_error_permission_denied(DBusMessage *msg);
DBusMessage *__near_error_passphrase_required(DBusMessage *msg);
DBusMessage *__near_error_not_registered(DBusMessage *msg);
DBusMessage *__near_error_not_unique(DBusMessage *msg);
DBusMessage *__near_error_not_supported(DBusMessage *msg);
DBusMessage *__near_error_not_implemented(DBusMessage *msg);
DBusMessage *__near_error_not_found(DBusMessage *msg);
DBusMessage *__near_error_no_carrier(DBusMessage *msg);
DBusMessage *__near_error_in_progress(DBusMessage *msg);
DBusMessage *__near_error_already_exists(DBusMessage *msg);
DBusMessage *__near_error_already_enabled(DBusMessage *msg);
DBusMessage *__near_error_already_disabled(DBusMessage *msg);
DBusMessage *__near_error_already_connected(DBusMessage *msg);
DBusMessage *__near_error_not_connected(DBusMessage *msg);
DBusMessage *__near_error_operation_aborted(DBusMessage *msg);
DBusMessage *__near_error_operation_timeout(DBusMessage *msg);
DBusMessage *__near_error_invalid_service(DBusMessage *msg);
DBusMessage *__near_error_invalid_property(DBusMessage *msg);

int __near_manager_adapter_add(uint32_t idx, const char *name,
			uint32_t protocols, near_bool_t powered);
void __near_manager_adapter_remove(uint32_t idx);
int __near_manager_init(DBusConnection *conn);
void __near_manager_cleanup(void);

#include <near/adapter.h>

struct near_adapter * __near_adapter_create(uint32_t idx,
		const char *name, uint32_t protocols, near_bool_t powered);
void __near_adapter_destroy(struct near_adapter *adapter);
const char *__near_adapter_get_path(struct near_adapter *adapter);
struct near_adapter *__near_adapter_get(uint32_t idx);
int __near_adapter_add(struct near_adapter *adapter);
void __near_adapter_remove(struct near_adapter *adapter);
int __near_adapter_add_target(uint32_t idx, uint32_t target_idx,
			uint32_t protocols, uint16_t sens_res, uint8_t sel_res,
			uint8_t *nfcid, uint8_t nfcid_len);
int __near_adapter_remove_target(uint32_t idx, uint32_t target_idx);
int __near_adapter_set_dep_state(uint32_t idx, near_bool_t dep);
void __near_adapter_tags_changed(uint32_t adapter_idx);
void __near_adapter_devices_changed(uint32_t adapter_idx);
void __near_adapter_list(DBusMessageIter *iter, void *user_data);
int __near_adapter_init(void);
void __near_adapter_cleanup(void);

#include <near/ndef.h>

#define NFC_MAX_URI_ID	0x23

int __near_ndef_init(void);
void __near_ndef_cleanup(void);
int __near_ndef_record_register(struct near_ndef_record *record, char *path);
void __near_ndef_record_free(struct near_ndef_record *record);
char *__near_ndef_record_get_path(struct near_ndef_record *record);
const char *__near_ndef_get_uri_prefix(uint8_t id);
struct near_ndef_message *__ndef_build_from_message(DBusMessage *msg);

#include <near/tag.h>

int __near_tag_init(void);
void __near_tag_cleanup(void);
struct near_tag *__near_tag_add(uint32_t idx, uint32_t target_idx,
				uint32_t protocols,
				uint16_t sens_res, uint8_t sel_res,
				uint8_t *nfcid, uint8_t nfcid_len);
void __near_tag_remove(struct near_tag *tag);
const char *__near_tag_get_path(struct near_tag *tag);
uint32_t __near_tag_get_idx(struct near_tag *tag);
uint32_t __near_tag_get_type(struct near_tag *tag);
void __near_tag_append_records(struct near_tag *tag, DBusMessageIter *iter);
int __near_tag_read(struct near_tag *tag, near_tag_io_cb cb);
int __near_tag_write(struct near_tag *tag,
				struct near_ndef_message *ndef,
				near_tag_io_cb cb);
int __near_tag_check_presence(struct near_tag *tag, near_tag_io_cb cb);

#include <near/device.h>

int __near_device_init(void);
void __near_device_cleanup(void);
const char *__near_device_get_path(struct near_device *device);
struct near_device *__near_device_add(uint32_t idx, uint32_t target_idx,
					uint8_t *nfcid, uint8_t nfcid_len);
void __near_device_remove(struct near_device *device);
int __near_device_listen(struct near_device *device, near_device_io_cb cb);

#include <near/tlv.h>

int __near_netlink_get_adapters(void);
int __near_netlink_start_poll(int idx, uint32_t protocols);
int __near_netlink_stop_poll(int idx);
int __near_netlink_dep_link_up(uint32_t idx, uint32_t target_idx,
				uint8_t comm_mode, uint8_t rf_mode);
int __near_netlink_dep_link_down(uint32_t idx);
int __near_netlink_adapter_enable(int idx, near_bool_t enable);
int __near_netlink_activate_target(uint32_t adapter_idx,
					uint32_t target_idx,
					uint32_t protocol);
int __near_netlink_deactivate_target(uint32_t adapter_idx,
					uint32_t target_idx);
int __near_netlink_init(void);
void __near_netlink_cleanup(void);

#include <near/setting.h>

#include <near/plugin.h>

int __near_plugin_init(const char *pattern, const char *exclude);
void __near_plugin_cleanup(void);

/* NFC Bluetooth Secure Simple Pairing */
#define BT_MIME_V2_0		0
#define BT_MIME_V2_1		1

int __near_bluetooth_init(void);
void __near_bluetooth_cleanup(void);
int __near_bt_parse_oob_record(uint8_t version, uint8_t *bt_data);

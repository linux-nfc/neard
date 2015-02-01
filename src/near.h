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
#include <stdbool.h>
#include <sys/socket.h>

#include <linux/socket.h>

#include <glib.h>

#include <near/nfc_copy.h>
#include <near/types.h>

struct near_adapter;
struct near_device_driver;

#include <near/log.h>

int __near_log_init(const char *debug, gboolean detach);
void __near_log_cleanup(void);

#include <near/dbus.h>

int __near_dbus_init(DBusConnection *conn);
void __near_dbus_cleanup(void);

DBusMessage *__near_error_failed(DBusMessage *msg, int errnum);
DBusMessage *__near_error_invalid_arguments(DBusMessage *msg);
DBusMessage *__near_error_out_of_memory(DBusMessage *msg);
DBusMessage *__near_error_permission_denied(DBusMessage *msg);
DBusMessage *__near_error_passphrase_required(DBusMessage *msg);
DBusMessage *__near_error_not_registered(DBusMessage *msg);
DBusMessage *__near_error_not_unique(DBusMessage *msg);
DBusMessage *__near_error_not_supported(DBusMessage *msg);
DBusMessage *__near_error_not_implemented(DBusMessage *msg);
DBusMessage *__near_error_not_found(DBusMessage *msg);
DBusMessage *__near_error_not_polling(DBusMessage *msg);
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
DBusMessage *__near_error_io_error(DBusMessage *msg);

int __near_manager_adapter_add(uint32_t idx, const char *name,
			uint32_t protocols, bool powered);
void __near_manager_adapter_remove(uint32_t idx);
int __near_manager_init(DBusConnection *conn);
void __near_manager_cleanup(void);

#include <near/adapter.h>

struct near_adapter *__near_adapter_create(uint32_t idx,
		const char *name, uint32_t protocols, bool powered);
void __near_adapter_destroy(struct near_adapter *adapter);
const char *__near_adapter_get_path(struct near_adapter *adapter);
struct near_adapter *__near_adapter_get(uint32_t idx);
int __near_adapter_add(struct near_adapter *adapter);
void __near_adapter_remove(struct near_adapter *adapter);
int __near_adapter_add_target(uint32_t idx, uint32_t target_idx,
			uint32_t protocols, uint16_t sens_res, uint8_t sel_res,
			uint8_t *nfcid, uint8_t nfcid_len,
			uint8_t iso15693_dsfid,
			uint8_t iso15693_uid_len, uint8_t *iso15693_uid);
int __near_adapter_remove_target(uint32_t idx, uint32_t target_idx);
int __near_adapter_get_targets_done(uint32_t idx);
int __near_adapter_add_device(uint32_t idx, uint8_t *nfcid, uint8_t nfcid_len);
int __near_adapter_remove_device(uint32_t idx);
int __near_adapter_set_dep_state(uint32_t idx, bool dep);
bool __near_adapter_get_dep_state(uint32_t idx);
void __near_adapter_listen(struct near_device_driver *driver);
void __near_adapter_start_check_presence(uint32_t adapter_idx, uint32_t target_idx);
void __near_adapter_stop_check_presence(uint32_t adapter_idx, uint32_t target_idx);
int __near_adapter_init(void);
void __near_adapter_cleanup(void);

#include <near/ndef.h>

#define NFC_MAX_URI_ID	0x23

int __near_ndef_init(void);
void __near_ndef_cleanup(void);
int __near_ndef_record_register(struct near_ndef_record *record, char *path);
void __near_ndef_record_free(struct near_ndef_record *record);
char *__near_ndef_record_get_path(struct near_ndef_record *record);
char *__near_ndef_record_get_type(struct near_ndef_record *record);
uint8_t *__near_ndef_record_get_data(struct near_ndef_record *record, size_t *len);
uint8_t *__near_ndef_record_get_payload(struct near_ndef_record *record, size_t *len);
void __near_ndef_append_records(DBusMessageIter *iter, GList *record);
const char *__near_ndef_get_uri_prefix(uint8_t id);
struct near_ndef_message *__ndef_build_from_message(DBusMessage *msg);

#include <near/snep.h>

int __near_snep_core_init(void);
void __near_snep_core_cleanup(void);

#include <near/tag.h>

int __near_tag_init(void);
void __near_tag_cleanup(void);
struct near_tag *__near_tag_add(uint32_t adapter_idx, uint32_t target_idx,
				uint32_t protocols,
				uint16_t sens_res, uint8_t sel_res,
				uint8_t *nfcid, uint8_t nfcid_len,
				uint8_t iso15693_dsfid,
				uint8_t iso15693_uid_len,
				uint8_t *iso15693_uid);
void __near_tag_remove(struct near_tag *tag);
const char *__near_tag_get_path(struct near_tag *tag);
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
uint32_t __neard_device_get_idx(struct near_device *device);
struct near_device *__near_device_add(uint32_t idx, uint32_t target_idx,
					uint8_t *nfcid, uint8_t nfcid_len);
void __near_device_remove(struct near_device *device);
bool __near_device_register_interface(struct near_device *device);
int __near_device_listen(struct near_device *device, near_device_io_cb cb);
int __near_device_push(struct near_device *device,
			struct near_ndef_message *ndef, char *service_name,
			near_device_io_cb cb);

#include <near/tlv.h>

int __near_netlink_get_adapters(void);
int __near_netlink_start_poll(int idx,
			uint32_t im_protocols, uint32_t tm_protocols);
int __near_netlink_stop_poll(int idx);
int __near_netlink_activate_target(uint32_t idx, uint32_t target_idx,
                                   uint32_t protocol);
int __near_netlink_dep_link_up(uint32_t idx, uint32_t target_idx,
				uint8_t comm_mode, uint8_t rf_mode);
int __near_netlink_dep_link_down(uint32_t idx);
int __near_netlink_adapter_enable(int idx, bool enable);
int __near_netlink_init(void);
void __near_netlink_cleanup(void);

#include <near/setting.h>

#include <near/plugin.h>

int __near_plugin_init(const char *pattern, const char *exclude);
void __near_plugin_cleanup(void);

/* NFC Bluetooth Secure Simple Pairing */
#define BT_MIME_V2_0		0
#define BT_MIME_V2_1		1
#define WIFI_WSC_MIME		2
#define BT_MIME_STRING_2_0	"nokia.com:bt"
#define BT_MIME_STRING_2_1	"application/vnd.bluetooth.ep.oob"
#define WIFI_WSC_MIME_STRING	"application/vnd.wfa.wsc"

/* Mime specific properties */
#define OOB_PROPS_EMPTY		0x00
#define OOB_PROPS_SP_HASH	0x01
#define OOB_PROPS_SP_RANDOM	0x02
#define OOB_PROPS_SHORT_NAME	0x04
#define OOB_PROPS_COD		0x08
#define OOB_PROPS_SP		(OOB_PROPS_SP_HASH | OOB_PROPS_SP_RANDOM)

/* Handover Agent Carrier Types */
#define NEAR_HANDOVER_AGENT_BLUETOOTH	"bluetooth"
#define NEAR_HANDOVER_AGENT_WIFI		"wifi"

#define NEAR_CARRIER_MAX	2

#define WIFI_WSC_ID_SSID        0x1045
#define WIFI_WSC_ID_AUTH_TYPE   0x1003
#define WIFI_WSC_ID_KEY         0x1027
#define WIFI_WSC_KEY_OPEN       0x0001
#define WIFI_WSC_KEY_PSK        0x0022
#define WIFI_WSC_ID_LENGTH      2
#define WIFI_WSC_ID_DATA_LENGTH 2

/* near_ndef_handover_carrier*/
enum handover_carrier {
	NEAR_CARRIER_EMPTY =  0x00,
	NEAR_CARRIER_BLUETOOTH = 0x01,	/* bit 0 */
	NEAR_CARRIER_WIFI      = 0x02,	/* bit 1 */
	NEAR_CARRIER_UNKNOWN   = 0x80,	/* Bit 7 */
};

enum carrier_power_state {
	CPS_INACTIVE    = 0x00,
	CPS_ACTIVE      = 0x01,
	CPS_ACTIVATING  = 0x02,
	CPS_UNKNOWN     = 0x03,
};

enum ho_agent_carrier {
	HO_AGENT_BT	= 0x00,
	HO_AGENT_WIFI	= 0x01,
	HO_AGENT_UNKNOWN = 0xFF
};

struct carrier_data {
	uint8_t type;
	uint8_t size;
	enum carrier_power_state state;
	uint8_t data[UINT8_MAX];
};

int __near_bluetooth_init(void);
void __near_bluetooth_cleanup(void);
void __near_bluetooth_legacy_start(void);
void __near_bluetooth_legacy_stop(void);
int __near_bluetooth_parse_oob_record(struct carrier_data *data,
					uint16_t *properties, bool pair);
int __near_bluetooth_pair(void *data);
struct carrier_data *__near_bluetooth_local_get_properties(uint16_t mime_props);

void __near_agent_ndef_parse_records(GList *records);
bool __near_agent_handover_registered(enum ho_agent_carrier carrier);

struct carrier_data *__near_agent_handover_request_data(
					enum ho_agent_carrier carrier,
					struct carrier_data *data);
int __near_agent_handover_push_data(enum ho_agent_carrier carrier,
					struct carrier_data *data);

int __near_agent_init(void);
void __near_agent_cleanup(void);

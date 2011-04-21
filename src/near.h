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

#include <glib.h>

#include "log.h"

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

int __near_manager_init(DBusConnection *conn);
void __near_manager_cleanup(void);

int __near_adapter_create(const char *name, guint32 idx, guint32 protocols);
void __near_adapter_list(DBusMessageIter *iter, void *user_data);
int __near_adapter_init(void);
void __near_adapter_cleanup(void);

int __near_netlink_get_adapters(void);
int __near_netlink_init(void);
void __near_netlink_cleanup(void);

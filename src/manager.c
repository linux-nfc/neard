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

static DBusConnection *connection;

int __near_manager_adapter_add(uint32_t idx, const char *name,
				uint32_t protocols, bool powered)
{
	struct near_adapter *adapter;
	const char *path;
	int err;

	DBG("idx %d", idx);

	adapter = __near_adapter_create(idx, name, protocols, powered);
	if (!adapter)
		return -ENOMEM;

	path = __near_adapter_get_path(adapter);
	if (!path) {
		__near_adapter_destroy(adapter);
		return -EINVAL;
	}

	err = __near_adapter_add(adapter);
	if (err < 0)
		__near_adapter_destroy(adapter);

	return err;
}

void __near_manager_adapter_remove(uint32_t idx)
{
	struct near_adapter *adapter;
	const char *path;

	DBG("idx %d", idx);

	adapter = __near_adapter_get(idx);
	if (!adapter)
		return;

	path = __near_adapter_get_path(adapter);
	if (!path)
		return;

	__near_adapter_remove(adapter);
}

int __near_manager_init(DBusConnection *conn)
{
	DBG("");

	connection = dbus_connection_ref(conn);

	DBG("connection %p", connection);

	g_dbus_attach_object_manager(connection);

	return __near_netlink_get_adapters();
}

void __near_manager_cleanup(void)
{
	DBG("");

	g_dbus_detach_object_manager(connection);

	dbus_connection_unref(connection);
}

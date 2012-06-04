/*
 *
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <glib.h>

#include <gdbus.h>

#include "near.h"

static DBusConnection *connection = NULL;
static guint agent_watch = 0;
static gchar *agent_path = NULL;
static gchar *agent_sender = NULL;

static void agent_free(void)
{
	agent_watch = 0;

	g_free(agent_sender);
	agent_sender = NULL;

	g_free(agent_path);
	agent_path = NULL;
}

static void agent_disconnect(DBusConnection *connection, void *data)
{
	DBG("data %p", data);

	agent_free();
}

int __near_handover_agent_register(const char *sender, const char *path)
{
	DBG("sender %s path %s", sender, path);

	if (agent_path != NULL)
		return -EEXIST;

	agent_sender = g_strdup(sender);
	agent_path = g_strdup(path);

	agent_watch = g_dbus_add_disconnect_watch(connection, sender,
						agent_disconnect, NULL, NULL);

	return 0;
}

int __near_handover_agent_unregister(const char *sender, const char *path)
{
	DBG("sender %s path %s", sender, path);

	if (agent_path == NULL)
		return -ESRCH;

	if (agent_watch > 0)
		g_dbus_remove_watch(connection, agent_watch);

	agent_free();

	return 0;
}

int __near_handover_init(void)
{
	DBG("");

	connection = near_dbus_get_connection();
	if (connection == NULL)
		return -1;

	return 0;
}

void __near_handover_cleanup(void)
{
	DBG("");

	agent_free();
}

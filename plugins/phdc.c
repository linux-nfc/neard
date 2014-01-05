/*
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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
 *  Foundation.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

#include <near/nfc_copy.h>
#include <near/dbus.h>
#include <near/log.h>
#include <near/device.h>

#include <glib.h>

#include <gdbus.h>

#include "p2p.h"


#define NFC_NEARD_PHDC_IFACE		NFC_SERVICE ".PHDC"
#define NFC_NEARD_PHDC_PATH		"/"

/* Phdc Agent */
#define PHDC_MANAGER_IFACE		"org.neard.PHDC.Manager"
#define DEFAULT_PHDC_AGENT_PATH		"/"
#define DEFAULT_PHDC_SERVICE		"urn:nfc:sn:phdc"

/*
 * Client role
 * TODO: Extend the role to Agent
 */
#define ROLE_MANAGER_TEXT		"Manager"
#define ROLE_AGENT_TEXT			"Agent"

enum near_role_id {
	ROLE_UNKNOWN	= 0,
	ROLE_MANAGER	= 1,
	ROLE_AGENT	= 2,
};

#define AGENT_NEWCONNECTION	"NewConnection"
#define AGENT_DISCONNECT	"Disconnection"
#define AGENT_RELEASE		"Release"

struct near_phdc_data {
	char *sender;			/* dbus sender internal */
	enum near_role_id role;		/* Manager or Agent */
	char *path;			/* dbus manager path */
	struct near_p2p_driver *p2p_driver;	/* associated p2p driver */
	guint watch;			/* dbus watch */
};

static DBusConnection *phdc_conn;
static GHashTable *mgr_list = NULL;	/* Existing managers list */

static DBusMessage *error_invalid_arguments(DBusMessage *msg)
{
	return g_dbus_create_error(msg, NFC_ERROR_INTERFACE
				".InvalidArguments", "Invalid arguments");
}

static DBusMessage *error_not_found(DBusMessage *msg)
{
	return g_dbus_create_error(msg, NFC_ERROR_INTERFACE
						".NotFound", "Not found");
}

static DBusMessage *error_permission_denied(DBusMessage *msg)
{
	return g_dbus_create_error(msg, NFC_ERROR_INTERFACE
				".PermissionDenied", "PermissionDenied");
}

static DBusMessage *error_failed(DBusMessage *msg, int errnum)
{
	const char *str = strerror(errnum);

	return g_dbus_create_error(msg, NFC_ERROR_INTERFACE
					".Failed", "%s", str);
}

/* Search for the specific path */
static void *search_mgr_list_by_path(const char *path)
{
	struct near_phdc_data *tmp;
	GHashTableIter it;
	gpointer key;

	DBG("Look for mgr path %s", path);
	g_hash_table_iter_init(&it, mgr_list);
	while (g_hash_table_iter_next(&it, &key, (gpointer *)&tmp))
		if (g_str_equal(tmp->path, path))
			return (void *)tmp;
	return NULL;
}

/* add the new phdc manager if the associated service is not already there */
static int manager_add_to_list(struct near_phdc_data *mgr)
{
	DBG(" mgr service name %s", mgr->p2p_driver->service_name);

	if (g_hash_table_lookup(mgr_list, mgr->p2p_driver->service_name)) {
		near_error("[%s] already present",
						mgr->p2p_driver->service_name);
		return -EALREADY;
	}

	g_hash_table_insert(mgr_list, mgr->p2p_driver->service_name, mgr);

	return 0;
}

static void mgr_agent_release(gpointer key, gpointer data, gpointer user_data)
{
	struct near_phdc_data *mgr_data = data;
	DBusMessage *message;

	DBG("%s %s", mgr_data->sender, mgr_data->path);

	message = dbus_message_new_method_call(mgr_data->sender, mgr_data->path,
					PHDC_MANAGER_IFACE, AGENT_RELEASE);
	if (!message)
		return;

	dbus_message_set_no_reply(message, TRUE);

	g_dbus_send_message(phdc_conn, message);
}

static void free_mgr_data(gpointer data)
{
	struct near_phdc_data *mgr_data = data;

	DBG("%p", data);

	/* free memory */
	if (mgr_data->watch > 0)
		g_dbus_remove_watch(phdc_conn, mgr_data->watch);

	if (mgr_data->p2p_driver) {
		g_free(mgr_data->p2p_driver->name);
		g_free(mgr_data->p2p_driver->service_name);
		g_free(mgr_data->p2p_driver);
	}

	g_free(mgr_data->path);
	g_free(mgr_data->sender);

	g_free(mgr_data);
}

/*
 * This function is called  when a new client (Phdc Agent) connects on the
 * same p2p service as the one we previously registered. We have to find the
 * right Phdc Manager (with the service name) to send it the file descriptor.
 */
static bool phdc_p2p_newclient(char *service_name, int agent_fd, gpointer data)
{
	DBusMessage *msg;
	DBusMessageIter args;
	struct near_phdc_data *mgr;

	DBG("");

	if ((!agent_fd) || (!service_name))
		return false;

	DBG("service name: %s fd: %d", service_name, agent_fd);

	/* Look for existing service name */
	mgr = g_hash_table_lookup(mgr_list, service_name);
	if (!mgr)
		return false;

	mgr->p2p_driver->user_data = mgr;

	/* Call the pdhc manager */
	msg = dbus_message_new_method_call(mgr->sender, mgr->path,
						PHDC_MANAGER_IFACE,
						AGENT_NEWCONNECTION);
	if (!msg) {
		near_error("msg NULL");
		return false;
	}

	/* Add args */
	dbus_message_iter_init_append(msg, &args);

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_UNIX_FD,
								&agent_fd)) {
		near_error("out of memory");
		return false;
	}

	dbus_message_set_no_reply(msg, TRUE);
	if (g_dbus_send_message(phdc_conn, msg) == FALSE) {
		near_error("Dbus send failed");
		return false;
	}

	return true;
}

static void phdc_p2p_close(int agent_fd, int err, gpointer data)
{
	DBusMessage *msg;
	DBusMessageIter args;
	struct near_phdc_data *mgr;

	mgr = (struct near_phdc_data *)data;

	DBG("fd: %d err: %d mgr:%p", agent_fd, err, mgr);
	if (!mgr) {
		near_error("mgr is null");
		return;
	}

	msg = dbus_message_new_method_call(mgr->sender,	mgr->path,
						PHDC_MANAGER_IFACE,
						AGENT_DISCONNECT);
	if (!msg) {
		near_error("msg NULL");
		return;
	}

	dbus_message_iter_init_append(msg, &args);

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_UNIX_FD,
								&agent_fd)) {
		near_error("out of memory");
		return;
	}

	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, &err)) {
		near_error("out of memory");
		return;
	}

	dbus_message_set_no_reply(msg, TRUE);

	if (g_dbus_send_message(phdc_conn, msg) == FALSE)
		near_error("Dbus send failed");
}

/* Called when the external Phdc manager ends or disconnect */
static void phdc_manager_disconnect(DBusConnection *conn, void *user_data)
{
	struct near_phdc_data *phdc_mgr = user_data;

	phdc_mgr->watch = 0;

	DBG("PHDC manager %s disconnected", phdc_mgr->sender);
	/* Stop the associated p2p driver */
	near_p2p_unregister(phdc_mgr->p2p_driver);

	g_hash_table_remove(mgr_list, phdc_mgr->p2p_driver->service_name);
}

/*
 * Parse the data dictionary sent, to fill the phdc_mgr and p2p driver struct.
 */
static int parse_dictionary(DBusMessage *msg, void *data,
		struct near_phdc_data *phdc_mgr,
		struct near_p2p_driver *p2p)
{
	DBusMessageIter array, dict;
	int err;

	/* p2p should exist */
	if (!p2p)
		return -EINVAL;

	if (dbus_message_iter_init(msg, &array) == FALSE)
		return -EINVAL;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		return -EINVAL;

	dbus_message_iter_recurse(&array, &dict);

	err = -ENOMEM;
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		/* get p2p driver service name */
		if (g_str_equal(key, "ServiceName")) {
			dbus_message_iter_get_basic(&value, &data);
			g_free(p2p->service_name);

			p2p->service_name = g_strdup(data);
			if (!p2p->service_name)
				goto error;
		}

		if (g_str_equal(key, "Path")) {
			dbus_message_iter_get_basic(&value, &data);
			g_free(phdc_mgr->path);
			phdc_mgr->path = g_strdup(data);
			if (!phdc_mgr->path)
				goto error;
		} else if (g_str_equal(key, "Role")) {
			dbus_message_iter_get_basic(&value, &data);
			/* Manager or Agent only */
			if (g_strcmp0(data, ROLE_MANAGER_TEXT) == 0)
				phdc_mgr->role = ROLE_MANAGER;
			else if (g_strcmp0(data, ROLE_AGENT_TEXT) == 0)
				phdc_mgr->role = ROLE_AGENT;
			else {
				err = -EINVAL;
				goto error;
			}
		}

		dbus_message_iter_next(&dict);
	}

	return 0;

error:
	g_free(p2p->service_name);
	p2p->service_name = NULL;


	g_free(phdc_mgr->path);
	phdc_mgr->path = NULL;

	return err;
}

/*
 * A Phdc Manager requests to be added to the manager list.
 * - parse the parameters
 *
 * Initial version: the PHDC manager calls dbus_register_phdc_manager,
 * sending a simple path and a service name
 * TODO: check for DBUS_TYPE_UNIX_FD   ((int) 'h')
 */
static DBusMessage *dbus_register_phdc_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_phdc_data *phdc_mgr;
	int err;

	DBG("conn %p", conn);

	/* Allocate the phdc_mgr struct */
	phdc_mgr = g_try_malloc0(sizeof(struct near_phdc_data));
	if (!phdc_mgr) {
		err = -ENOMEM;
		goto error;
	}

	/* Allocate a default p2p_driver */
	phdc_mgr->p2p_driver = g_try_malloc0(sizeof(struct near_p2p_driver));
	if (!phdc_mgr->p2p_driver) {
		err = -ENOMEM;
		goto error;
	}

	/* Get the the sender name */
	phdc_mgr->sender = g_strdup(dbus_message_get_sender(msg));

	DBG("%s", phdc_mgr->sender);

	/* default p2p values */
	phdc_mgr->p2p_driver->fallback_service_name = NULL;
	phdc_mgr->p2p_driver->sock_type = SOCK_STREAM;
	phdc_mgr->p2p_driver->single_connection = FALSE;
	phdc_mgr->p2p_driver->new_client = phdc_p2p_newclient;
	phdc_mgr->p2p_driver->close = phdc_p2p_close;

	/* look for dict values and fill the struct */
	err = parse_dictionary(msg, data, phdc_mgr, phdc_mgr->p2p_driver);
	if (err < 0)
		goto error;

	/* TODO: At this time, there's no support for Role == Agent */
	if (phdc_mgr->role == ROLE_AGENT) {
		err = -ENOTSUP;
		goto error;
	}

	/* No correct role ? */
	if (phdc_mgr->role == ROLE_UNKNOWN) {
		err = -EINVAL;
		goto error;
	}

	/* No path ? */
	if (!phdc_mgr->path) {
		err = -EINVAL;
		goto error;
	}

	/* defaulting the p2p driver */
	if (!phdc_mgr->p2p_driver->service_name)
		phdc_mgr->p2p_driver->service_name =
						g_strdup(DEFAULT_PHDC_SERVICE);

	/* p2p internal name */
	phdc_mgr->p2p_driver->name = g_strdup_printf("{%s-%s}",
			(phdc_mgr->role == ROLE_MANAGER ? ROLE_MANAGER_TEXT :
							ROLE_AGENT_TEXT),
					phdc_mgr->p2p_driver->service_name);

	/* if one pointer is null, memory failed ! */
	if ((!phdc_mgr->p2p_driver->name) ||
				(!phdc_mgr->p2p_driver->service_name)) {
		err = -ENOMEM;
		goto error;
	}

	/* Watch the Phdc Manager */
	phdc_mgr->watch = g_dbus_add_disconnect_watch(phdc_conn,
							phdc_mgr->sender,
							phdc_manager_disconnect,
							phdc_mgr, NULL);
	/* Add to the existing Manager list */
	err = manager_add_to_list(phdc_mgr);
	if (err < 0)
		goto error;

	/* and register the p2p driver for the specified service */
	err = near_p2p_register(phdc_mgr->p2p_driver);
	if (err < 0)
		goto error;

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

error:
	/* free memory */
	if (phdc_mgr)
		free_mgr_data(phdc_mgr);

	return error_failed(msg, -err);
}

/*
 * Phdc Manager requests to be removed from the existing list of managers.
 */
static DBusMessage *dbus_unregister_phdc_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct near_phdc_data *mgr;
	DBusMessageIter iter;
	const char *path, *role, *sender;

	DBG("conn %p", conn);

	if (!dbus_message_iter_init(msg, &iter))
		return error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return error_invalid_arguments(msg);

	sender = dbus_message_get_sender(msg);

	dbus_message_iter_get_basic(&iter, &path);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &role);

	/* look for specific path */
	mgr = search_mgr_list_by_path(path);
	if (!mgr)
		return error_not_found(msg);

	DBG("%s", mgr->sender);

	if (strncmp(sender, mgr->sender, strlen(mgr->sender)))
		return error_permission_denied(msg);

	/* remove it */
	near_p2p_unregister(mgr->p2p_driver);

	g_hash_table_remove(mgr_list, mgr->p2p_driver->service_name);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable phdc_methods[] = {
	{ GDBUS_METHOD("RegisterAgent",
			GDBUS_ARGS({"", "a{sv}"}),
			NULL, dbus_register_phdc_agent) },

{ GDBUS_METHOD("UnregisterAgent",
			GDBUS_ARGS({ "path", "o" }, { "type", "s"}),
			NULL, dbus_unregister_phdc_agent) },
	{ },
};

/* Initialize the PHDC plugin - Expose our dbus entry points */
int phdc_init(void)
{
	gboolean err;

	DBG("");

	/* save the dbus connection */
	phdc_conn = near_dbus_get_connection();

	mgr_list = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
								free_mgr_data);

	/* register dbus interface */
	err = g_dbus_register_interface(phdc_conn, "/org/neard",
							NFC_NEARD_PHDC_IFACE,
							phdc_methods,
							NULL, NULL, NULL, NULL);

	return err;
}

/* Called when exiting neard */
void phdc_exit(void)
{
	DBG("");

	/* Notify listeners...*/
	g_hash_table_foreach(mgr_list, mgr_agent_release, NULL);

	g_dbus_unregister_interface(phdc_conn, "/org/neard",
							NFC_NEARD_PHDC_IFACE);
	/* Clean before leaving */
	g_hash_table_remove_all(mgr_list);
	g_hash_table_destroy(mgr_list);
}

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

#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/socket.h>
#include <linux/nfc.h>

#include <near/plugin.h>
#include <near/log.h>
#include <near/types.h>
#include <near/target.h>
#include <near/adapter.h>
#include <near/tlv.h>

#include "p2p.h"

static GSList *driver_list = NULL;

struct p2p_data {
	struct near_p2p_driver *driver;
	uint32_t adapter_idx;
	uint32_t target_idx;
	near_tag_io_cb cb;
	int fd;
	guint watch;

	GList *client_list;
};

static gboolean p2p_client_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct p2p_data *client_data = user_data;
	near_bool_t more;

	DBG("condition 0x%x", condition);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		if (client_data->watch > 0)
			g_source_remove(client_data->watch);
		client_data->watch = 0;

		if (client_data->driver->close != NULL)
			client_data->driver->close(client_data->fd, -EIO);

		near_error("Error with %s client channel",
					client_data->driver->name);

		return FALSE;
	}

	more = client_data->driver->read(client_data->fd,
						client_data->adapter_idx,
						client_data->target_idx,
						client_data->cb);

	if (more == FALSE) {
		if (client_data->driver->close != NULL)
			client_data->driver->close(client_data->fd, 0);
		close(client_data->fd);
	}

	return more;
}

static void p2p_free_clients(struct p2p_data *server_data)
{
	GList *list;
	struct p2p_data *client_data;

	list = server_data->client_list;

	while (list != NULL) {
		client_data = (struct p2p_data *)list->data;

		list = list->next;

		server_data->client_list =
			g_list_remove(server_data->client_list, client_data);
		if (client_data->driver->close != NULL)
			client_data->driver->close(client_data->fd, 0);
		g_free(client_data);
	}
}

static gboolean p2p_listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct sockaddr_nfc_llcp client_addr;
	socklen_t client_addr_len;
	int server_fd, client_fd;
	struct p2p_data *client_data, *server_data = user_data;
	GIOChannel *client_channel;
	struct near_p2p_driver *driver = server_data->driver;

	DBG("condition 0x%x", condition);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		if (server_data->watch > 0)
			g_source_remove(server_data->watch);
		server_data->watch = 0;
		p2p_free_clients(server_data);

		near_error("Error with %s server channel", driver->name);

		return TRUE;
	}

	server_fd = g_io_channel_unix_get_fd(channel);

	client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
							&client_addr_len);
	if (client_fd < 0) {
		near_error("accept failed %d", client_fd);

		close(server_fd);
		return FALSE;
	}

	DBG("client dsap %d ssap %d",
		client_addr.dsap, client_addr.ssap);

	client_data = g_try_malloc0(sizeof(struct p2p_data));
	if (client_data == NULL) {
		close(client_fd);
		return FALSE;
	}

	client_data->driver = server_data->driver;
	client_data->adapter_idx = server_data->adapter_idx;
	client_data->target_idx = server_data->target_idx;
	client_data->fd = client_fd;
	client_data->cb = server_data->cb;

	client_channel = g_io_channel_unix_new(client_fd);
	g_io_channel_set_close_on_unref(client_channel, TRUE);

	client_data->watch = g_io_add_watch(client_channel,
				G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
				p2p_client_event,
				client_data);

	server_data->client_list = g_list_append(server_data->client_list, client_data);

	return TRUE;
}

static int p2p_bind(struct near_p2p_driver *driver, uint32_t adapter_idx,
		uint32_t target_idx, near_tag_io_cb cb)
{
	int err, fd;
	struct sockaddr_nfc_llcp addr;
	GIOChannel *channel;
	struct p2p_data *server_data;

	DBG("Binding %s", driver->name);

	fd = socket(AF_NFC, SOCK_STREAM, NFC_SOCKPROTO_LLCP);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(struct sockaddr_nfc_llcp));
	addr.sa_family = AF_NFC;
	addr.dev_idx = adapter_idx;
	addr.nfc_protocol = NFC_PROTO_NFC_DEP;
	addr.service_name_len = strlen(driver->service_name);
	strcpy(addr.service_name, driver->service_name);

	err = bind(fd, (struct sockaddr *)&addr,
			sizeof(struct sockaddr_nfc_llcp));
	if (err < 0) {
		near_error("%s bind failed %d", driver->name, err);

		close(fd);
		return err;
	}

	err = listen(fd, 10);
	if (err < 0) {
		near_error("%s listen failed %d", driver->name, err);

		close(fd);
		return err;
	}

	server_data = g_try_malloc0(sizeof(struct p2p_data));
	if (server_data == NULL) {
		close(fd);
		return -ENOMEM;
	}

	server_data->driver = driver;
	server_data->adapter_idx = adapter_idx;
	server_data->target_idx = target_idx;
	server_data->fd = fd;
	server_data->cb = cb;

	channel = g_io_channel_unix_new(fd);
	g_io_channel_set_close_on_unref(channel, TRUE);

	server_data->watch = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
				p2p_listener_event,
				(gpointer) server_data);

	return 0;
}

static int p2p_read(uint32_t adapter_idx,
		uint32_t target_idx, near_tag_io_cb cb)
{
	int err = 0;
	GSList *list;

	for (list = driver_list; list != NULL; list = list->next) {
		struct near_p2p_driver *driver = list->data;

		err &= p2p_bind(driver, adapter_idx, target_idx, cb);
	}

	return err;
}

static int p2p_check_presence(uint32_t adapter_idx, uint32_t target_idx,
							near_tag_io_cb cb)
{
	int present = -ENODEV;

	DBG("Present %d", near_adapter_get_dep_state(adapter_idx));

	if (near_adapter_get_dep_state(adapter_idx) == TRUE)
		present = 0;

	cb(adapter_idx, target_idx, present);

	return 0;
}

static struct near_tag_driver p2p_driver = {
	.type           = NFC_PROTO_NFC_DEP,
	.priority       = NEAR_TAG_PRIORITY_HIGH,
	.read_tag       = p2p_read,
	.check_presence = p2p_check_presence,
};


int near_p2p_register(struct near_p2p_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_prepend(driver_list, driver);

	return 0;
}

void near_p2p_unregister(struct near_p2p_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}

static int p2p_init(void)
{
	DBG("");

	npp_init();
	snep_init();
	handover_init();

	return near_tag_driver_register(&p2p_driver);
}

static void p2p_exit(void)
{
	DBG("");

	snep_exit();
	npp_exit();
	handover_exit();

	near_tag_driver_unregister(&p2p_driver);
}

NEAR_PLUGIN_DEFINE(p2p, "NFC Forum peer to peer mode support", VERSION,
		NEAR_PLUGIN_PRIORITY_HIGH, p2p_init, p2p_exit)

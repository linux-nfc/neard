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
#include <near/tag.h>
#include <near/device.h>
#include <near/adapter.h>
#include <near/tlv.h>
#include <near/ndef.h>

#include "p2p.h"

static GSList *driver_list = NULL;
static GList *server_list = NULL;

struct p2p_data {
	struct near_p2p_driver *driver;
	uint32_t adapter_idx;
	uint32_t target_idx;
	near_device_io_cb cb;
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
		int err;

		if (client_data->watch > 0)
			g_source_remove(client_data->watch);
		client_data->watch = 0;

		if (condition & (G_IO_NVAL | G_IO_ERR))
			err = -EIO;
		else
			err = 0;

		if (client_data->driver->close != NULL)
			client_data->driver->close(client_data->fd, err);

		near_error("%s client channel closed",
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

static void free_client_data(gpointer data)
{
	struct p2p_data *client_data;

	DBG("");

	client_data = (struct p2p_data *)data;

	if (client_data->driver->close != NULL)
		client_data->driver->close(client_data->fd, 0);

	if (client_data->watch > 0)
		g_source_remove(client_data->watch);

	g_free(client_data);
}

static void free_server_data(gpointer data)
{
	struct p2p_data *server_data;

	DBG("");

	server_data = (struct p2p_data *)data;

	if (server_data->watch > 0)
		g_source_remove(server_data->watch);
	server_data->watch = 0;
	g_list_free_full(server_data->client_list, free_client_data);

	DBG("Closing server socket");

	close(server_data->fd);
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

	server_fd = g_io_channel_unix_get_fd(channel);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		if (server_data->watch > 0)
			g_source_remove(server_data->watch);
		server_data->watch = 0;
		g_list_free_full(server_data->client_list, free_client_data);

		close(server_fd);

		near_error("Error with %s server channel", driver->name);

		return FALSE;
	}

	client_addr_len = sizeof(client_addr);
	client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
							&client_addr_len);
	if (client_fd < 0) {
		near_error("accept failed %d", client_fd);

		close(server_fd);
		return FALSE;
	}

	DBG("client dsap %d ssap %d",
		client_addr.dsap, client_addr.ssap);
	DBG("target idx %d", client_addr.target_idx);

	client_data = g_try_malloc0(sizeof(struct p2p_data));
	if (client_data == NULL) {
		close(client_fd);
		return FALSE;
	}

	client_data->driver = server_data->driver;
	client_data->adapter_idx = server_data->adapter_idx;
	client_data->target_idx = client_addr.target_idx;
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
							near_device_io_cb cb)
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
		if (errno == EADDRINUSE) {
			DBG("%s is already bound", driver->name);
			return 0;
		}

		near_error("%s bind failed %d %d", driver->name, err, errno);

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
	server_data->fd = fd;
	server_data->cb = cb;

	channel = g_io_channel_unix_new(fd);
	g_io_channel_set_close_on_unref(channel, TRUE);

	server_data->watch = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
				p2p_listener_event,
				(gpointer) server_data);

	server_list = g_list_append(server_list, server_data);

	return 0;
}

static int p2p_listen(uint32_t adapter_idx, near_device_io_cb cb)
{
	int err = 0;
	GSList *list;

	for (list = driver_list; list != NULL; list = list->next) {
		struct near_p2p_driver *driver = list->data;

		err &= p2p_bind(driver, adapter_idx, cb);
	}

	return err;
}

static int p2p_connect(uint32_t adapter_idx, uint32_t target_idx,
			struct near_ndef_message *ndef,
			near_device_io_cb cb,  struct near_p2p_driver *driver)
{
	int fd, err = 0;
	struct sockaddr_nfc_llcp addr;

	DBG("");

	fd = socket(AF_NFC, SOCK_STREAM, NFC_SOCKPROTO_LLCP);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(struct sockaddr_nfc_llcp));
	addr.sa_family = AF_NFC;
	addr.dev_idx = adapter_idx;
	addr.target_idx = target_idx;
	addr.nfc_protocol = NFC_PROTO_NFC_DEP;
	addr.service_name_len = strlen(driver->service_name);
	strcpy(addr.service_name, driver->service_name);

	err = connect(fd, (struct sockaddr *)&addr,
			sizeof(struct sockaddr_nfc_llcp));
	if (err < 0) {
		near_error("Connect failed  %d", err);
		close(fd);

		return err;
	}

	return fd;
}

static int p2p_push(uint32_t adapter_idx, uint32_t target_idx,
			struct near_ndef_message *ndef, char *service_name,
			near_device_io_cb cb)
{
	int fd;
	GSList *list;

	DBG("");

	for (list = driver_list; list != NULL; list = list->next) {
		struct near_p2p_driver *driver = list->data;

		if (strcmp(driver->service_name, service_name) != 0)
			continue;

		fd = p2p_connect(adapter_idx, target_idx, ndef, cb, driver);
		if (fd < 0)
			return fd;

		return driver->push(fd, adapter_idx, target_idx, ndef, cb);
	}

	return -1;
}

static struct near_device_driver p2p_driver = {
	.priority       = NEAR_DEVICE_PRIORITY_HIGH,
	.listen         = p2p_listen,
	.push		= p2p_push,
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

	return near_device_driver_register(&p2p_driver);
}

static void p2p_exit(void)
{
	DBG("");

	g_list_free_full(server_list, free_server_data);

	snep_exit();
	npp_exit();
	handover_exit();

	near_device_driver_unregister(&p2p_driver);
}

NEAR_PLUGIN_DEFINE(p2p, "NFC Forum peer to peer mode support", VERSION,
		NEAR_PLUGIN_PRIORITY_HIGH, p2p_init, p2p_exit)

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
#include <near/tlv.h>

#include "p2p.h"

static GSList *driver_list = NULL;

struct p2p_driver_data {
	struct near_p2p_driver *driver;
	uint32_t adapter_idx;
	uint32_t target_idx;
	near_tag_io_cb cb;
	int server_fd;
	guint watch;
};

static gboolean p2p_listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct sockaddr_nfc_llcp client_addr;
	int server_fd, client_fd;
	socklen_t client_addr_len;
	struct p2p_driver_data *driver_data = user_data;
	struct near_p2p_driver *driver = driver_data->driver;

	DBG("condition 0x%x", condition);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		if (driver_data->watch > 0)
			g_source_remove(driver_data->watch);
		driver_data->watch = 0;

		near_error("Error with %s server channel", driver->name);

		return FALSE;
	}

	if (condition & G_IO_IN) {
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

		driver->read(client_fd, driver_data->adapter_idx,
				driver_data->target_idx, driver_data->cb);

		close(client_fd);

		return FALSE;
	}

	return FALSE;
}

static int p2p_bind(struct near_p2p_driver *driver, uint32_t adapter_idx,
		uint32_t target_idx, near_tag_io_cb cb)
{
	int err, fd;
	struct sockaddr_nfc_llcp addr;
	GIOChannel *channel;
	struct p2p_driver_data *driver_data;

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

	driver_data = g_try_malloc0(sizeof(struct p2p_driver_data));
	if (driver_data == NULL) {
		close(fd);
		return -ENOMEM;
	}

	driver_data->driver = driver;
	driver_data->adapter_idx = adapter_idx;
	driver_data->target_idx = target_idx;
	driver_data->server_fd = fd;
	driver_data->cb = cb;

	channel = g_io_channel_unix_new(fd);
	g_io_channel_set_close_on_unref(channel, TRUE);

	driver_data->watch = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
				p2p_listener_event,
				(gpointer) driver_data);

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

static struct near_tag_driver p2p_driver = {
		.type     = NEAR_TAG_NFC_DEP,
		.read_tag = p2p_read,
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

	return near_tag_driver_register(&p2p_driver);
}

static void p2p_exit(void)
{
	DBG("");

	snep_exit();
	npp_exit();

	near_tag_driver_unregister(&p2p_driver);
}

NEAR_PLUGIN_DEFINE(p2p, "NFC Forum peer to peer mode support", VERSION,
		NEAR_PLUGIN_PRIORITY_HIGH, p2p_init, p2p_exit)

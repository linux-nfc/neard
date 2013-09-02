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
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>

#include <linux/socket.h>

#include <near/nfc_copy.h>
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
	struct p2p_data *server;

	GList *client_list;
};

/* common function for socket binding */
static int __p2p_bind(struct p2p_data *server_data, GIOFunc listener)
{
	int err, fd = server_data->fd;
	struct sockaddr_nfc_llcp addr;
	GIOChannel *channel;
	struct near_p2p_driver *driver = server_data->driver;

	DBG("Binding %s", driver->name);

	memset(&addr, 0, sizeof(struct sockaddr_nfc_llcp));
	addr.sa_family = AF_NFC;
	addr.dev_idx = server_data->adapter_idx;
	addr.nfc_protocol = NFC_PROTO_NFC_DEP;
	addr.service_name_len = strlen(driver->service_name);
	strcpy(addr.service_name, driver->service_name);

	err = bind(fd, (struct sockaddr *) &addr,
			sizeof(struct sockaddr_nfc_llcp));
	if (err < 0) {
		if (errno == EADDRINUSE) {
			DBG("%s is already bound", driver->name);
			err = 0;
			goto out_err;
		}

		near_error("%s bind failed %d %d", driver->name, err, errno);
		goto out_err;
	}

	if (server_data->driver->sock_type == SOCK_STREAM) {
		err = listen(fd, 10);
		if (err < 0) {
			near_error("%s listen failed %d", driver->name, err);
			goto out_err;
		}
	}

	channel = g_io_channel_unix_new(fd);
	g_io_channel_set_close_on_unref(channel, TRUE);

	server_data->watch = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
				listener, (gpointer) server_data);
	g_io_channel_unref(channel);

	return 0;

out_err:
	close(fd);
	return err;
}

static gboolean p2p_listener_event(GIOChannel *channel, GIOCondition condition,
				   gpointer user_data);

struct p2p_connect {
	uint32_t adapter_idx;
	uint32_t target_idx;
	guint watch;
	struct near_p2p_driver *driver;
	struct near_ndef_message *ndef;
	near_device_io_cb cb;
};

static gboolean p2p_client_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct p2p_data *client_data = user_data;

	DBG("condition 0x%x", condition);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		int err;
		struct p2p_data *server_data = client_data->server;

		if (client_data->watch > 0)
			g_source_remove(client_data->watch);
		client_data->watch = 0;

		if (condition & (G_IO_NVAL | G_IO_ERR))
			err = -EIO;
		else
			err = 0;

		if (client_data->driver->close)
			client_data->driver->close(client_data->fd, err,
						client_data->driver->user_data);

		near_error("%s client channel closed",
					client_data->driver->name);

		if (server_data)
			server_data->client_list =
				g_list_remove(server_data->client_list,
								client_data);

		if (client_data->driver->single_connection) {
			server_data->fd = socket(AF_NFC, SOCK_STREAM,
							NFC_SOCKPROTO_LLCP);
			if (server_data->fd > 0)
				__p2p_bind(server_data, p2p_listener_event);
		}

		if (client_data->driver->sock_type == SOCK_STREAM)
			g_free(client_data);

		return FALSE;
	}

	if (client_data->driver->new_client)
		return true;

	return client_data->driver->read(client_data->fd,
						client_data->adapter_idx,
						client_data->target_idx,
						client_data->cb,
						client_data->driver->user_data);

}

static void free_client_data(gpointer data)
{
	struct p2p_data *client_data;

	DBG("");

	client_data = (struct p2p_data *) data;

	if (client_data->driver->close)
		client_data->driver->close(client_data->fd, 0,
						client_data->driver->user_data);

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
	server_data->client_list = NULL;

	DBG("Closing server socket");

	close(server_data->fd);

	g_free(server_data);
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
		server_data->client_list = NULL;

		near_error("Error with %s server channel", driver->name);

		return FALSE;
	}

	client_addr_len = sizeof(client_addr);
	client_fd = accept(server_fd, (struct sockaddr *) &client_addr,
							&client_addr_len);
	if (client_fd < 0) {
		near_error("accept failed %d", client_fd);

		return FALSE;
	}

	DBG("client dsap %d ssap %d",
		client_addr.dsap, client_addr.ssap);
	DBG("target idx %d", client_addr.target_idx);

	client_data = g_try_malloc0(sizeof(struct p2p_data));
	if (!client_data) {
		close(client_fd);
		return FALSE;
	}

	client_data->driver = server_data->driver;
	client_data->adapter_idx = server_data->adapter_idx;
	client_data->target_idx = client_addr.target_idx;
	client_data->fd = client_fd;
	client_data->cb = server_data->cb;
	client_data->server = server_data;

	client_channel = g_io_channel_unix_new(client_fd);
	g_io_channel_set_close_on_unref(client_channel, TRUE);

	/* This would enable passthru active */
	if (server_data->driver->new_client)
		server_data->driver->new_client(
				client_data->driver->service_name, client_fd,
				server_data->driver->user_data);

	client_data->watch = g_io_add_watch(client_channel,
				G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
				p2p_client_event,
				client_data);

	g_io_channel_unref(client_channel);

	server_data->client_list = g_list_append(server_data->client_list,
								client_data);

	return !driver->single_connection;
}

static int p2p_connect_blocking(uint32_t adapter_idx, uint32_t target_idx,
				struct near_ndef_message *ndef,
				near_device_io_cb cb,
				struct near_p2p_driver *driver)
{
	int fd, err = 0;
	struct timeval timeout;
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

	timeout.tv_sec = 8;
	timeout.tv_usec = 0;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
			sizeof(timeout)) < 0)
		near_error("Could not set the receive timeout\n");

	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
			sizeof(timeout)) < 0)
		near_error("Could not set the send timeout\n");

	err = connect(fd, (struct sockaddr *) &addr,
			sizeof(struct sockaddr_nfc_llcp));
	if (err < 0) {
		near_error("Connect failed  %d", err);
		close(fd);

		return err;
	}

	return fd;
}

static gboolean p2p_push_blocking(gpointer user_data)
{
	struct p2p_connect *conn = user_data;
	int fd, err;

	DBG("");

	fd = p2p_connect_blocking(conn->adapter_idx, conn->target_idx,
				  conn->ndef, conn->cb, conn->driver);
	if (fd < 0) {
		err = fd;
		goto out;
	}

	err = conn->driver->push(fd, conn->adapter_idx, conn->target_idx,
						conn->ndef, conn->cb,
						conn->driver->user_data);

out:
	if (err < 0)
		conn->cb(conn->adapter_idx, conn->target_idx, err);

	g_free(conn->ndef->data);
	g_free(conn->ndef);
	g_free(conn);

	return FALSE;
}

static bool check_nval(GIOChannel *io)
{
	struct pollfd fds;

	memset(&fds, 0, sizeof(fds));
	fds.fd = g_io_channel_unix_get_fd(io);
	fds.events = POLLNVAL;

	if (poll(&fds, 1, 0) > 0 && (fds.revents & POLLNVAL))
		return true;

	return false;
}

static gboolean p2p_connect_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct p2p_connect *conn = user_data;
	int err, sk_err, fd;
	socklen_t len = sizeof(sk_err);

	DBG("condition 0x%x", condition);

	if (!conn->driver->push) {
		err = -EOPNOTSUPP;
		goto out;
	}

	fd = g_io_channel_unix_get_fd(channel);

	if ((condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) ||
						check_nval(channel)) {
		near_error("%s connect error", conn->driver->name);

		if (condition & G_IO_HUP) {
			DBG("Trying a blocking connect");

			close(fd);

			g_timeout_add(300, p2p_push_blocking, conn);

			return FALSE;
		}

		err = -EIO;
		goto out;
	}

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
		err = -errno;
	else
		err = -sk_err;
	if (err < 0) {
		near_error("%s Connection error %d",
					conn->driver->name, -err);
		goto out;
	}

	err = conn->driver->push(fd, conn->adapter_idx, conn->target_idx,
					conn->ndef, conn->cb,
					conn->driver->user_data);

out:
	if (err < 0)
		conn->cb(conn->adapter_idx, conn->target_idx, err);

	g_free(conn->ndef->data);
	g_free(conn->ndef);
	g_free(conn);

	return FALSE;
}

static int p2p_bind(struct near_p2p_driver *driver, uint32_t adapter_idx,
							near_device_io_cb cb)
{
	int err, fd;
	struct p2p_data *server_data;
	GIOFunc g_func;

	DBG("");

	if (driver->sock_type == SOCK_DGRAM)
		g_func = p2p_client_event;
	else
		g_func = p2p_listener_event;

	if (driver->sock_type != SOCK_DGRAM &&
					driver->sock_type != SOCK_STREAM) {
		near_error("Undefined socket type for %s ", driver->name);
		return -EINVAL;
	}

	fd = socket(AF_NFC, driver->sock_type, NFC_SOCKPROTO_LLCP);
	if (fd < 0)
		return -errno;

	server_data = g_try_malloc0(sizeof(struct p2p_data));
	if (!server_data) {
		close(fd);
		return -ENOMEM;
	}

	server_data->driver = driver;
	server_data->adapter_idx = adapter_idx;
	server_data->fd = fd;
	server_data->cb = cb;

	err = __p2p_bind(server_data, g_func);
	if (err < 0) {
		g_free(server_data);
		return err;
	}

	server_list = g_list_append(server_list, server_data);

	return 0;
}

static int p2p_listen(uint32_t adapter_idx, near_device_io_cb cb)
{
	int err = -1, bind_err;
	GSList *list;

	for (list = driver_list; list; list = list->next) {
		struct near_p2p_driver *driver = list->data;

		bind_err = p2p_bind(driver, adapter_idx, cb);
		if (bind_err == 0) {
			err = 0;
		} else if (bind_err == -EPROTONOSUPPORT) {
			near_error("LLCP is not supported");
			return bind_err;
		}
	}

	return err;
}

static int p2p_connect(uint32_t adapter_idx, uint32_t target_idx,
			struct near_ndef_message *ndef,
			near_device_io_cb cb,  struct near_p2p_driver *driver)
{
	int fd, err = 0;
	struct timeval timeout;
	struct sockaddr_nfc_llcp addr;
	GIOChannel *channel;
	GIOCondition cond;
	struct p2p_connect *conn;

	DBG("");

	fd = socket(AF_NFC, SOCK_STREAM, NFC_SOCKPROTO_LLCP);
	if (fd < 0)
		return -errno;

	conn = g_try_malloc0(sizeof(struct p2p_connect));
	if (!conn) {
		close(fd);
		return -ENOMEM;
	}

	conn->driver = driver;
	conn->ndef = ndef;
	conn->cb = cb;
	conn->target_idx = target_idx;
	conn->adapter_idx = adapter_idx;

	channel = g_io_channel_unix_new(fd);
	g_io_channel_set_flags(channel, G_IO_FLAG_NONBLOCK, NULL);

	memset(&addr, 0, sizeof(struct sockaddr_nfc_llcp));
	addr.sa_family = AF_NFC;
	addr.dev_idx = adapter_idx;
	addr.target_idx = target_idx;
	addr.nfc_protocol = NFC_PROTO_NFC_DEP;
	addr.service_name_len = strlen(driver->service_name);
	strcpy(addr.service_name, driver->service_name);

	timeout.tv_sec = 8;
	timeout.tv_usec = 0;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
			sizeof(timeout)) < 0)
		near_error("Could not set the receive timeout\n");

	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
			sizeof(timeout)) < 0)
		near_error("Could not set the send timeout\n");

	err = connect(fd, (struct sockaddr *) &addr,
			sizeof(struct sockaddr_nfc_llcp));
	if (err < 0 && errno != EINPROGRESS) {
		near_error("Connect failed  %d", errno);
		g_free(conn);
		close(fd);

		return err;
	}

	cond = G_IO_OUT | G_IO_HUP |  G_IO_ERR | G_IO_NVAL;
	conn->watch = g_io_add_watch(channel, cond, p2p_connect_event, conn);
	g_io_channel_unref(channel);

	return fd;
}

static int p2p_push(uint32_t adapter_idx, uint32_t target_idx,
			struct near_ndef_message *ndef, char *service_name,
			near_device_io_cb cb)
{
	int fd;
	GSList *list;

	DBG("");

	for (list = driver_list; list; list = list->next) {
		struct near_p2p_driver *driver = list->data;

		if (strcmp(driver->service_name, service_name) != 0)
			continue;
		/*
		 * Because of Android's implementation, we have use SNEP for
		 * Handover. So, on Handover session, we try to connect to
		 * the handover service and fallback to SNEP on connect fail.
		 */
		fd = p2p_connect(adapter_idx, target_idx, ndef, cb, driver);
		if (fd > 0)
			return fd;

		if (driver->fallback_service_name)
			return  p2p_push(adapter_idx, target_idx, ndef,
					(char *) driver->fallback_service_name,
					cb);
		else
			return -1;
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
	struct near_p2p_driver *tmp_driver;
	GSList *list = NULL;

	DBG("driver %p name %s service %s", driver, driver->name,
			driver->service_name);

	for (list = driver_list; list; list = list->next) {
		tmp_driver = list->data;
		if (g_strcmp0(tmp_driver->service_name,
						driver->service_name) == 0) {
			near_error("%s already registered",
							driver->service_name);
			return -EALREADY;
		}
	}

	driver_list = g_slist_prepend(driver_list, driver);
	return 0;
}

void near_p2p_unregister(struct near_p2p_driver *driver)
{
	DBG("driver %p name %s", driver, driver->service_name);

	driver_list = g_slist_remove(driver_list, driver);
}

static int p2p_init(void)
{
	DBG("");

	phdc_init();
	npp_init();
	snep_init();
	snep_validation_init();
	llcp_validation_init();
	handover_init();

	return near_device_driver_register(&p2p_driver);
}

static void p2p_exit(void)
{
	DBG("");

	g_list_free_full(server_list, free_server_data);

	llcp_validation_exit();
	snep_exit();
	snep_validation_exit();
	npp_exit();
	phdc_exit();
	handover_exit();

	near_device_driver_unregister(&p2p_driver);
}

NEAR_PLUGIN_DEFINE(p2p, "NFC Forum peer to peer mode support", VERSION,
		NEAR_PLUGIN_PRIORITY_HIGH, p2p_init, p2p_exit)

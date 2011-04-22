/*
 *
 *  neard - Near Field Communication manager
 *
 *  Copyright 2007, 2008	Johannes Berg <johannes@sipsolutions.net>
 *  Copyright (C) 2011 Instituto Nokia de Tecnologia
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

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include <linux/nfc.h>

#include "near.h"

struct nlnfc_state {
	struct nl_sock *nl_sock;
	struct nl_cache *nl_cache;
	struct genl_family *nlnfc;
	int mcid;
};

static struct nlnfc_state *nfc_state;
static GIOChannel *netlink_channel = NULL;

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;

	DBG("");

	*ret = err->error;

	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	DBG("");

	*ret = 1;

	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	DBG("");

	*ret = 1;

	return NL_STOP;
}

static int nl_send_msg(struct nl_sock *sock, struct nl_msg *msg,
			int (*rx_handler)(struct nl_msg *, void *),
			void *data)
{
	struct nl_cb *cb;
	int err, done;

	DBG("");

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (cb == NULL)
		return -ENOMEM;

	err = nl_send_auto_complete(sock, msg);
	if (err < 0) {
		nl_cb_put(cb);
		near_error("%s", strerror(err));

		return err;
	}

	err = done = 0;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &done);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &done);

	if (rx_handler != NULL)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, rx_handler, data);

	while (err == 0 && done == 0)
		nl_recvmsgs(sock, cb);

	nl_cb_put(cb);

	return err;
}


static int get_devices_handler(struct nl_msg *n, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(n);
	struct nlattr *attrs[NFC_ATTR_MAX + 1];
	char *name;
	uint32_t idx, protocols;

	DBG("");

	genlmsg_parse(nlh, 0, attrs, NFC_ATTR_MAX, NULL);

	if (!attrs[NFC_ATTR_DEVICE_INDEX] || !attrs[NFC_ATTR_DEVICE_NAME]) {
		nl_perror(NLE_MISSING_ATTR, "NFC_CMD_GET_DEVICE");
		return NL_STOP;
	}

	idx = nla_get_u32(attrs[NFC_ATTR_DEVICE_INDEX]);
	name = nla_get_string(attrs[NFC_ATTR_DEVICE_NAME]);
	protocols = nla_get_u32(attrs[NFC_ATTR_PROTOCOLS]);

	__near_adapter_create(name, idx, protocols);

	return NL_SKIP;
}

int __near_netlink_get_adapters(void)
{
	struct nl_msg *msg;
	void *hdr;
	int err, family;

	DBG("");

	msg = nlmsg_alloc();
	if (msg == NULL)
		return -ENOMEM;

	family = genl_family_get_id(nfc_state->nlnfc);

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0,
			  NLM_F_DUMP, NFC_CMD_GET_DEVICE, NFC_GENL_VERSION);
	if (hdr == NULL) {
		err = -EINVAL;
		goto out;
	}

	err = nl_send_msg(nfc_state->nl_sock, msg, get_devices_handler, NULL);

out:
	nlmsg_free(msg);

	return err;
}

static int no_seq_check(struct nl_msg *n, void *arg)
{
	DBG("");

	return NL_OK;
}

static int nfc_netlink_event(struct nl_msg *n, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(n));

	DBG("event 0x%x", gnlh->cmd);

	switch (gnlh->cmd) {
	case NFC_EVENT_TARGETS_FOUND:
		DBG("Targets found");
		break;
	case NFC_EVENT_DEVICE_ADDED:
		DBG("Adapter added");
		break;
	case NFC_EVENT_DEVICE_REMOVED:
		DBG("Adapter removed");
		break;
	}

	return NL_SKIP;
}

static gboolean __nfc_netlink_event(GIOChannel *channel,
				GIOCondition cond, gpointer data)
{
	struct nl_cb *cb;
	struct nlnfc_state *state = data;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	cb = nl_cb_alloc(NL_CB_VERBOSE);
	if (cb == NULL)
		return TRUE;

	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nfc_netlink_event, data);

	nl_recvmsgs(state->nl_sock, cb);

	return TRUE;
}

static int nfc_event_listener(struct nlnfc_state *state)
{
	int sock;

	sock = nl_socket_get_fd(state->nl_sock);
	netlink_channel = g_io_channel_unix_new(sock);
	g_io_channel_set_close_on_unref(netlink_channel, TRUE);

	g_io_channel_set_encoding(netlink_channel, NULL, NULL);
	g_io_channel_set_buffered(netlink_channel, FALSE);

	g_io_add_watch(netlink_channel,
				G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
						__nfc_netlink_event, state);

	return 0;
}

struct handler_args {
	const char *group;
	int id;
};

static int family_handler(struct nl_msg *msg, void *arg)
{
	struct handler_args *grp = arg;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *mcgrp;
	int rem_mcgrp;

	DBG("");

	nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

        if (!tb[CTRL_ATTR_MCAST_GROUPS])
		return NL_SKIP;

	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp) {
		struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

		nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX,
			  nla_data(mcgrp), nla_len(mcgrp), NULL);

		if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
			continue;
		if (strncmp(nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
			    grp->group, nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
			continue;
		grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
		break;
	}
	
	return NL_SKIP;
}

static int nl_get_multicast_id(struct nl_sock *sock, const char *family,
				const char *group)
{
	struct nl_msg *msg;
	int err, ctrlid;
	struct handler_args grp = {
		.group = group,
		.id = -ENOENT,
	};

	DBG("");

	msg = nlmsg_alloc();
	if (msg == NULL)
		return -ENOMEM;

	ctrlid = genl_ctrl_resolve(sock, "nlctrl");

        genlmsg_put(msg, 0, 0, ctrlid, 0,
		    0, CTRL_CMD_GETFAMILY, 0);

	NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

	err = nl_send_msg(sock, msg, family_handler, &grp);
	if (err)
		goto nla_put_failure;

	DBG("multicast id %d", grp.id);

	err = grp.id;

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

int __near_netlink_init(void)
{
	int err;

	DBG("");

	nfc_state = g_try_malloc0(sizeof(struct nlnfc_state));
	if (nfc_state == NULL)
		return -ENOMEM;

	nfc_state->nl_sock = nl_socket_alloc();
	if (nfc_state->nl_sock == NULL) {
		near_error("Failed to allocate NFC netlink socket");
		err = -ENOMEM;
		goto state_free;
	}

	if (genl_connect(nfc_state->nl_sock)) {
		near_error("Failed to connect to generic netlink");
		err = -ENOLINK;
		goto handle_destroy;
	}

	if (genl_ctrl_alloc_cache(nfc_state->nl_sock, &nfc_state->nl_cache)) {
		near_error("Failed to allocate generic netlink cache");
		err = -ENOMEM;
		goto handle_destroy;
	}

	nfc_state->nlnfc = genl_ctrl_search_by_name(nfc_state->nl_cache, "nfc");
	if (nfc_state->nlnfc == NULL) {
		near_error("nfc not found");
		err = -ENOENT;
		goto cache_free;
	}

	nfc_state->mcid = nl_get_multicast_id(nfc_state->nl_sock, NFC_GENL_NAME,
						NFC_GENL_MCAST_EVENT_NAME);
	if (nfc_state->mcid <= 0) {
		near_error("Wrong mcast id %d", nfc_state->mcid);
		err = nfc_state->mcid;
		goto family_free;
	}

	err = nl_socket_add_membership(nfc_state->nl_sock, nfc_state->mcid);
	if (err) {
		near_error("Error adding nl socket to membership");
		goto family_free;
	}

	return nfc_event_listener(nfc_state);

family_free:
	genl_family_put(nfc_state->nlnfc);
cache_free:
	nl_cache_free(nfc_state->nl_cache);
handle_destroy:
	nl_socket_free(nfc_state->nl_sock);
state_free:
	g_free(nfc_state);

	near_error("netlink init failed");

	return err;
}

void __near_netlink_cleanup(void)
{
	g_io_channel_shutdown(netlink_channel, TRUE, NULL);
	g_io_channel_unref(netlink_channel);

	netlink_channel = NULL;

	genl_family_put(nfc_state->nlnfc);
	nl_cache_free(nfc_state->nl_cache);
	nl_socket_free(nfc_state->nl_sock);

	g_free(nfc_state);

	DBG("");
}


/*
 *
 *  seeld - Secure Element Manager
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include <sys/socket.h>
#include <linux/socket.h>

#include <glib.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include <near/log.h>
#include <near/plugin.h>
#include <near/nfc_copy.h>

#include "../manager.h"
#include "../driver.h"


#ifdef NEED_LIBNL_COMPAT
#define nl_sock nl_handle

static inline struct nl_handle *nl_socket_alloc(void)
{
	return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_sock *h)
{
	nl_handle_destroy(h);
}

#define NLE_MISSING_ATTR	14

static inline void __nl_perror(int error, const char *s)
{
	nl_perror(s);
}
#define nl_perror __nl_perror
#endif

struct nfc_transceive_context {
	void *context;
	uint8_t *apdu;
	size_t apdu_length;
	transceive_cb_t cb;
};

struct nlnfc_state {
	struct nl_sock *cmd_sock;
	struct nl_sock *event_sock;
	int nfc_id;
	int mcid;

	struct nfc_transceive_context *ctx;
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

static int no_seq_check(struct nl_msg *n, void *arg)
{
	DBG("");

	return NL_OK;
}

static enum seel_se_type nfc_se_type(uint32_t se_type)
{
	switch (se_type) {
	case NFC_SE_UICC:
		return SEEL_SE_UICC;
	case NFC_SE_EMBEDDED:
		return SEEL_SE_NFC;
	}

	return SEEL_SE_UNKNOWN;
}

static int nfc_netlink_event_se(struct genlmsghdr *gnlh, bool add)
{
	struct nlattr *attrs[NFC_ATTR_MAX + 1];
	uint32_t nfc_idx, se_idx;

	DBG("");

	nla_parse(attrs, NFC_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (attrs[NFC_ATTR_DEVICE_INDEX] == NULL) {
		near_error("Missing NFC controller index");
		return -ENODEV;
	}

	if (attrs[NFC_ATTR_SE_INDEX] == NULL) {
		near_error("Missing NFC SE index");
		return -ENODEV;
	}

	nfc_idx = nla_get_u32(attrs[NFC_ATTR_DEVICE_INDEX]);
	se_idx = nla_get_u32(attrs[NFC_ATTR_SE_INDEX]);

	DBG("NFC %d SE %d", nfc_idx, se_idx);

	if (add) {
		uint8_t se_type, seel_se_type;

		if (attrs[NFC_ATTR_SE_TYPE] == NULL) {
			near_error("Missing SE type attribute");
			return -EINVAL;
		}

		se_type = nla_get_u8(attrs[NFC_ATTR_SE_TYPE]);
		seel_se_type = nfc_se_type(se_type);
		DBG("NFC SE type %d %d", se_type, seel_se_type);

		return seel_manager_se_add(se_idx, nfc_idx, seel_se_type,
						SEEL_CONTROLLER_NFC);
	} else {
		return seel_manager_se_remove(se_idx, nfc_idx,
						SEEL_CONTROLLER_NFC);
	}
}

static int nfc_netlink_event_io(struct genlmsghdr *gnlh)
{
	struct nlattr *attrs[NFC_ATTR_MAX + 1];
	uint32_t nfc_idx, se_idx;
	uint8_t *apdu;
	size_t apdu_len;
	int err;

	DBG("");

	if (!nfc_state->ctx)
		return -EINVAL;

	nla_parse(attrs, NFC_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!attrs[NFC_ATTR_DEVICE_INDEX]) {
		near_error("Missing NFC controller index");
		err = -ENODEV;
		goto out;
	}

	if (!attrs[NFC_ATTR_SE_INDEX]) {
		near_error("Missing NFC SE index");
		err = -ENODEV;
		goto out;
	}

	if (!attrs[NFC_ATTR_SE_APDU]) {
		near_error("Missing SE APDU");
		err = -EIO;
		goto out;
	}

	nfc_idx = nla_get_u32(attrs[NFC_ATTR_DEVICE_INDEX]);
	se_idx = nla_get_u32(attrs[NFC_ATTR_SE_INDEX]);
	apdu_len = nla_len(attrs[NFC_ATTR_SE_APDU]);
	if (!apdu_len) {
		err = -EINVAL;
		goto out;
	}

	apdu = nla_data(attrs[NFC_ATTR_SE_APDU]);
	if (!apdu) {
		err = -EINVAL;
		goto out;
	}

	DBG("NFC %d SE %d APDU len %zd", nfc_idx, se_idx, apdu_len);

	nfc_state->ctx->cb(nfc_state->ctx->context, apdu, apdu_len, 0);

	err = 0;
out:
	if (err)
		nfc_state->ctx->cb(nfc_state->ctx->context, NULL, 0, err);

	g_free(nfc_state->ctx);
	nfc_state->ctx = NULL;

	return err;
}

static int nfc_netlink_event(struct nl_msg *n, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(n));

	DBG("event 0x%x", gnlh->cmd);

	switch (gnlh->cmd) {
	case NFC_EVENT_SE_ADDED:
		DBG("SE added");
		nfc_netlink_event_se(gnlh, true);
		break;

	case NFC_EVENT_SE_REMOVED:
		DBG("SE removed");
		nfc_netlink_event_se(gnlh, false);
		break;

	case NFC_CMD_SE_IO:
		DBG("SE IO");
		nfc_netlink_event_io(gnlh);
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

	nl_recvmsgs(state->event_sock, cb);

	nl_cb_put(cb);

	return TRUE;
}

static int nfc_event_listener(struct nlnfc_state *state)
{
	int sock;

	sock = nl_socket_get_fd(state->event_sock);
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

	genlmsg_put(msg, 0, 0, ctrlid, 0, 0, CTRL_CMD_GETFAMILY, 0);

	err = -EMSGSIZE;

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

static int nfc_toggle_se(uint8_t ctrl_idx, uint32_t se_idx, bool enable)
{
	struct nl_msg *msg;
	void *hdr;
	int err;
	uint8_t cmd;

	DBG("");

	msg = nlmsg_alloc();
	if (msg == NULL)
		return -ENOMEM;

	if (enable == TRUE)
		cmd = NFC_CMD_ENABLE_SE;
	else
		cmd = NFC_CMD_DISABLE_SE;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			NLM_F_REQUEST, cmd, NFC_GENL_VERSION);
	if (hdr == NULL) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	err = -EMSGSIZE;

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, ctrl_idx);
	NLA_PUT_U32(msg, NFC_ATTR_SE_INDEX, se_idx);

	err = nl_send_msg(nfc_state->cmd_sock, msg, NULL, NULL);

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

static int get_ses_handler(struct nl_msg *n, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(n);
	struct nlattr *attrs[NFC_ATTR_MAX + 1];
	uint32_t nfc_idx, se_idx;
	uint8_t se_type, seel_se_type;

	DBG("");

	genlmsg_parse(nlh, 0, attrs, NFC_ATTR_MAX, NULL);

	if (attrs[NFC_ATTR_DEVICE_INDEX] == NULL ||
	    attrs[NFC_ATTR_SE_INDEX] == NULL ||
	    attrs[NFC_ATTR_SE_TYPE] == NULL) {
		nl_perror(NLE_MISSING_ATTR, "NFC_CMD_GET_SE");
		return NL_STOP;
	}

	nfc_idx = nla_get_u32(attrs[NFC_ATTR_DEVICE_INDEX]);
	se_idx = nla_get_u32(attrs[NFC_ATTR_SE_INDEX]);
	se_type = nla_get_u8(attrs[NFC_ATTR_SE_TYPE]);

	seel_se_type = nfc_se_type(se_type);
	DBG("NFC SE type %d %d", se_type, seel_se_type);

	seel_manager_se_add(se_idx, nfc_idx, seel_se_type,
						SEEL_CONTROLLER_NFC);

	return NL_SKIP;
}

static int nfc_get_ses(void)
{
	struct nl_msg *msg;
	void *hdr;
	int err;

	DBG("");

	if (nfc_state == NULL || nfc_state->nfc_id < 0)
		return -ENODEV;

	msg = nlmsg_alloc();
	if (msg == NULL)
		return -ENOMEM;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			  NLM_F_DUMP, NFC_CMD_GET_SE, NFC_GENL_VERSION);
	if (hdr == NULL) {
		err = -EINVAL;
		goto out;
	}

	err = nl_send_msg(nfc_state->cmd_sock, msg, get_ses_handler, NULL);

out:
	nlmsg_free(msg);

	return err;
}

static int nfc_enable_se(uint8_t ctrl_idx, uint32_t se_idx)
{
	return nfc_toggle_se(ctrl_idx, se_idx, true);
}

static int nfc_disable_se(uint8_t ctrl_idx, uint32_t se_idx)
{
	return nfc_toggle_se(ctrl_idx, se_idx, false);
}

static struct seel_ctrl_driver nfc_ctrl_driver = {
	.type = SEEL_CONTROLLER_NFC,
	.enable_se = nfc_enable_se,
	.disable_se = nfc_disable_se,
};

static int nfc_transceive(uint8_t ctrl_idx, uint32_t se_idx,
			  uint8_t *apdu, size_t apdu_length,
			  transceive_cb_t cb, void *context)
{
	struct nl_msg *msg;
	void *hdr;
	int err;

	DBG("%zd APDU %p", apdu_length, apdu);

	if (nfc_state->ctx)
		return -EALREADY;

	nfc_state->ctx = g_try_malloc0(sizeof(struct nfc_transceive_context));
	if (!nfc_state->ctx) {
		cb(context, NULL, 0, -ENOMEM);

		return -ENOMEM;
	}

	nfc_state->ctx->context = context;
	nfc_state->ctx->cb = cb;

	msg = nlmsg_alloc();
	if (msg == NULL)
		return -ENOMEM;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			NLM_F_REQUEST, NFC_CMD_SE_IO, NFC_GENL_VERSION);
	if (hdr == NULL) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	err = -EMSGSIZE;

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, ctrl_idx);
	NLA_PUT_U32(msg, NFC_ATTR_SE_INDEX, se_idx);
	NLA_PUT(msg, NFC_ATTR_SE_APDU, apdu_length, apdu);

	err = nl_send_msg(nfc_state->cmd_sock, msg, NULL, NULL);

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

static struct seel_io_driver nfc_io_driver = {
	.type = SEEL_SE_NFC,
	.transceive = nfc_transceive,
};

static int nfc_init(void)
{
	int err;

	DBG("");

	nfc_state = g_try_malloc0(sizeof(struct nlnfc_state));
	if (nfc_state == NULL)
		return -ENOMEM;

	nfc_state->cmd_sock = nl_socket_alloc();
	if (nfc_state->cmd_sock == NULL) {
		near_error("Failed to allocate NFC command netlink socket");
		err = -ENOMEM;
		goto state_free;
	}

	nfc_state->event_sock = nl_socket_alloc();
	if (nfc_state->event_sock == NULL) {
		near_error("Failed to allocate NFC event netlink socket");
		err = -ENOMEM;
		goto handle_cmd_destroy;
	}

	if (genl_connect(nfc_state->cmd_sock)) {
		near_error("Failed to connect to generic netlink");
		err = -ENOLINK;
		goto handle_event_destroy;
	}

	if (genl_connect(nfc_state->event_sock)) {
		near_error("Failed to connect to generic netlink");
		err = -ENOLINK;
		goto handle_event_destroy;
	}

	nfc_state->nfc_id = genl_ctrl_resolve(nfc_state->cmd_sock, "nfc");
	if (nfc_state->nfc_id < 0) {
		near_error("Unable to find NFC netlink family");
		err = -ENOENT;
		goto handle_event_destroy;
	}

	nfc_state->mcid = nl_get_multicast_id(nfc_state->cmd_sock, NFC_GENL_NAME,
						NFC_GENL_MCAST_EVENT_NAME);
	if (nfc_state->mcid <= 0) {
		near_error("Wrong mcast id %d", nfc_state->mcid);
		err = nfc_state->mcid;
		goto handle_event_destroy;
	}

	err = nl_socket_add_membership(nfc_state->event_sock, nfc_state->mcid);
	if (err) {
		near_error("Error adding nl event socket to membership");
		goto handle_event_destroy;
	}

	err = nfc_event_listener(nfc_state);
	if (err)  {
		near_error("Failed to start NFC event listener");
		goto netlink_channel_destroy;
	}

	err = seel_ctrl_driver_register(&nfc_ctrl_driver);
	if (err)  {
		near_error("Could not register NFC ctrl driver");
		goto netlink_channel_destroy;
	}

	err = seel_io_driver_register(&nfc_io_driver);
	if (err)  {
		near_error("Could not register NFC IO driver");
		goto unregister_ctrl_driver;
	}

	return	nfc_get_ses();

unregister_ctrl_driver:
	seel_ctrl_driver_unregister(&nfc_ctrl_driver);

netlink_channel_destroy:
	g_io_channel_shutdown(netlink_channel, TRUE, NULL);
	g_io_channel_unref(netlink_channel);

	netlink_channel = NULL;

handle_event_destroy:
	nl_socket_free(nfc_state->event_sock);

handle_cmd_destroy:
	nl_socket_free(nfc_state->cmd_sock);

state_free:
	g_free(nfc_state);

	nfc_state = NULL;

	near_error("netlink init failed");

	return err;
}

static void nfc_exit(void)
{
	seel_ctrl_driver_unregister(&nfc_ctrl_driver);
	seel_io_driver_unregister(&nfc_io_driver);

	if (netlink_channel != NULL) {
		g_io_channel_shutdown(netlink_channel, TRUE, NULL);
		g_io_channel_unref(netlink_channel);

		netlink_channel = NULL;
	}

	if (nfc_state == NULL)
		return;

	nl_socket_free(nfc_state->cmd_sock);
	nl_socket_free(nfc_state->event_sock);

	g_free(nfc_state);

	DBG("");
}

NEAR_PLUGIN_DEFINE(nfc, "SE NFC support", VERSION,
			NEAR_PLUGIN_PRIORITY_HIGH, nfc_init, nfc_exit)

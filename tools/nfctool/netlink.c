/*
 *
 *  Near Field Communication nfctool
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

#include <errno.h>
#include <sys/socket.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include <glib.h>

#include <near/nfc_copy.h>

#include "nfctool.h"
#include "netlink.h"
#include "adapter.h"

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

struct handler_args {
	const char *group;
	int id;
};

struct nlnfc_state {
	struct nl_sock *cmd_sock;
	struct nl_sock *event_sock;
	int nfc_id;
	int mcid;
};

static struct nlnfc_state *nfc_state = NULL;

static GIOChannel *nl_gio_channel = NULL;

static GHashTable *handlers = NULL;

static int nl_error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;

	DBG("");

	*ret = err->error;

	return NL_STOP;
}

static int nl_finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	DBG("");

	*ret = 1;

	return NL_SKIP;
}

static int nl_ack_handler(struct nl_msg *msg, void *arg)
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
	if (!cb)
		return -ENOMEM;

	err = nl_send_auto_complete(sock, msg);
	if (err < 0) {
		nl_cb_put(cb);
		print_error("%s", strerror(err));

		return err;
	}

	err = done = 0;

	nl_cb_err(cb, NL_CB_CUSTOM, nl_error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nl_finish_handler, &done);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, nl_ack_handler, &done);

	if (rx_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, rx_handler, data);

	while (err == 0 && done == 0)
		nl_recvmsgs(sock, cb);

	nl_cb_put(cb);

	return err;
}

static int nl_family_handler(struct nl_msg *msg, void *arg)
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
			    grp->group,
			    nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
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
	int err = 0, ctrlid;
	struct handler_args grp = {
		.group = group,
		.id = -ENOENT,
	};

	DBG("");

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	ctrlid = genl_ctrl_resolve(sock, "nlctrl");

	genlmsg_put(msg, 0, 0, ctrlid, 0,
		    0, CTRL_CMD_GETFAMILY, 0);

	NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

	err = nl_send_msg(sock, msg, nl_family_handler, &grp);
	if (err)
		goto nla_put_failure;

	DBG("multicast id %d", grp.id);

	err = grp.id;

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

static int nl_no_seq_check_cb(struct nl_msg *n, void *arg)
{
	DBG("");

	return NL_OK;
}

static int nl_get_params_handler(struct nl_msg *n, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(n);
	struct nlattr *attrs[NFC_ATTR_MAX + 1];
	struct nfc_adapter *adapter = (struct nfc_adapter *)arg;
	guint32 idx;

	DBG("");

	genlmsg_parse(nlh, 0, attrs, NFC_ATTR_MAX, NULL);

	if (!attrs[NFC_ATTR_DEVICE_INDEX]) {
		nl_perror(NLE_MISSING_ATTR, "NFC_CMD_GET_PARAMS");
		return NL_STOP;
	}

	idx = nla_get_u32(attrs[NFC_ATTR_DEVICE_INDEX]);
	if (idx != adapter->idx) {
		nl_perror(NLE_MISSING_ATTR, "NFC_CMD_GET_PARAMS");
		return NL_STOP;
	}

	adapter->param_lto = nla_get_u8(attrs[NFC_ATTR_LLC_PARAM_LTO]);
	adapter->param_rw = nla_get_u8(attrs[NFC_ATTR_LLC_PARAM_RW]);
	adapter->param_miux = nla_get_u16(attrs[NFC_ATTR_LLC_PARAM_MIUX]);

	return NL_STOP;
}

int nl_get_params(struct nfc_adapter *adapter)
{
	struct nl_msg *msg;
	void *hdr;
	int err = 0;

	DBG("");

	if (!nfc_state || nfc_state->nfc_id < 0)
		return -ENODEV;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			  0, NFC_CMD_LLC_GET_PARAMS, NFC_GENL_VERSION);
	if (!hdr) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);

	err = nl_send_msg(nfc_state->cmd_sock, msg, nl_get_params_handler,
			  adapter);

	DBG("nl_send_msg returns %d", err);

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

int nl_set_params(struct nfc_adapter *adapter, gint32 lto, gint32 rw,
		  gint32 miux)
{
	struct nl_msg *msg;
	void *hdr;
	int err = 0;

	DBG("");

	if (lto < 0 && rw < 0 && miux < 0)
		return -EINVAL;

	if (!nfc_state || nfc_state->nfc_id < 0)
		return -ENODEV;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			  0, NFC_CMD_LLC_SET_PARAMS, NFC_GENL_VERSION);
	if (!hdr) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);
	if (lto >= 0)
		NLA_PUT_U8(msg, NFC_ATTR_LLC_PARAM_LTO, (guint8)lto);
	if (rw >= 0)
		NLA_PUT_U8(msg, NFC_ATTR_LLC_PARAM_RW, (guint8)rw);
	if (miux >= 0)
		NLA_PUT_U16(msg, NFC_ATTR_LLC_PARAM_MIUX, (guint16)miux);

	err = nl_send_msg(nfc_state->cmd_sock, msg, NULL, NULL);

	DBG("nl_send_msg returns %d", err);

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

static int nl_get_targets_handler(struct nl_msg *n, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(n);
	struct nlattr *attrs[NFC_ATTR_MAX + 1];
	guint32 target_idx, target_type, protocols;
	struct nfc_adapter *adapter;

	DBG("");

	adapter = (struct nfc_adapter *)arg;

	genlmsg_parse(nlh, 0, attrs, NFC_ATTR_MAX, NULL);

	target_idx = nla_get_u32(attrs[NFC_ATTR_TARGET_INDEX]);
	protocols = nla_get_u32(attrs[NFC_ATTR_PROTOCOLS]);

	if (protocols & NFC_PROTO_NFC_DEP_MASK)
		target_type = TARGET_TYPE_DEVICE;
	else
		target_type = TARGET_TYPE_TAG;

	adapter_add_target(adapter, target_type, target_idx);

	return 0;
}

int nl_get_targets(struct nfc_adapter *adapter)
{
	struct nl_msg *msg;
	void *hdr;
	int err;

	DBG("");

	if (!nfc_state || nfc_state->nfc_id < 0)
		return -ENODEV;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			  NLM_F_DUMP, NFC_CMD_GET_TARGET, NFC_GENL_VERSION);
	if (!hdr) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	err = -EMSGSIZE;

	g_slist_free(adapter->tags);
	adapter->tags = NULL;

	g_slist_free(adapter->devices);
	adapter->devices = NULL;

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);

	err = nl_send_msg(nfc_state->cmd_sock, msg,
			  nl_get_targets_handler, adapter);

	DBG("nl_send_msg returns %d", err);

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

static int nl_get_devices_handler(struct nl_msg *n, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(n);
	struct nlattr *attrs[NFC_ATTR_MAX + 1];
	guint32 idx, protocols = 0;
	guint8 powered = 0;
	guint8 rf_mode = NFC_RF_NONE;

	DBG("");

	genlmsg_parse(nlh, 0, attrs, NFC_ATTR_MAX, NULL);

	if (!attrs[NFC_ATTR_DEVICE_INDEX]) {
		nl_perror(NLE_MISSING_ATTR, "NFC_CMD_GET_DEVICE");
		return NL_STOP;
	}

	idx = nla_get_u32(attrs[NFC_ATTR_DEVICE_INDEX]);

	if (attrs[NFC_ATTR_PROTOCOLS])
		protocols = nla_get_u32(attrs[NFC_ATTR_PROTOCOLS]);

	if (attrs[NFC_ATTR_RF_MODE])
		rf_mode = nla_get_u8(attrs[NFC_ATTR_RF_MODE]);

	if (attrs[NFC_ATTR_DEVICE_POWERED])
		powered = nla_get_u8(attrs[NFC_ATTR_DEVICE_POWERED]);

	adapter_add(idx, protocols, powered, rf_mode);

	return NL_SKIP;
}

int nl_get_devices(void)
{
	struct nl_msg *msg;
	void *hdr;
	int err;

	DBG("");

	if (!nfc_state || nfc_state->nfc_id < 0)
		return -ENODEV;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			  NLM_F_DUMP, NFC_CMD_GET_DEVICE, NFC_GENL_VERSION);
	if (!hdr) {
		err = -EINVAL;
		goto out;
	}

	err = nl_send_msg(nfc_state->cmd_sock, msg, nl_get_devices_handler,
			  NULL);

	DBG("nl_send_msg returns %d", err);

out:
	nlmsg_free(msg);

	return err;
}

int nl_send_dep_link_up(guint32 idx, guint32 target_idx)
{
	struct nl_msg *msg;
	void *hdr;
	int err;

	DBG("");

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			  NLM_F_REQUEST, NFC_CMD_DEP_LINK_UP, NFC_GENL_VERSION);
	if (!hdr) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	err = -EMSGSIZE;

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, idx);
	NLA_PUT_U32(msg, NFC_ATTR_TARGET_INDEX, target_idx);
	NLA_PUT_U8(msg, NFC_ATTR_COMM_MODE, NFC_COMM_ACTIVE);
	NLA_PUT_U8(msg, NFC_ATTR_RF_MODE, NFC_RF_INITIATOR);

	err = nl_send_msg(nfc_state->cmd_sock, msg, NULL, NULL);

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

int nl_start_poll(struct nfc_adapter *adapter, guint8 mode)
{
	struct nl_msg *msg;
	void *hdr;
	int err;
	guint32 im_protocols = 0;
	guint32 tm_protocols = 0;

	if ((mode & POLLING_MODE_INITIATOR) == POLLING_MODE_INITIATOR)
		im_protocols = adapter->protocols;

	if ((mode & POLLING_MODE_TARGET) == POLLING_MODE_TARGET)
		tm_protocols = adapter->protocols;

	DBG("IM protos 0x%x TM protos 0x%x", im_protocols, tm_protocols);

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			  NLM_F_REQUEST, NFC_CMD_START_POLL, NFC_GENL_VERSION);
	if (!hdr) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	err = -EMSGSIZE;

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);
	if (im_protocols != 0) {
		NLA_PUT_U32(msg, NFC_ATTR_IM_PROTOCOLS, im_protocols);
		NLA_PUT_U32(msg, NFC_ATTR_PROTOCOLS, im_protocols);
	}
	if (tm_protocols != 0)
		NLA_PUT_U32(msg, NFC_ATTR_TM_PROTOCOLS, tm_protocols);

	err = nl_send_msg(nfc_state->cmd_sock, msg, NULL, NULL);

	if (err == 0)
		adapter->polling = TRUE;

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

int nl_set_powered(struct nfc_adapter *adapter, bool powered)
{
	struct nl_msg *msg;
	void *hdr;
	int err;
	uint8_t cmd;

	DBG("");

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	if (powered)
		cmd = NFC_CMD_DEV_UP;
	else
		cmd = NFC_CMD_DEV_DOWN;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			NLM_F_REQUEST, cmd, NFC_GENL_VERSION);
	if (!hdr) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	err = -EMSGSIZE;

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);

	err = nl_send_msg(nfc_state->cmd_sock, msg, NULL, NULL);

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

int nl_send_sdreq(struct nfc_adapter *adapter, GSList *uris)
{
	struct nl_msg *msg;
	void *hdr;
	GSList *uri;
	struct nlattr *sdp_attr, *uri_attr;
	int err = 0, i;

	DBG("");

	if (!nfc_state || nfc_state->nfc_id < 0)
		return -ENODEV;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			  NLM_F_REQUEST, NFC_CMD_LLC_SDREQ, NFC_GENL_VERSION);
	if (!hdr) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);

	sdp_attr = nla_nest_start(msg, NFC_ATTR_LLC_SDP);
	if (!sdp_attr) {
		err = -ENOMEM;
		goto nla_put_failure;
	}

	i = 1;
	uri = uris;
	while (uri) {
		uri_attr = nla_nest_start(msg, i);

		if (!uri_attr) {
			err = -ENOMEM;
			goto nla_put_failure;
		}

		NLA_PUT_STRING(msg, NFC_SDP_ATTR_URI, uri->data);

		nla_nest_end(msg, uri_attr);

		uri = g_slist_next(uri);

		i++;
	}

	nla_nest_end(msg, sdp_attr);

	err = nl_send_msg(nfc_state->event_sock, msg, NULL, NULL);

	DBG("nl_send_msg returns %d", err);

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

static int nl_nfc_send_sdres_event(guint32 idx, struct nlattr *sdres_attr,
							nfc_event_cb_t handler)
{
	GSList *sdres_list = NULL;
	struct nfc_snl *sdres;
	struct nlattr *attr;
	struct nlattr *sdp_attrs[NFC_SDP_ATTR_MAX + 1];
	int rem, err = 0;
	size_t uri_len;

	nla_for_each_nested(attr, sdres_attr, rem) {
		err = nla_parse_nested(sdp_attrs, NFC_SDP_ATTR_MAX,
					attr, NULL);

		if (err != 0) {
			DBG("nla_parse_nested returned %d\n", err);
			continue;
		}

		if (!sdp_attrs[NFC_SDP_ATTR_URI] ||
		    !sdp_attrs[NFC_SDP_ATTR_SAP]) {
			print_error("Missing attribute in reply");
			continue;
		}

		uri_len = nla_strlcpy(NULL, sdp_attrs[NFC_SDP_ATTR_URI], 0);

		uri_len++;

		sdres = nfctool_snl_alloc(uri_len);

		nla_strlcpy(sdres->uri, sdp_attrs[NFC_SDP_ATTR_URI], uri_len);

		sdres->sap = nla_get_u8(sdp_attrs[NFC_SDP_ATTR_SAP]);

		DBG("URI: %s, sap: %d\n", sdres->uri, sdres->sap);

		sdres_list = g_slist_append(sdres_list, sdres);
	}

	handler(NFC_EVENT_LLC_SDRES, idx, sdres_list);

	g_slist_free_full(sdres_list, (GDestroyNotify)nfctool_sdres_free);

	return err;
}

int nl_fw_download(struct nfc_adapter *adapter, gchar *fw_filename)
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

	err = -EINVAL;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_state->nfc_id, 0,
			  NLM_F_REQUEST, NFC_CMD_FW_DOWNLOAD, NFC_GENL_VERSION);
	if (hdr == NULL)
		goto nla_put_failure;

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);

	NLA_PUT_STRING(msg, NFC_ATTR_FIRMWARE_NAME, fw_filename);

	err = nl_send_msg(nfc_state->event_sock, msg, NULL, NULL);

nla_put_failure:
	nlmsg_free(msg);

	return err;
}

static int nl_nfc_event_cb(struct nl_msg *n, void *arg)
{
	guint32 idx = INVALID_ADAPTER_IDX;
	struct nlattr *attr[NFC_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(n));
	guint32 cmd = gnlh->cmd;
	nfc_event_cb_t cb = NULL;

	DBG("Received cmd %d", gnlh->cmd);

	nla_parse(attr, NFC_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		genlmsg_attrlen(gnlh, 0), NULL);

	if (attr[NFC_ATTR_DEVICE_INDEX])
		idx = nla_get_u32(attr[NFC_ATTR_DEVICE_INDEX]);

	if (handlers)
		cb = g_hash_table_lookup(handlers, GINT_TO_POINTER(cmd));

	if (!cb)
		return NL_SKIP;

	switch (cmd) {
	case NFC_EVENT_LLC_SDRES:
		DBG("Received NFC_EVENT_LLC_SDRES\n");
		nl_nfc_send_sdres_event(idx, attr[NFC_ATTR_LLC_SDP], cb);
		break;

	default:
		cb(gnlh->cmd, idx, &attr);
		break;
	}

	return NL_SKIP;
}

static gboolean nl_gio_handler(GIOChannel *channel,
			       GIOCondition cond, gpointer data)
{
	struct nl_cb *cb;
	struct nlnfc_state *state = data;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	cb = nl_cb_alloc(NL_CB_VERBOSE);
	if (!cb)
		return TRUE;

	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl_no_seq_check_cb, NULL);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, nl_nfc_event_cb, data);

	nl_recvmsgs(state->event_sock, cb);

	nl_cb_put(cb);

	return TRUE;
}

void nl_add_event_handler(guint8 cmd, nfc_event_cb_t cb)
{
	guint32 c = cmd;

	if (handlers)
		g_hash_table_replace(handlers, GINT_TO_POINTER(c), cb);
}

void nl_cleanup(void)
{
	if (nl_gio_channel) {
		g_io_channel_shutdown(nl_gio_channel, TRUE, NULL);
		g_io_channel_unref(nl_gio_channel);
		nl_gio_channel = NULL;
	}

	if (nfc_state) {
		if (nfc_state->cmd_sock)
			nl_socket_free(nfc_state->cmd_sock);

		if (nfc_state->event_sock)
			nl_socket_free(nfc_state->event_sock);

		g_free(nfc_state);
		nfc_state = NULL;
	}

	if (handlers)
		g_hash_table_destroy(handlers);
}

int nl_init(void)
{
	int err;
	int fd;

	DBG("");

	nfc_state = g_malloc0(sizeof(struct nlnfc_state));

	nfc_state->cmd_sock = nl_socket_alloc();
	if (!nfc_state->cmd_sock) {
		print_error("Failed to allocate NFC netlink socket");
		err = -ENOMEM;
		goto exit_err;
	}

	nfc_state->event_sock = nl_socket_alloc();
	if (!nfc_state->event_sock) {
		print_error("Failed to allocate NFC netlink socket");
		err = -ENOMEM;
		goto exit_err;
	}

	if (genl_connect(nfc_state->cmd_sock)) {
		print_error("Failed to connect to generic netlink");
		err = -ENOLINK;
		goto exit_err;
	}

	if (genl_connect(nfc_state->event_sock)) {
		print_error("Failed to connect to generic netlink");
		err = -ENOLINK;
		goto exit_err;
	}

	nfc_state->nfc_id = genl_ctrl_resolve(nfc_state->cmd_sock, "nfc");
	if (nfc_state->nfc_id < 0) {
		print_error("Unable to find NFC netlink family");
		err = -ENOENT;
		goto exit_err;
	}

	nfc_state->mcid = nl_get_multicast_id(nfc_state->cmd_sock,
					      NFC_GENL_NAME,
					      NFC_GENL_MCAST_EVENT_NAME);
	if (nfc_state->mcid <= 0) {
		print_error("Wrong mcast id %d", nfc_state->mcid);
		err = nfc_state->mcid;
		goto exit_err;
	}

	err = nl_socket_add_membership(nfc_state->event_sock, nfc_state->mcid);
	if (err) {
		print_error("Error adding nl socket to membership");
		goto exit_err;
	}

	handlers = g_hash_table_new(g_direct_hash, g_direct_equal);

	fd = nl_socket_get_fd(nfc_state->event_sock);
	nl_gio_channel = g_io_channel_unix_new(fd);
	g_io_channel_set_close_on_unref(nl_gio_channel, TRUE);

	g_io_channel_set_encoding(nl_gio_channel, NULL, NULL);
	g_io_channel_set_buffered(nl_gio_channel, FALSE);

	g_io_add_watch(nl_gio_channel,
		       G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
		       nl_gio_handler, nfc_state);

	return 0;

exit_err:
	nl_cleanup();

	print_error("netlink init failed");

	return err;
}

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <errno.h>
#include <glib.h>

#include <near/nfc_copy.h>

#include "nfctool.h"
#include "llcp-decode.h"
#include "sniffer.h"

#define PCAP_MAGIC_NUMBER 0xa1b2c3d4
#define PCAP_MAJOR_VER 2
#define PCAP_MINOR_VER 4
#define PCAP_SNAP_LEN 0xFFFF
#define PCAP_NETWORK 0xF5

#define BUFFER_LEN 0x8FF

static GIOChannel *gio_channel = NULL;
guint watch = 0;

static FILE *pcap_file = NULL;
static guint8 *buffer;

static int pcap_file_write_packet(guint8 *data, guint32 len,
				  struct timeval *timestamp)
{
	guint32 val32;
	guint32 incl_len;

	if (!pcap_file || !data || len == 0)
		return -EINVAL;

	val32 = timestamp->tv_sec;
	if (fwrite(&val32, 4, 1, pcap_file) < 1)
		goto exit_err;

	val32 = timestamp->tv_usec;
	if (fwrite(&val32, 4, 1, pcap_file) < 1)
		goto exit_err;

	if (len > PCAP_SNAP_LEN)
		incl_len = PCAP_SNAP_LEN;
	else
		incl_len = len;

	if (fwrite(&incl_len, 4, 1, pcap_file) < 1)
		goto exit_err;

	if (fwrite(&len, 4, 1, pcap_file) < 1)
		goto exit_err;

	if (fwrite(data, 1, incl_len, pcap_file) < incl_len)
		goto exit_err;

	return 0;

exit_err:
	return -errno;
}

static int pcap_file_init(char *pcap_filename)
{
	int err = 0;
	guint16 value16;
	guint32 value32;

	pcap_file = fopen(pcap_filename, "w");

	if (!pcap_file) {
		err = errno;
		print_error("Can't open file %s: %s",
				pcap_filename, strerror(err));
		return -err;
	}

	value32 = PCAP_MAGIC_NUMBER;
	if (fwrite(&value32, 4, 1, pcap_file) < 1)
		goto exit_err;

	value16 = PCAP_MAJOR_VER;
	if (fwrite(&value16, 2, 1, pcap_file) < 1)
		goto exit_err;

	value16 = PCAP_MINOR_VER;
	if (fwrite(&value16, 2, 1, pcap_file) < 1)
		goto exit_err;

	value32 = 0;
	if (fwrite(&value32, 4, 1, pcap_file) < 1)
		goto exit_err;
	if (fwrite(&value32, 4, 1, pcap_file) < 1)
		goto exit_err;

	value32 = PCAP_SNAP_LEN;
	if (fwrite(&value32, 4, 1, pcap_file) < 1)
		goto exit_err;

	value32 = PCAP_NETWORK;
	if (fwrite(&value32, 4, 1, pcap_file) < 1)
		goto exit_err;

	return 0;

exit_err:
	return -errno;
}

static void pcap_file_cleanup(void)
{
	if (pcap_file) {
		fclose(pcap_file);
		pcap_file = NULL;
	}
}


#define LINE_SIZE (10 + 3 * 16 + 2 + 18 + 1)
#define HUMAN_READABLE_OFFSET 55

/*
 * Dumps data in Hex+ASCII format as:
 *
 * 00000000: 01 01 43 20 30 70 72 6F 70 65 72 74 69 65 73 20  |..C 0properties |
 *
 */
void sniffer_print_hexdump(FILE *file, guint8 *data, guint32 len,
			   guint8 indent, bool print_len)
{
	guint8 digits;
	guint32 offset;
	guint32 total;
	guint32 output_len;
	gchar line[LINE_SIZE];
	gchar *hexa = NULL, *human = NULL;
	guint8 offset_len;
	guint8 human_offset;
	gchar *fmt;

	if (len == 0)
		return;

	offset = 0;
	digits = 0;
	total = 0;

	if (opts.snap_len && len > opts.snap_len)
		output_len = opts.snap_len;
	else
		output_len = len;

	if (output_len > 0xFFFF) {
		offset_len = 8;
		human_offset = HUMAN_READABLE_OFFSET + 4;
		fmt = "%08X: ";
	} else {
		offset_len = 4;
		human_offset = HUMAN_READABLE_OFFSET;
		fmt = "%04X: ";
	}

	if (print_len) {
		if (indent)
			fprintf(file, "%*c", indent, ' ');

		fprintf(file, "Total length: %u bytes\n", len);
	}

	while (total < output_len) {
		if (digits == 0) {
			memset(line, ' ', human_offset);

			sprintf(line, fmt, offset);

			offset += 16;

			hexa = line + offset_len + 2;

			human = line + human_offset;
			*human++ = '|';
		}

		sprintf(hexa, "%02hhX ", data[total]);
		*human++ = isprint((int)data[total]) ? (char)data[total] : '.';
		hexa += 3;

		if (++digits >= 16) {
			*hexa = ' ';
			strcpy(human, "|");
			if (indent)
				fprintf(file, "%*c", indent, ' ');
			fprintf(file, "%s\n", line);

			digits = 0;
		}

		total++;
	}

	if ((output_len & 0xF) != 0) {
		*hexa = ' ';
		strcpy(human, "|");
		if (indent)
			fprintf(file, "%*c", indent, ' ');
		fprintf(file, "%s\n", line);
	}

	if (output_len != len) {
		if (indent)
			fprintf(file, "%*c", indent, ' ');
		fprintf(file, "--- truncated ---\n");
	}
}

static gboolean gio_handler(GIOChannel *channel,
				 GIOCondition cond, gpointer data)
{
	struct msghdr msg;
	struct iovec iov;
	int sock;
	int len;
	guint8 ctrl[CMSG_SPACE(sizeof(struct timeval))];
	struct cmsghdr *cmsg;
	struct timeval msg_timestamp;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		print_error("Sniffer IO error 0x%x\n", cond);

		if (watch > 0)
			g_source_remove(watch);
		watch = 0;
		gio_channel = NULL;

		return FALSE;
	}

	sock = g_io_channel_unix_get_fd(channel);

	memset(&msg, 0, sizeof(struct msghdr));

	msg.msg_control = &ctrl;
	msg.msg_controllen = sizeof(ctrl);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = buffer;
	iov.iov_len = BUFFER_LEN;

	len = recvmsg(sock, &msg, 0);
	if (len < 0) {
		print_error("recv: %s", strerror(errno));
		return FALSE;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg && cmsg->cmsg_type == SCM_TIMESTAMP)
		memcpy(&msg_timestamp, CMSG_DATA(cmsg), sizeof(struct timeval));
	else
		gettimeofday(&msg_timestamp, NULL);

	llcp_print_pdu(buffer, len, &msg_timestamp);

	pcap_file_write_packet(buffer, len, &msg_timestamp);

	return TRUE;
}

void sniffer_cleanup(void)
{
	DBG("gio_channel: %p", gio_channel);

	if (gio_channel) {
		g_io_channel_shutdown(gio_channel, TRUE, NULL);
		g_io_channel_unref(gio_channel);

		gio_channel = NULL;
	}

	pcap_file_cleanup();

	llcp_decode_cleanup();
}

int sniffer_init(void)
{
	struct sockaddr_nfc_llcp sockaddr;
	int sock = 0;
	int err;
	int one = 1;

	buffer = g_malloc(BUFFER_LEN);

	sock = socket(AF_NFC, SOCK_RAW, NFC_SOCKPROTO_LLCP);

	if (sock < 0) {
		print_error("socket: %s", strerror(errno));
		return -1;
	}

	err = setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));
	if (err < 0)
		print_error("setsockopt: %s", strerror(errno));

	memset(&sockaddr, 0, sizeof(struct sockaddr_nfc_llcp));
	sockaddr.sa_family = AF_NFC;
	sockaddr.dev_idx = opts.adapter_idx;
	sockaddr.nfc_protocol = NFC_PROTO_NFC_DEP;

	err = bind(sock, (struct sockaddr *)&sockaddr,
			sizeof(struct sockaddr_nfc_llcp));

	if (err < 0) {
		print_error("bind: %s", strerror(errno));
		goto exit;
	}

	gio_channel = g_io_channel_unix_new(sock);
	g_io_channel_set_close_on_unref(gio_channel, TRUE);

	g_io_channel_set_encoding(gio_channel, NULL, NULL);
	g_io_channel_set_buffered(gio_channel, FALSE);

	watch = g_io_add_watch(gio_channel,
		       G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
		       gio_handler, NULL);

	g_io_channel_unref(gio_channel);

	if (opts.pcap_filename) {
		err = pcap_file_init(opts.pcap_filename);
		if (err)
			goto exit;
	}

	err = llcp_decode_init();
	if (err)
		goto exit;

	printf("Start sniffer on nfc%d\n\n", opts.adapter_idx);

exit:
	if (err)
		sniffer_cleanup();

	return err;
}

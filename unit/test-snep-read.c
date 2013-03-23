/*
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2013  Mobica Limited. All rights reserved.
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
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/socket.h>

#include <near/types.h>

#include "test-utils.h"

#define TEST_SNEP_LOG(fmt, ...) do { \
	if (g_test_verbose()) {\
		g_printf("[SNEP unit] " fmt, ##__VA_ARGS__); \
	} \
	} while (0)

#define TEST_SNEP_PTR_UNUSED(x) do { if ((void *)x != NULL) {} } while (0)

static const char *short_text = "neard";

/* sockets */
static int sockfd[2];
static int client;
static int server;

struct test_snep_context {
	uint8_t snep_version;
	uint32_t req_info_len;
	uint32_t payload_len;
	uint8_t *req_info;

	uint32_t acc_len; /* req GET specific */

	struct near_ndef_message *test_recd_msg;
};

/* variables used in dummy_req_{get|put} */
static struct test_snep_context *gcontext;
static struct near_ndef_record *stored_recd;
static GSList *test_fragments;

static void test_snep_init(gpointer context, gconstpointer data)
{
	struct test_snep_context *ctx = context;
	struct timeval tv;
	int ret;
	const char *test_data = data;

	g_assert(socketpair(PF_LOCAL, SOCK_STREAM, 0, sockfd) == 0);

	client = 0;
	server = 1;

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret = setsockopt(sockfd[client], SOL_SOCKET, SO_RCVTIMEO,
			(const void *) &tv, sizeof(tv));
	if (ret != 0)
		TEST_SNEP_LOG("set sock SO_RCVTIMEO failed");

	__near_snep_core_init();

	stored_recd = NULL;

	ctx->test_recd_msg = test_ndef_create_test_record(test_data);

	ctx->snep_version = NEAR_SNEP_VERSION;
	ctx->req_info = ctx->test_recd_msg->data;
	ctx->req_info_len = ctx->test_recd_msg->length;
	ctx->payload_len = ctx->test_recd_msg->length;
	ctx->acc_len = 64;

	gcontext = ctx;
}

static void test_snep_cleanup(gpointer context, gconstpointer data)
{
	struct test_snep_context *ctx = context;

	__near_snep_core_cleanup();

	if (stored_recd)
		test_ndef_free_record(stored_recd);

	if (ctx->test_recd_msg) {
		g_free(ctx->test_recd_msg->data);
		g_free(ctx->test_recd_msg);
	}

	g_slist_free(test_fragments);

	close(sockfd[client]);
	close(sockfd[server]);

	gcontext = NULL;
}

/*
 * @brief Test: Confirm that server is able to send simple response
 */
static void test_snep_response_noinfo(gpointer context, gconstpointer gp)
{
	int bytes_recv;
	struct p2p_snep_resp_frame resp;

	near_snep_core_response_noinfo(sockfd[client], NEAR_SNEP_RESP_SUCCESS);

	bytes_recv = recv(sockfd[server], &resp, sizeof(resp), 0);
	g_assert(bytes_recv == NEAR_SNEP_RESP_HEADER_LENGTH);
	g_assert(resp.version == NEAR_SNEP_VERSION);
	g_assert(resp.response == NEAR_SNEP_RESP_SUCCESS);
	g_assert(resp.length == 0);
}

int main(int argc, char **argv)
{
	GTestSuite *ts;
	GTestFixtureFunc init = test_snep_init;
	GTestFixtureFunc exit = test_snep_cleanup;
	size_t fs = sizeof(struct test_snep_context);

	g_test_init(&argc, &argv, NULL);

	ts = g_test_create_suite("SNEP responses");
	g_test_suite_add(ts,
		g_test_create_case("noinfo", fs, short_text,
			init, test_snep_response_noinfo, exit));

	g_test_suite_add_suite(g_test_get_root(), ts);

	return g_test_run();
}

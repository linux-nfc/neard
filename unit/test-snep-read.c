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

#define TEST_SNEP_PTR_UNUSED(x) do { if ((void *)x) {} } while (0)

static const char *short_text = "neard";

static const char *long_text = "The Linux NFC project aims to provide a " \
	"full NFC support for Linux. It is based on the neard NFC user space "\
	"stack running on top of the Linux kernel NFC subsystem. NFC stands " \
	"Near Field Communication. It is a short-range (a few centimeters)"\
	"radio technology that enables communication between devices that " \
	"either touch or are momentarily held close together. NFC is an open "\
	"technology standardized by the NFC Forum. It is based on RFID. ";

/* 'neard' - UTF-8 - en-US Text NDEF */
static uint8_t text[] = { 0xd1, 0x1, 0xb, 0x54, 0x5, 0x65, 0x6e,
			0x2d, 0x55, 0x53, 0x6e, 0x65, 0x61, 0x72, 0x64 };

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

/* GET/PUT server functions */

/*
 * @brief Utility: Dummy PUT request handler
 */
static bool test_snep_dummy_req_put(int fd, void *data)
{
	struct p2p_snep_data *snep_data = data;
	GList *records;
	uint8_t *nfc_data;
	uint32_t nfc_data_length;
	uint32_t offset = 0;

	TEST_SNEP_LOG(">> dummy_req_put entry %p\n", data);

	if (!snep_data)
		goto error;

	if (stored_recd)
		TEST_SNEP_LOG("\tdummy_req_put already stored record\n");

	if (snep_data->nfc_data_length > snep_data->nfc_data_current_length)
		return true;

	test_fragments = g_slist_append(test_fragments, snep_data);

	nfc_data_length = 0;
	nfc_data = g_try_malloc0(snep_data->nfc_data_length);
	g_assert(nfc_data);

	while (g_slist_length(test_fragments) > 0) {
		static int frag_cnt;
		struct p2p_snep_data *fragment = test_fragments->data;

		TEST_SNEP_LOG("\tdummy_req_put frag=%d, len=%d, current=%d\n",
				frag_cnt, fragment->nfc_data_length,
				fragment->nfc_data_current_length);
		test_fragments = g_slist_remove(test_fragments, fragment);

		memcpy(nfc_data + offset, fragment->nfc_data,
			fragment->nfc_data_current_length - nfc_data_length);

		offset += fragment->nfc_data_current_length - nfc_data_length;
		nfc_data_length = offset;

		frag_cnt++;
	}

	records = near_ndef_parse_msg(nfc_data, nfc_data_length, NULL);
	if (!records) {
		TEST_SNEP_LOG("\tdummy_req_put parsing ndef failed\n");
		goto error;
	}

	if (g_list_length(records) != 1) {
		TEST_SNEP_LOG("\tdummy_req_put records number mismatch");
		goto error;
	}

	g_free(nfc_data);

	stored_recd = records->data;

	TEST_SNEP_LOG("\t\tdummy_req_put STORED REC data=%p length=%zu\n",
			stored_recd->data, stored_recd->data_len);

	near_snep_core_response_noinfo(fd, NEAR_SNEP_RESP_SUCCESS);
	return true;

error:
	TEST_SNEP_LOG("\tdummy_req_put error!!!\n");
	return false;
}

/*
 * @brief Utility: Dummy GET request handler
 */
static bool test_snep_dummy_req_get(int fd, void *data)
{
	struct p2p_snep_data *snep_data = data;

	TEST_SNEP_LOG(">> dummy_req_get entry %p\n", data);

	if (!snep_data)
		goto error;

	TEST_SNEP_LOG("\t\tdummy_req_get STORED REC data=%p length=%zu\n",
			stored_recd->data, stored_recd->data_len);

	near_snep_core_response_with_info(fd, NEAR_SNEP_RESP_SUCCESS,
					near_ndef_data_ptr(stored_recd),
					near_ndef_data_length(stored_recd));
	return true;

error:
	TEST_SNEP_LOG("\tdummy_req_get error!!!\n");
	return false;
}

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
 * @brief Utility: Allocate and build SNEP request frame.
 *
 * @param[in] frame_len   Size of the entire frame
 * @param[in] ver         SNEP protocol version field
 * @param[in] resp_type   SNEP response code field
 * @param[in] info_len    SNEP info length field
 * @param[in] data        SNEP info field
 * @param[in] payload_len Size of the payload to be inserted
 * @return p2p_snep_resp_frame
 */
static struct p2p_snep_req_frame *test_snep_build_req_frame(
		size_t frame_len, uint8_t ver, uint8_t req_type,
		uint32_t info_len, uint8_t *data, uint32_t payload_len)
{
	struct p2p_snep_req_frame *req;

	req = g_try_malloc0(frame_len);
	g_assert(req);

	req->version = ver;
	req->request = req_type;
	req->length = GUINT_TO_BE(info_len);
	memcpy(req->ndef, data, payload_len);

	return req;
}

/*
 * @brief Utility: Allocate and build SNEP GET request frame.
 *
 * @param[in] frame_len   Size of the entire frame
 * @param[in] ver         SNEP protocol version field
 * @param[in] resp_type   SNEP response code field
 * @param[in] info_len    SNEP info length field
 * @param[in] data        SNEP info field
 * @param[in] acc_len     SNEP acceptable length field
 * @param[in] payload_len Size of the payload to be inserted
 * @return p2p_snep_resp_frame
 */
static struct p2p_snep_req_frame *test_snep_build_req_get_frame(
			size_t frame_len, uint8_t ver, uint8_t req_type,
			uint32_t info_len, uint32_t acc_len, uint8_t *data,
			uint32_t payload_len)
{
	struct p2p_snep_req_frame *req;
	uint32_t acc_len_be = GUINT_TO_BE(acc_len);

	req = g_try_malloc0(frame_len);
	g_assert(req);

	req->version = ver;
	req->request = req_type;
	req->length = GUINT_TO_BE(info_len);
	memcpy(req->ndef, &acc_len_be, sizeof(acc_len_be));
	memcpy(req->ndef + sizeof(acc_len_be), data, payload_len);

	return req;
}

/*
 * @brief Utility: Allocate and build SNEP response frame.
 *
 * @param[in] frame_len   Size of the entire frame
 * @param[in] ver         SNEP protocol version field
 * @param[in] resp_type   SNEP response code field
 * @param[in] info_len    SNEP info length field
 * @param[in] data        SNEP info field
 * @return p2p_snep_resp_frame
 */
static struct p2p_snep_resp_frame *test_snep_build_resp_frame(
			size_t frame_len, uint8_t ver, uint8_t resp_type,
			uint32_t info_len, uint8_t *data)
{
	struct p2p_snep_resp_frame *resp;

	resp = g_try_malloc0(frame_len);
	g_assert(resp);

	resp->version = ver;
	resp->response = resp_type;
	resp->length = GUINT_TO_BE(info_len);
	memcpy(resp->info, data, info_len);

	return resp;
}

/*
 * @brief Utility: Send the \p req frame to the socket and call
 * near_snep_core_read
 *
 * @param[in] req        Request frame to send
 * @param[in] frame_len  Size of the frame
 * @param[in] req_get    GET server function
 * @param[in] req_put    PUT server function
 * @return near_bool_t returned by near_snep_core_read
 */
static bool test_snep_read_req_common(
			struct p2p_snep_req_frame *req, size_t frame_len,
			near_server_io req_get, near_server_io req_put)
{
	bool ret;
	size_t nbytes;

	nbytes = send(sockfd[client], req, frame_len, 0);
	g_assert(nbytes == frame_len);

	TEST_SNEP_LOG("sent 0x%02X request\n", req->request);

	ret = near_snep_core_read(sockfd[server], 0, 0, NULL, req_get, req_put,
									NULL);

	return ret;
}

/*
 * @brief Utility: Send \p frame_len bytes of the fragment \p data
 * to the socket and call near_snep_core_read
 *
 * @param[in] frag_len
 * @param[in] data
 * @return near_bool_t returned by near_snep_core_read
 *
 * @note does not call near_snep_core_read for now, since it can't handle
 * frame without SNEP header
 */
static bool test_snep_read_send_fragment(size_t frag_len,
						uint8_t *data)
{
	size_t nbytes;

	nbytes = send(sockfd[client], data, frag_len, 0);
	g_assert(nbytes == frag_len);

	near_snep_core_read(sockfd[server], 0, 0, NULL,
			test_snep_dummy_req_get, test_snep_dummy_req_put,
									NULL);

	return true;
}

/*
 * @brief Utility: Receive remaining fragments and store in \p data_recvd
 *
 * @param[in]  frag_len
 * @param[in]  remaining_bytes
 * @param[out] data             Must be preallocated
 */
static void test_snep_read_recv_fragments(uint32_t frag_len,
				uint32_t remaining_bytes, void *data_recvd)
{
	struct p2p_snep_resp_frame *resp;
	uint32_t offset = 0;
	int nbytes;

	g_assert(data_recvd);

	resp = g_try_malloc0(frag_len);
	g_assert(resp);

	do {
		memset(resp, 0, frag_len);

		/* receive remaining fragments */
		nbytes = recv(sockfd[client], resp, frag_len, 0);
		g_assert(nbytes > 0); /* TODO use explicit value? */

		/* store received data (no header this time) */
		memcpy(data_recvd + offset, resp, nbytes);
		offset += nbytes;
	} while (offset < remaining_bytes);

	g_free(resp);
}

/*
 * @brief Utility: Confirm that server didn't send any response
 */
static void test_snep_read_no_response(void)
{
	struct p2p_snep_resp_frame *resp;
	int nbytes;

	resp = g_try_malloc0(sizeof(*resp));
	g_assert(resp);

	nbytes = recv(sockfd[client], resp, sizeof(*resp), MSG_DONTWAIT);
	g_assert(nbytes < 0);
	g_assert(errno == EAGAIN);

	g_free(resp);
}

/*
 * @brief Utility: Verify response sent by the server
 *
 * @param[in] exp_resp_code      Expected response code
 * @param[in] exp_resp_info_len  Expected response info length
 * @param[in] exp_resp_info      Expected response info
 */
static void test_snep_read_verify_resp(int exp_resp_code,
		uint32_t exp_resp_info_len, uint8_t *exp_resp_info)
{
	struct p2p_snep_resp_frame *resp;
	size_t nbytes, frame_len;

	frame_len = NEAR_SNEP_RESP_HEADER_LENGTH + exp_resp_info_len;
	resp = test_snep_build_resp_frame(frame_len, 0, 0, 0, NULL);
	g_assert(resp);

	nbytes = recv(sockfd[client], resp, frame_len, 0);
	g_assert(nbytes == frame_len);

	TEST_SNEP_LOG("received response = 0x%02X, exp = 0x%02X\n",
			resp->response, exp_resp_code);

	g_assert(resp->version == NEAR_SNEP_VERSION);
	g_assert(resp->response == exp_resp_code);
	g_assert(resp->length == GUINT_TO_BE(exp_resp_info_len));
	g_assert(!memcmp(resp->info, exp_resp_info, exp_resp_info_len));

	g_free(resp);
}

/*
 * @brief Utility: Verify code of the response sent by the server
 *
 * @param[in] exp_resp_code  Expected response code
 */
static void test_snep_read_verify_resp_code(int exp_resp_code)
{
	test_snep_read_verify_resp(exp_resp_code, 0, NULL);
}

/*
 * @brief Test: Confirm that server is able to handle PUT request
 *
 * Steps:
 * - Send well-formed PUT request
 * - Verify server responded with SUCCESS
 */
static void test_snep_read_put_req_ok(gpointer context, gconstpointer gp)
{
	struct test_snep_context *ctx = context;
	struct p2p_snep_req_frame *req;
	uint32_t frame_len, payload_len;
	bool ret;

	payload_len = ctx->req_info_len;
	frame_len = NEAR_SNEP_REQ_PUT_HEADER_LENGTH + payload_len;

	req = test_snep_build_req_frame(frame_len, NEAR_SNEP_VERSION,
					NEAR_SNEP_REQ_PUT, ctx->req_info_len,
					ctx->req_info, payload_len);

	ret = test_snep_read_req_common(req, frame_len, test_snep_dummy_req_get,
					test_snep_dummy_req_put);
	g_assert(ret);

	test_snep_read_verify_resp_code(NEAR_SNEP_RESP_SUCCESS);

	g_free(req);
}

/*
 * @brief Test: Confirm that server checks the version field of the request.
 *
 * Steps:
 * - Send PUT request with incorrect version field
 * - Verify server responded with UNSUPPORTED VERSION
 */
static void test_snep_read_put_req_unsupp_ver(gpointer context,
						gconstpointer gp)
{
	struct test_snep_context *ctx = context;
	struct p2p_snep_req_frame *req;
	uint32_t frame_len, payload_len;
	bool ret;

	payload_len = ctx->req_info_len;
	frame_len = NEAR_SNEP_REQ_PUT_HEADER_LENGTH + payload_len;

	req = test_snep_build_req_frame(frame_len, 0xF8, NEAR_SNEP_REQ_PUT,
				ctx->req_info_len, ctx->req_info, payload_len);

	ret = test_snep_read_req_common(req, frame_len, test_snep_dummy_req_get,
					test_snep_dummy_req_put);
	g_assert(ret);

	test_snep_read_verify_resp_code(NEAR_SNEP_RESP_VERSION);

	g_free(req);
}

/*
 * @brief Test: Confirm that server responds about no support for the
 * functionality in request message
 *
 * Steps:
 * - Send PUT request
 * - Pass NULL PUT request handler to the near_snep_core_read
 * - Verify server responded with NOT IMPLEMENTED
 */
static void test_snep_read_put_req_not_impl(gpointer context,
						gconstpointer gp)
{
	struct test_snep_context *ctx = context;
	struct p2p_snep_req_frame *req;
	uint32_t frame_len, payload_len;
	bool ret;

	payload_len = ctx->req_info_len;
	frame_len = NEAR_SNEP_REQ_PUT_HEADER_LENGTH + payload_len;

	req = test_snep_build_req_frame(frame_len, NEAR_SNEP_VERSION,
					NEAR_SNEP_REQ_PUT, ctx->req_info_len,
					ctx->req_info, payload_len);

	ret = test_snep_read_req_common(req, frame_len, test_snep_dummy_req_get,
					NULL);
	g_assert(ret);

	test_snep_read_verify_resp_code(NEAR_SNEP_RESP_NOT_IMPL);

	g_free(req);
}

/*
 * @brief Test: Confirm that server is able to receive fragmented request msg
 *
 * Steps:
 * - Send PUT request with incomplete data
 * - Verify server responded with CONTINUE
 * - Send second fragment of the message
 * - Verify server didn't respond
 * - Send last fragment of the message
 * - Verify server responded with SUCCESS
 */
static void test_snep_read_put_req_fragmented(gpointer context,
						gconstpointer gp)
{
	struct test_snep_context *ctx = context;
	struct p2p_snep_req_frame *req;
	uint32_t frame_len, payload_len;
	bool ret;

	payload_len = ctx->req_info_len / 3;
	frame_len = NEAR_SNEP_REQ_PUT_HEADER_LENGTH + payload_len;

	req = test_snep_build_req_frame(frame_len, NEAR_SNEP_VERSION,
					NEAR_SNEP_REQ_PUT, ctx->req_info_len,
					ctx->req_info, payload_len);

	/* send 1st fragment within PUT request */
	ret = test_snep_read_req_common(req, frame_len, test_snep_dummy_req_get,
					test_snep_dummy_req_put);
	g_assert(ret);

	test_snep_read_verify_resp_code(NEAR_SNEP_RESP_CONTINUE);

	/* send 2nd fragment */
	ret = test_snep_read_send_fragment(payload_len,
					ctx->req_info + payload_len);
	g_assert(ret);

	/* do not expect a response */
	test_snep_read_no_response();

	/* send last fragment */
	ret = test_snep_read_send_fragment(ctx->req_info_len - 2 * payload_len,
					ctx->req_info + 2 * payload_len);
	g_assert(ret);

	/*
	 * TODO expected SUCCESS response:
	 *     test_snep_read_verify_resp_code(NEAR_SNEP_RESP_SUCCESS);
	 */

	TEST_SNEP_LOG("EXPECTED FAIL: fragments are not received by SNEP\n");

	g_free(req);
}

/*
 * @brief Test: Confirm that server is able to handle GET request
 *
 * Steps:
 * - Send PUT request with some data
 * - Send GET request
 * - Verify server responded with SUCCESS and correct data
 */
static void test_snep_read_get_req_ok(gpointer context, gconstpointer gp)
{
	struct test_snep_context *ctx = context;
	struct p2p_snep_req_frame *req;
	uint32_t frame_len, payload_len, info_len;
	bool ret;

	/* send some data to the server */
	test_snep_read_put_req_ok(context, gp);

	info_len = ctx->req_info_len + NEAR_SNEP_ACC_LENGTH_SIZE;
	payload_len = ctx->req_info_len;

	frame_len = NEAR_SNEP_REQ_GET_HEADER_LENGTH + payload_len;

	req = test_snep_build_req_get_frame(frame_len, NEAR_SNEP_VERSION,
				NEAR_SNEP_REQ_GET, info_len,
				ctx->acc_len, ctx->req_info, payload_len);

	ret = test_snep_read_req_common(req, frame_len, test_snep_dummy_req_get,
					test_snep_dummy_req_put);
	g_assert(ret);

	test_snep_read_verify_resp(NEAR_SNEP_RESP_SUCCESS, ctx->req_info_len,
				ctx->req_info);

	g_free(req);
}

/*
 * @brief Test: Confirm that server responds about no support for the
 * functionality in request message
 *
 * Steps:
 * - Send PUT request with some data
 * - Send GET request
 * - Pass NULL GET request handler to the near_snep_core_read
 * - Verify server responded with NOT IMPLEMENTED
 */
static void test_snep_read_get_req_not_impl(gpointer context,
						gconstpointer gp)
{
	struct test_snep_context *ctx = context;
	struct p2p_snep_req_frame *req;
	uint32_t frame_len, payload_len;
	bool ret;

	/* send some data to the server */
	test_snep_read_put_req_ok(context, gp);

	payload_len = ctx->req_info_len;
	frame_len = NEAR_SNEP_REQ_GET_HEADER_LENGTH + payload_len;

	/* build REQ GET frame */
	req = test_snep_build_req_get_frame(frame_len, NEAR_SNEP_VERSION,
			NEAR_SNEP_REQ_GET, ctx->req_info_len, ctx->acc_len,
			ctx->req_info, payload_len);

	/* call snep_core_read with NULL req_get handler */
	ret = test_snep_read_req_common(req, frame_len, NULL,
					test_snep_dummy_req_put);
	g_assert(ret);

	test_snep_read_verify_resp_code(NEAR_SNEP_RESP_NOT_IMPL);

	g_free(req);
}

/*
 * @brief Test: Confirm that server is able to respond with fragmented message
 *
 * Steps:
 * - Send PUT request with some data
 * - Send GET request with Acceptable Length less than actual data length
 * - Verify that server returned with incomplete data
 * - Send CONTINUE or REJECT request (depending on \p client_resp param)
 * - If REJECT requested, verify that server didn't respond
 * - If CONTINUE requested, receive remaining fragments and verify data
 */
static void test_snep_read_get_req_frags_client_resp(gpointer context,
					gconstpointer gp, uint8_t client_resp)
{
	struct test_snep_context *ctx = context;
	struct p2p_snep_req_frame *req;
	struct p2p_snep_resp_frame *resp;
	uint32_t frame_len, payload_len;
	bool ret;
	size_t nbytes;
	uint8_t *data_recvd;
	uint32_t offset;
	uint32_t frag_len, info_len;

	/* send some data to the server */
	test_snep_read_put_req_ok(context, gp);

	payload_len = ctx->req_info_len;
	frame_len = NEAR_SNEP_REQ_GET_HEADER_LENGTH + payload_len;

	/* force fragmentation */
	ctx->acc_len = 60;
	g_assert(ctx->acc_len < ctx->req_info_len);
	g_assert(NEAR_SNEP_REQ_MAX_FRAGMENT_LENGTH < ctx->req_info_len);

	/* TODO frag_len should be calculated based on SNEP acc_len */
	TEST_SNEP_LOG("WORKAROUND: SNEP core ignores the acceptable length\n");
	frag_len = NEAR_SNEP_REQ_MAX_FRAGMENT_LENGTH;

	info_len = ctx->req_info_len + NEAR_SNEP_ACC_LENGTH_SIZE;

	req = test_snep_build_req_get_frame(frame_len, NEAR_SNEP_VERSION,
				NEAR_SNEP_REQ_GET, info_len,
				ctx->acc_len, ctx->req_info, payload_len);

	/* send GET request */
	ret = test_snep_read_req_common(req, frame_len, test_snep_dummy_req_get,
					test_snep_dummy_req_put);
	g_assert(ret);
	g_free(req);

	frame_len = NEAR_SNEP_RESP_HEADER_LENGTH + payload_len;
	resp = test_snep_build_resp_frame(frame_len, 0, 0, 0, NULL);

	/* start receiving fragments */
	nbytes = recv(sockfd[client], resp, frame_len, 0);
	g_assert(nbytes == frag_len);
	g_assert(resp->length == GUINT_TO_BE(ctx->req_info_len));
	g_assert(resp->info);

	data_recvd = g_try_malloc0(ctx->req_info_len);
	g_assert(data_recvd);

	/* store received info field */
	memcpy(data_recvd, resp->info, nbytes - NEAR_SNEP_RESP_HEADER_LENGTH);
	g_free(resp);

	offset = nbytes - NEAR_SNEP_RESP_HEADER_LENGTH;

	/* 1st fragment has been received, so request resp=CONTINUE/REJECT */
	frame_len = NEAR_SNEP_REQ_PUT_HEADER_LENGTH;
	req = test_snep_build_req_frame(frame_len, NEAR_SNEP_VERSION,
					client_resp, 0, NULL, 0);

	ret = test_snep_read_req_common(req, frame_len, NULL, NULL);
	g_free(req);

	if (client_resp == NEAR_SNEP_REQ_REJECT) {
		g_assert(ret);
		test_snep_read_no_response();
	} else if (client_resp == NEAR_SNEP_REQ_CONTINUE) {
		g_assert(ret);

		/* receive remaining fragments */
		test_snep_read_recv_fragments(frag_len,
					ctx->req_info_len - offset,
					data_recvd + offset);

		/* verify data */
		g_assert(!memcmp(data_recvd, ctx->req_info,
				ctx->req_info_len));
	}

	g_free(data_recvd);
}

/* Refer to the test_snep_read_get_req_frags_client_resp for description */
static void test_snep_read_get_frags_continue(gpointer context,
						gconstpointer gp)
{
	test_snep_read_get_req_frags_client_resp(context, gp,
						NEAR_SNEP_REQ_CONTINUE);
}

/* Refer to the test_snep_read_get_req_frags_client_resp for description */
static void test_snep_read_get_frags_reject(gpointer context,
						gconstpointer gp)
{
	test_snep_read_get_req_frags_client_resp(context, gp,
						NEAR_SNEP_REQ_REJECT);
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

/*
 * @brief Test: Confirm that server is able to communicate with the client
 */
static void test_snep_response_put_get_ndef(gpointer context,
						gconstpointer gp)
{
	size_t nbytes;

	struct p2p_snep_req_frame *req;
	struct p2p_snep_resp_frame *resp;
	struct near_ndef_message *ndef;

	bool ret;
	uint frame_len;

	ndef = near_ndef_prepare_text_record("UTF-8", "en-US", "neard");
	g_assert(ndef);
	g_assert(ndef->data);
	g_assert(ndef->length > 0);

	frame_len = NEAR_SNEP_RESP_HEADER_LENGTH + ndef->length;

	req = g_try_malloc0(frame_len);
	g_assert(req);

	req->version = 0x10;
	req->request = NEAR_SNEP_REQ_PUT;
	req->length = GUINT_TO_BE(ndef->length);
	memcpy(req->ndef, ndef->data, ndef->length);

	/* Send PUT request with text record */
	nbytes = send(sockfd[server], req, frame_len, 0);
	g_assert(nbytes == frame_len);

	/* UUT */
	ret = near_snep_core_read(sockfd[client], 0, 0, NULL,
			test_snep_dummy_req_get, test_snep_dummy_req_put, NULL);
	g_assert(ret);

	resp = g_try_malloc0(frame_len);
	g_assert(resp);

	/* Get response from server */
	nbytes = recv(sockfd[server], resp, frame_len, 0);
	g_assert(nbytes > 0);
	g_assert(resp->response == NEAR_SNEP_RESP_SUCCESS);

	/* Send GET request to retrieve a record */
	req->request = NEAR_SNEP_REQ_GET;
	req->length = 0;
	nbytes = send(sockfd[server], req, NEAR_SNEP_RESP_HEADER_LENGTH, 0);
	g_assert(nbytes > 0);

	/* UUT */
	ret = near_snep_core_read(sockfd[client], 0, 0, NULL,
			test_snep_dummy_req_get, test_snep_dummy_req_put, NULL);
	g_assert(ret);

	/* Get response and verify */
	nbytes = recv(sockfd[server], resp, frame_len, 0);
	g_assert(nbytes > 0);
	g_assert(resp->response == NEAR_SNEP_RESP_SUCCESS);
	g_assert(resp->length == GUINT_TO_BE(ndef->length));
	g_assert(!memcmp(resp->info, text, ndef->length));

	g_free(req);
	g_free(resp);
	g_free(ndef->data);
	g_free(ndef);
}

int main(int argc, char **argv)
{
	GTestSuite *ts;
	GTestFixtureFunc init = test_snep_init;
	GTestFixtureFunc exit = test_snep_cleanup;
	size_t fs = sizeof(struct test_snep_context);

	g_test_init(&argc, &argv, NULL);

	ts = g_test_create_suite("testSNEP-response");
	g_test_suite_add(ts,
		g_test_create_case("noinfo", fs, short_text,
			init, test_snep_response_noinfo, exit));

	g_test_suite_add_suite(g_test_get_root(), ts);

	ts = g_test_create_suite("testSNEP-readGET");
	g_test_suite_add(ts,
		g_test_create_case("Request ok", fs, short_text,
			init, test_snep_read_get_req_ok, exit));
	g_test_suite_add(ts,
		g_test_create_case("Request not implemented", fs, short_text,
			init, test_snep_read_get_req_not_impl, exit));
	g_test_suite_add(ts,
		g_test_create_case("Request fragmented CONTINUE",
			fs, long_text, init,
			test_snep_read_get_frags_continue, exit));
	g_test_suite_add(ts,
		g_test_create_case("Request fragmented REJECT",
			fs, long_text, init,
			test_snep_read_get_frags_reject, exit));

	g_test_suite_add_suite(g_test_get_root(), ts);

	ts = g_test_create_suite("testSNEP-readPUT");
	g_test_suite_add(ts,
		g_test_create_case("Request ok", fs, short_text,
			init, test_snep_read_put_req_ok, exit));
	g_test_suite_add(ts,
		g_test_create_case("Request unsupported ver", fs, short_text,
			init, test_snep_read_put_req_unsupp_ver, exit));
	g_test_suite_add(ts,
		g_test_create_case("Request not implemented", fs, short_text,
			init, test_snep_read_put_req_not_impl, exit));
	g_test_suite_add(ts,
		g_test_create_case("Request fragmented", fs, long_text,
			init, test_snep_read_put_req_fragmented, exit));

	g_test_suite_add_suite(g_test_get_root(), ts);

	ts = g_test_create_suite("testSNEP-misc");
	g_test_suite_add(ts,
		g_test_create_case("PUT and GET request NDEF",
			fs, short_text, init,
			test_snep_response_put_get_ndef, exit));

	g_test_suite_add_suite(g_test_get_root(), ts);

	return g_test_run();
}

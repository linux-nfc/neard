#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/socket.h>

#include <near/nfc_copy.h>
#include <near/types.h>
#include <near/ndef.h>

#include "../src/near.h"

/* HACK HACK */
#ifndef AF_NFC
#define AF_NFC 39
#endif

#define SNEP_VERSION     0x10

/* Request codes */
#define SNEP_REQ_CONTINUE 0x00
#define SNEP_REQ_GET      0x01
#define SNEP_REQ_PUT      0x02
#define SNEP_REQ_REJECT   0x7f

/* Response codes */
#define SNEP_RESP_CONTINUE  0x80
#define SNEP_RESP_SUCCESS   0x81
#define SNEP_RESP_NOT_FOUND 0xc0
#define SNEP_RESP_EXCESS    0xc1
#define SNEP_RESP_BAD_REQ   0xc2
#define SNEP_RESP_NOT_IMPL  0xe0
#define SNEP_RESP_VERSION   0xe1
#define SNEP_RESP_REJECT    0xff

struct p2p_snep_req_frame {
	uint8_t version;
	uint8_t request;
	uint32_t length;
	uint8_t ndef[];
} __attribute__((packed));

int main(int argc, char *argv[])
{
	int fd, len;
	struct near_ndef_message *ndef;
	int adapter_idx, target_idx;
	struct sockaddr_nfc_llcp addr;
	struct p2p_snep_req_frame *frame;
	size_t frame_length;

	if (argc < 3) {
		printf("Usage: %s <adapter index> <target index>\n", argv[0]);
		exit(0);
	}

	adapter_idx = atoi(argv[1]);
	target_idx = atoi(argv[2]);

	fd =  socket(AF_NFC, SOCK_STREAM, NFC_SOCKPROTO_LLCP);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(struct sockaddr_nfc_llcp));
	addr.sa_family = AF_NFC;
	addr.dev_idx = adapter_idx;
	addr.target_idx = target_idx;
	addr.nfc_protocol = NFC_PROTO_NFC_DEP;
	addr.service_name_len = strlen("urn:nfc:sn:snep");
	strcpy(addr.service_name, "urn:nfc:sn:snep");

	if (connect(fd, (struct sockaddr *)&addr,
		    sizeof(struct sockaddr_nfc_llcp)) < 0) {
		near_error("Connect error %s\n", strerror(errno));
		return -1;
	}
	
	ndef = near_ndef_prepare_text_record("UTF-8", "en", "Hello world");
	if (!ndef) {
		close(fd);
		near_error("Could not build NDEF");
		return -1;
	}

	frame_length = sizeof(struct p2p_snep_req_frame) + ndef->length;
	frame = g_try_malloc0(frame_length);
	if (!frame) {
		close(fd);
		near_error("Could not allocate SNEP frame");
		return -1;
	}

	frame->version = SNEP_VERSION;
	frame->request = SNEP_REQ_PUT;
	frame->length = GUINT_TO_BE(ndef->length);

	memcpy(frame->ndef, ndef->data, ndef->length);

	len = send(fd, (uint8_t *)frame, frame_length, 0);
	if (len < 0) {
		near_error("Could not send text NDEF %s\n", strerror(errno));

		g_free(frame);
		close(fd);

		return -1;
	}

	DBG("Sent %d bytes", len);

	g_free(frame);
	close(fd);

	return 0;
}

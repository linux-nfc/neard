/*
 *
 *  neard - Near Field Communication manager
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

#ifndef AF_NFC
#define AF_NFC 39
#endif

#ifndef SOL_NFC
#define SOL_NFC	280
#endif

#define LLCP_DEFAULT_MIU 128

struct near_p2p_driver {
	char *name;
	char *service_name;
	const char *fallback_service_name;
	bool single_connection;
	int sock_type;
	gpointer user_data;

	bool (*read)(int client_fd, uint32_t adapter_idx, uint32_t target_idx,
						near_device_io_cb cb,
						gpointer data);
	int (*push)(int client_fd, uint32_t adapter_idx, uint32_t target_idx,
						struct near_ndef_message *ndef,
						near_device_io_cb cb,
						gpointer data);
	void (*close)(int client_fd, int err, gpointer data);
	bool (*new_client)(char *service_name, int client_fd, gpointer data);
};

int phdc_init(void);
void phdc_exit(void);

int npp_init(void);
void npp_exit(void);

int handover_init(void);
void handover_exit(void);

int snep_init(void);
void snep_exit(void);

int snep_validation_init(void);
void snep_validation_exit(void);

int llcp_validation_init(void);
void llcp_validation_exit(void);

int near_p2p_register(struct near_p2p_driver *driver);
void near_p2p_unregister(struct near_p2p_driver *driver);

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

struct near_p2p_driver {
	const char *name;
	const char *service_name;
	near_bool_t (*read)(int client_fd,
				uint32_t adapter_idx, uint32_t target_idx,
				near_device_io_cb cb);
	void (*close)(int client_fd, int err);
};

#define TLV_SIZE 2

int npp_init(void);
void npp_exit(void);

int snep_init(void);
void snep_exit(void);

int handover_init(void);
void handover_exit(void);

int near_p2p_register(struct near_p2p_driver *driver);
void near_p2p_unregister(struct near_p2p_driver *driver);

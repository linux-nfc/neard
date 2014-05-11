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

#ifndef __SEEL_DRIVER_H
#define __SEEL_DRIVER_H

#define SEEL_DRIVER_PRIORITY_LOW      -100
#define SEEL_DRIVER_PRIORITY_DEFAULT     0
#define SEEL_DRIVER_PRIORITY_HIGH      100

enum seel_controller_type {
	SEEL_CONTROLLER_NFC = 0,
	SEEL_CONTROLLER_MODEM,
	SEEL_CONTROLLER_ASSD,
	SEEL_CONTROLLER_PCSC,
	SEEL_CONTROLLER_UNKNOWN = 0xff
};

enum seel_se_type {
	SEEL_SE_NFC = 0, /* Embedded SE on NFC */
	SEEL_SE_ASSD, /* Advanced Security SD SE */
	SEEL_SE_PCSC, /* PCSC compatible SE */
	SEEL_SE_UICC, /* SIM card SE */
	SEEL_SE_UNKNOWN = 0xff
};

struct seel_ctrl_driver {
	enum seel_controller_type type;
	int priority;

	int (*enable_se)(uint8_t ctrl_idx, uint32_t se_idx);
	int (*disable_se)(uint8_t ctrl_idx, uint32_t se_idx);
};

typedef void (*transceive_cb_t)(void *context,
				uint8_t *apdu, size_t apdu_length,
				int err);
struct seel_io_driver {
	enum seel_se_type type;
	int priority;

	int (*transceive)(uint8_t ctrl_idx, uint32_t se_idx,
			  uint8_t *apdu, size_t apdu_length,
			  transceive_cb_t cb, void *context);
};

struct seel_cert_driver {
	GSList * (*get_hashes)(pid_t pid);
};

int seel_io_driver_register(struct seel_io_driver *driver);
void seel_io_driver_unregister(struct seel_io_driver *driver);

int seel_ctrl_driver_register(struct seel_ctrl_driver *driver);
void seel_ctrl_driver_unregister(struct seel_ctrl_driver *driver);

int seel_cert_driver_register(struct seel_cert_driver *driver);
void seel_cert_driver_unregister(struct seel_cert_driver *driver);
#endif

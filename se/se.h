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

#ifndef __SEEL_SE_H
#define __SEEL_SE_H

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

#endif

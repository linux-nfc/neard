/*
 *
 *  neard - Near Field Communication manager
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
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

#include <near/plugin.h>
#include <near/log.h>

static int nfctype2_init(void)
{
	DBG("");

	return 0;
}

static void nfctype2_exit(void)
{
	DBG("");
}

NEAR_PLUGIN_DEFINE(nfctype2, "NFC Forum Type 2 tags support", VERSION,
			NEAR_PLUGIN_PRIORITY_HIGH, nfctype2_init, nfctype2_exit)


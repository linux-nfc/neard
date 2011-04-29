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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <glib.h>

#include <gdbus.h>

#include "near.h"

static GList *driver_list = NULL;

int near_tag_driver_register(struct near_tag_driver *driver)
{
	DBG("");

	driver_list = g_list_append(driver_list, driver);

	return 0;
}

int near_tag_driver_unregister(struct near_tag_driver *driver)
{
	DBG("");

	driver_list = g_list_remove(driver_list, driver);

	return 0;
}

#if 0
int near_tag_read(guint32 adapter_idx, void *buf, size_t length)
{
	return 0;
}

#endif

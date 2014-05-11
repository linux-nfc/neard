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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <glib.h>

#include <gdbus.h>

#include "driver.h"
#include "seel.h"

static GSList *ctrl_driver_list;
static GSList *io_driver_list;
static struct seel_cert_driver *cert_driver;

static gint cmp_io_prio(gconstpointer a, gconstpointer b)
{
	const struct seel_io_driver *driver1 = a;
	const struct seel_io_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

int seel_io_driver_register(struct seel_io_driver *driver)
{
	DBG("");

	if (driver->transceive == NULL)
		return -EINVAL;

	io_driver_list = g_slist_insert_sorted(io_driver_list, driver, cmp_io_prio);

	return 0;
}

void seel_io_driver_unregister(struct seel_io_driver *driver)
{
	DBG("");

	io_driver_list = g_slist_remove(io_driver_list, driver);
}

static gint cmp_ctrl_prio(gconstpointer a, gconstpointer b)
{
	const struct seel_ctrl_driver *driver1 = a;
	const struct seel_ctrl_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

int seel_ctrl_driver_register(struct seel_ctrl_driver *driver)
{
	DBG("");

	if (driver->enable_se == NULL || driver->disable_se == NULL)
		return -EINVAL;

	ctrl_driver_list = g_slist_insert_sorted(ctrl_driver_list, driver, cmp_ctrl_prio);

	return 0;
}

void seel_ctrl_driver_unregister(struct seel_ctrl_driver *driver)
{
	DBG("");

	ctrl_driver_list = g_slist_remove(ctrl_driver_list, driver);
}

int seel_cert_driver_register(struct seel_cert_driver *driver)
{
	DBG("");

	if (!driver->get_hashes)
		return -EINVAL;

	/*
	 * OS should provide unified method to get the certificate
	 * then we only allow register one certificate driver
	 */
	if (cert_driver) {
		near_error("Certificate driver already registered");
		return -EALREADY;
	}

	cert_driver = driver;

	return 0;
}

void seel_cert_driver_unregister(struct seel_cert_driver *driver)
{
	DBG("");

	cert_driver = NULL;
}

struct seel_ctrl_driver *
__seel_driver_ctrl_find(enum seel_controller_type type)
{
	GSList *list;

	for (list = ctrl_driver_list; list; list = list->next) {
		struct seel_ctrl_driver *driver = list->data;

		DBG("driver type 0x%x", driver->type);

		if (driver->type == type)
			return driver;
	}

	return NULL;
}

struct seel_io_driver *
__seel_driver_io_find(enum seel_se_type type)
{
	GSList *list;

	for (list = io_driver_list; list; list = list->next) {
		struct seel_io_driver *driver = list->data;

		DBG("driver type 0x%x", driver->type);

		if (driver->type == type)
			return driver;
	}

	return NULL;
}

struct seel_cert_driver *__seel_driver_cert_get(void)
{
	return cert_driver;
}

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

#include <stdarg.h>
#include <syslog.h>

#include "near.h"

void near_info(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_INFO, format, ap);

	va_end(ap);
}

void near_warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_WARNING, format, ap);

	va_end(ap);
}

void near_error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_ERR, format, ap);

	va_end(ap);
}

void near_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_DEBUG, format, ap);

	va_end(ap);
}

extern struct near_debug_desc __start___debug[];
extern struct near_debug_desc __stop___debug[];

static gchar **enabled = NULL;

static bool is_enabled(struct near_debug_desc *desc)
{
	int i;

	if (!enabled)
		return false;

	for (i = 0; enabled[i]; i++) {
		if (desc->name && g_pattern_match_simple(enabled[i],
							desc->name))
			return true;
		if (desc->file && g_pattern_match_simple(enabled[i],
							desc->file))
			return true;
	}

	return false;
}

int __near_log_init(const char *debug, gboolean detach)
{
	int option = LOG_NDELAY | LOG_PID;
	struct near_debug_desc *desc;
	const char *name = NULL, *file = NULL;

	if (debug)
		enabled = g_strsplit_set(debug, ":, ", 0);

	for (desc = __start___debug; desc < __stop___debug; desc++) {
		if (file || name) {
			if (g_strcmp0(desc->file, file) == 0) {
				if (!desc->name)
					desc->name = name;
			} else
				file = NULL;
		}

		if (is_enabled(desc))
			desc->flags |= NEAR_DEBUG_FLAG_PRINT;
	}

	if (!detach)
		option |= LOG_PERROR;

	openlog("neard", option, LOG_DAEMON);

	syslog(LOG_INFO, "NEAR daemon version %s", VERSION);

	return 0;
}

void __near_log_cleanup(void)
{
	syslog(LOG_INFO, "Exit");

	closelog();

	g_strfreev(enabled);
}

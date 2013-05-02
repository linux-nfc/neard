/*
 *
 *  Near Field Communication nfctool
 *
 *  Copyright (C) 2011-2013  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>

#include "display.h"

static pid_t pager_pid = 0;

bool use_color(void)
{
	static int cached_use_color = -1;

	if (__builtin_expect(!!(cached_use_color < 0), 0))
		cached_use_color = isatty(STDOUT_FILENO) > 0 || pager_pid > 0;

	return cached_use_color;
}

int num_columns(void)
{
	static int cached_num_columns = -1;

	if (__builtin_expect(!!(cached_num_columns < 0), 0)) {
		struct winsize ws;

		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0)
			return -1;

		if (ws.ws_col > 0)
			cached_num_columns = ws.ws_col;
	}

	return cached_num_columns;
}

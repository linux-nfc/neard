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


#ifndef __NEAR_PLUGIN_H
#define __NEAR_PLUGIN_H

#include <near/version.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NEAR_PLUGIN_PRIORITY_LOW      -100
#define NEAR_PLUGIN_PRIORITY_DEFAULT     0
#define NEAR_PLUGIN_PRIORITY_HIGH      100

/**
 * SECTION:plugin
 * @title: Plugin premitives
 * @short_description: Functions for declaring plugins
 */

struct near_plugin_desc {
	const char *name;
	const char *description;
	const char *version;
	int priority;
	int (*init) (void);
	void (*exit) (void);
};

/**
 * NEAR_PLUGIN_DEFINE:
 * @name: plugin name
 * @description: plugin description
 * @version: plugin version string
 * @init: init function called on plugin loading
 * @exit: exit function called on plugin removal
 *
 * Macro for defining a plugin descriptor
 *
 * |[
 * #include <near/plugin.h>
 *
 * static int example_init(void)
 * {
 * 	return 0;
 * }
 *
 * static void example_exit(void)
 * {
 * }
 *
 * NEAR_PLUGIN_DEFINE(example, "Example plugin", NEAR_VERSION,
 * 					example_init, example_exit)
 * ]|
 */
#ifdef NEAR_PLUGIN_BUILTIN
#define NEAR_PLUGIN_DEFINE(name, description, version, priority, init, exit) \
		struct near_plugin_desc __near_builtin_ ## name = { \
			#name, description, version, priority, init, exit \
		};
#else
#define NEAR_PLUGIN_DEFINE(name, description, version, priority, init, exit) \
		extern struct near_plugin_desc near_plugin_desc \
				__attribute__ ((visibility("default"))); \
		struct near_plugin_desc near_plugin_desc = { \
			#name, description, version, priority, init, exit \
		};
#endif

#ifdef __cplusplus
}
#endif

#endif /* __NEAR_PLUGIN_H */

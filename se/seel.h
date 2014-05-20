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

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>

#include <linux/socket.h>

#include <glib.h>

#include "../src/near.h"

struct seel_se;
struct seel_channel;
struct seel_ace;
struct seel_apdu *apdu;

int __seel_manager_init(DBusConnection *conn);
void __seel_manager_cleanup(void);

#include "driver.h"

struct seel_ctrl_driver *__seel_driver_ctrl_find(enum seel_controller_type type);
struct seel_io_driver *__seel_driver_io_find(enum seel_se_type type);
struct seel_cert_driver *__seel_driver_cert_get(void);

struct seel_se *__seel_se_get(uint32_t se_idx, uint8_t ctrl_idx,
			      uint8_t ctrl_type);
const char *__seel_se_get_path(struct seel_se *se);
const GSList *__seel_se_get_hashes(struct seel_se *se, const char *owner);
int __seel_se_queue_io(struct seel_se *se, struct seel_apdu *apdu,
		       transceive_cb_t cb, void *context);
void __seel_se_list(DBusMessageIter *iter, void *user_data);
char *__seel_se_add(uint32_t se_idx, uint8_t ctrl_idx,
		    uint8_t se_type, uint8_t ctrl_type);
int __seel_se_remove(uint32_t se_idx, uint8_t ctrl_idx,
		     uint8_t ctrl_type);
int __seel_se_init(DBusConnection *conn);
void __seel_se_cleanup(void);

struct seel_apdu *__seel_apdu_build(uint8_t *apdu, size_t length, uint8_t channel);
void __seel_apdu_dump(uint8_t *apdu, size_t length);
void __seel_apdu_free(struct seel_apdu *apdu);
size_t __seel_apdu_length(struct seel_apdu *apdu);
uint8_t *__seel_apdu_data(struct seel_apdu *apdu);
struct seel_apdu *__seel_apdu_open_logical_channel(void);
struct seel_apdu *__seel_apdu_close_logical_channel(uint8_t channel);
struct seel_apdu *__seel_apdu_select_aid(uint8_t channel, uint8_t *aid, size_t aid_length);
struct seel_apdu *__seel_apdu_get_all_gp_data(void);
struct seel_apdu *__seel_apdu_get_next_gp_data(size_t length);
struct seel_apdu *__seel_apdu_get_refresh_gp_data(void);
int __seel_apdu_resp_status(uint8_t *apdu, size_t apdu_length);

struct seel_channel *__seel_channel_add(struct seel_se *se,
					uint8_t channel,
					unsigned char *aid, size_t aid_len,
					bool basic);
void __seel_channel_remove(struct seel_channel *channel);
char *__seel_channel_get_path(struct seel_channel *channel);
uint8_t __seel_channel_get_channel(struct seel_channel *channel);
uint8_t *__seel_channel_get_aid(struct seel_channel *channel, size_t *aid_len);
struct seel_se *__seel_channel_get_se(struct seel_channel *channel);
bool __seel_channel_is_basic(struct seel_channel *channel);

gboolean __seel_ace_add(gpointer user_data);
int __seel_ace_remove(struct seel_se *se);
bool __seel_ace_apdu_allowed(struct seel_channel *channel, uint8_t *app_hash,
			     uint8_t *apdu, size_t apdu_len);
int __seel_ace_init(void);
void __seel_ace_cleanup(void);

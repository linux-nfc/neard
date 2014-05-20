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
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <gdbus.h>

#include "driver.h"
#include "seel.h"

#define MAX_AID_LEN 16
#define MIN_AID_LEN 5

#define APP_HASH_LEN 20

#define GP_AID_LEN 9
uint8_t gp_aid[] = {0xA0, 0x00, 0x00, 0x01,
			0x51, 0x41, 0x43, 0x4C, 0x00 };

/* Data Object Tags */
#define AID_REF_DO_ALL 0xC0
#define HASH_REF_DO    0xC1
#define AID_REF_DO     0x4F
#define REF_DO         0xE1
#define REF_AR_DO      0xE2
#define AR_DO          0xE3
#define APDU_AR_DO     0xD0
#define NFC_AR_DO      0xD1

#define APDU_STATUS_LEN 2
#define GET_ALL_DATA_CMD_LEN 2
#define GET_REFRESH_DATA_CMD_LEN 2
#define GET_REFRESH_DATA_TAG_LEN 1
#define GET_REFRESH_TAG_LEN 8

/* if ((APDU_header & rule->mask) == rule->header) then APDU is allowed */
struct seel_ace_apdu_rule {
	uint32_t header;
	uint32_t mask;
};

struct seel_ace_rule {
	uint8_t aid[MAX_AID_LEN];
	size_t aid_len;

	uint8_t hash[APP_HASH_LEN];
	size_t hash_len;

	uint8_t *apdu_rules;
	size_t apdu_rules_len;

	bool nfc_rule;
};

struct seel_ace {
	struct seel_se *se;

	size_t rules_length;
	size_t current_rules_length;
	uint8_t *rules_payload;

	uint8_t rules_tag[8];

	GSList *rules;
};

GHashTable *ace_hash;

static void free_rule(gpointer data)
{
	struct seel_ace_rule *rule = data;

	DBG("%p", rule);

	g_free(rule->apdu_rules);
	g_free(rule);
}

static void free_ace(gpointer data)
{
	struct seel_ace *ace = data;

	DBG("%p %p", ace, ace->rules);

	g_slist_free_full(ace->rules, free_rule);
	g_free(ace);
}

static void dump_rule(gpointer data, gpointer user_data)
{
	struct seel_ace_rule *rule = data;
	struct seel_ace_apdu_rule *apdu_rule;
	char aid[3 * MAX_AID_LEN + 1];
	char hash[3 * APP_HASH_LEN + 1];
	size_t i;

	DBG("ACE Rule:");

	if (rule->aid_len == 0) {
		DBG("  Hash: All SE applications");
	} else {
		for (i = 0; i < rule->aid_len; i++)
			sprintf(aid + (3 * i), "%02X ", rule->aid[i]);
		aid[3 * i] = 0;
		DBG("  AID [%zd]: %s", rule->aid_len, aid);
	}

	if (rule->hash_len == 0) {
		DBG("  Hash: All host applications");
	} else {
		for (i = 0; i < rule->hash_len; i++)
			sprintf(hash + (3 * i), "%02X ", rule->hash[i]);
		hash[3 * i] = 0;
		DBG("  Hash [%zd]: %s", rule->hash_len, hash);
	}

	if (rule->apdu_rules_len == 1) {
		DBG("  APDU: %s", rule->apdu_rules[0] ? "Always" : "Never");
	} else {
		uint8_t *header, *mask;
		size_t n_rules;

		apdu_rule = (struct seel_ace_apdu_rule *)rule->apdu_rules;
		n_rules = rule->apdu_rules_len /
				sizeof(struct seel_ace_apdu_rule);

		DBG("  APDU rules (%zd)", n_rules);
		for (i = 0; i < n_rules; i++) {
			header = (uint8_t *)&apdu_rule->header;
			mask = (uint8_t *)&apdu_rule->mask;
			DBG("    header 0x%02x:0x%02x:0x%02x:0x%02x "
			    "mask 0x%02x:0x%02x:0x%02x:0x%02x",
				header[0], header[1], header[2], header[3],
				mask[0], mask[1], mask[2], mask[3]);
			apdu_rule++;
		}
	}

	DBG("  NFC: %s", rule->nfc_rule ? "Always" : "Never");

}

static void dump_ace(struct seel_ace *ace)
{
	DBG("ACE Tag [0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x]",
	ace->rules_tag[0], ace->rules_tag[1], ace->rules_tag[2], ace->rules_tag[3],
	ace->rules_tag[4], ace->rules_tag[5], ace->rules_tag[6], ace->rules_tag[7]);

	g_slist_foreach(ace->rules, dump_rule, NULL);
}

static int build_ref(struct seel_ace_rule *ace_rule,
			uint8_t *rule, size_t rule_length)
{
	uint8_t *rule_ptr;
	size_t remaining, do_length;

	remaining = rule_length;
	rule_ptr = rule;
	while (remaining) {

		switch (rule_ptr[0]) {
		case AID_REF_DO:
			do_length = rule_ptr[1];
			DBG("AID_REF_DO %zd", do_length);
			rule_ptr += 2;

			if (remaining < do_length)
				return -EINVAL;

			if (do_length > MAX_AID_LEN)
				return -EINVAL;

			memcpy(ace_rule->aid, rule_ptr, do_length);
			ace_rule->aid_len = do_length;

			remaining -= do_length + 2;
			rule_ptr += do_length;

			break;

		case HASH_REF_DO:
			do_length = rule_ptr[1];
			DBG("HASH_REF_DO %zd", do_length);
			rule_ptr += 2;

			if (remaining < do_length)
				return -EINVAL;

			if (do_length > APP_HASH_LEN)
				return -EINVAL;

			memcpy(ace_rule->hash, rule_ptr, do_length);
			ace_rule->hash_len = do_length;

			remaining -= do_length + 2;
			rule_ptr += do_length;

			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int build_ar(struct seel_ace_rule *ace_rule,
			uint8_t *rule, size_t rule_length)
{
	uint8_t *rule_ptr;
	size_t remaining, do_length;

	remaining = rule_length;
	rule_ptr = rule;
	while (remaining) {

		switch (rule_ptr[0]) {
		case APDU_AR_DO:
			do_length = rule_ptr[1];
			DBG("APDU_AR_DO %zd", do_length);
			rule_ptr += 2;

			if (remaining < do_length)
				return -EINVAL;

			ace_rule->apdu_rules = g_try_malloc0(do_length);
			if (!ace_rule->apdu_rules)
				return -ENOMEM;

			memcpy(ace_rule->apdu_rules, rule_ptr, do_length);
			ace_rule->apdu_rules_len = do_length;

			remaining -= do_length + 2;
			rule_ptr += do_length;

			break;

		case NFC_AR_DO:
			do_length = rule_ptr[1];
			DBG("NFC_AR_DO %zd", do_length);
			rule_ptr += 2;

			if (do_length != 1)
				return -EINVAL;

			ace_rule->nfc_rule = !!rule_ptr[0];

			remaining -= do_length + 2;
			rule_ptr += do_length;

			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}

static struct seel_ace_rule *build_rule(struct seel_ace *ace,
				uint8_t *rule, size_t rule_length)
{
	struct seel_ace_rule *ace_rule;
	uint8_t *rule_ptr;
	size_t remaining, do_length;
	int err;

	DBG("");

	ace_rule = g_try_malloc0(sizeof(struct seel_ace_rule));
	if (!ace_rule)
		return NULL;

	remaining = rule_length;
	rule_ptr = rule;
	while (remaining) {

		switch (rule_ptr[0]) {
		case REF_DO:
			do_length = rule_ptr[1];
			DBG("REF_DO %zd", do_length);
			rule_ptr += 2;

			err = build_ref(ace_rule, rule_ptr, do_length);
			if (err)
				goto error;

			remaining -= do_length + 2;
			rule_ptr += do_length;

			break;

		case AR_DO:
			do_length = rule_ptr[1];
			DBG("AR_DO %zd", do_length);
			rule_ptr += 2;

			err = build_ar(ace_rule, rule_ptr, do_length);
			if (err)
				goto error;

			remaining -= do_length + 2;
			rule_ptr += do_length;

			break;
		default:
			goto error;
		}
	}

	return ace_rule;

error:
	free_rule(ace_rule);
	return NULL;
}

static int build_ace_rules(struct seel_ace *ace,
			uint8_t *rules, size_t rules_length)
{
	struct seel_ace_rule *rule;
	uint8_t *rule_ptr;
	size_t remaining = rules_length, ref_ar_do_length;
	int err;

	DBG("");

	err = 0;
	remaining = rules_length;
	rule_ptr = rules;
	while (remaining) {
		if (rule_ptr[0] != REF_AR_DO) {
			rule_ptr++;
			remaining--;
			continue;
		}

		ref_ar_do_length = rule_ptr[1];
		/* Tag + Length + value length */
		remaining -= ref_ar_do_length + 2;
		rule_ptr += 2;

		DBG("REF_AR_DO %zd bytes", ref_ar_do_length);

		rule = build_rule(ace, rule_ptr, ref_ar_do_length);
		if (!rule) {
			err = -EINVAL;
			break;
		}

		ace->rules = g_slist_append(ace->rules, rule);

		rule_ptr += ref_ar_do_length;
	}

	return err;
}

static int ace_rule_length(uint8_t *apdu, size_t apdu_length,
						size_t *length_length)
{
	size_t length;

	if (apdu_length < 3)
		return -EINVAL;

	length = apdu[2];
	*length_length = 1;

	/*
	 * BER: If length bit 8 is one, bit [0..7] is the number
	 * of bytes used for encoding the length.
	 */
	if (length & 0x80) {
		size_t _length = length & 0x7f, i, base;

		DBG("%zd", _length);

		if (apdu_length < 3 + _length)
			return -EINVAL;

		length = 0;
		base = 1 << 8 * _length;
		for (i = 0; i < _length; i++) {
			base >>= 8;
			length += apdu[3 + i] * base;
		}

		*length_length = _length + 1;
	}

	DBG("length 0x%zx", length);

	return length;
}

static void get_next_gp_data(struct seel_ace *ace);

static void get_next_gp_data_cb(void *context,
			uint8_t *apdu, size_t apdu_length,
			int err)
{
	struct seel_ace *ace  = context;
	size_t payload_length;

	DBG("Current %zd Total %zd Got %zd",
		ace->current_rules_length, ace->rules_length, apdu_length);

	if (err)
		goto out;

	payload_length = apdu_length - APDU_STATUS_LEN;

	if (ace->current_rules_length + payload_length > ace->rules_length)
		goto out;

	memcpy(ace->rules_payload + ace->current_rules_length,
						apdu, payload_length);
	ace->current_rules_length += apdu_length - APDU_STATUS_LEN;

	if (ace->current_rules_length < ace->rules_length)
		return get_next_gp_data(ace);

	if (build_ace_rules(ace, ace->rules_payload, ace->rules_length))
		goto out;

	dump_ace(ace);

	g_hash_table_replace(ace_hash, ace->se, ace);

out:
	g_free(ace->rules_payload);

	return;
}

static void get_next_gp_data(struct seel_ace *ace)
{
	struct seel_apdu *get_next_gp_data;
	size_t req_length;
	int err;

	if (ace->rules_length - ace->current_rules_length < 0x100)
		req_length = ace->rules_length - ace->current_rules_length;
	else
		req_length = 0;

	get_next_gp_data = __seel_apdu_get_next_gp_data(req_length);
	if (!get_next_gp_data) {
		g_free(ace->rules_payload);
		return;
	}

	err = __seel_se_queue_io(ace->se, get_next_gp_data,
					get_next_gp_data_cb, ace);
	if (err < 0) {
		near_error("GET NEXT ALL err %d", err);
		return;
	}

	return;
}

static void get_all_gp_data_cb(void *context,
			uint8_t *apdu, size_t apdu_length,
			int err)
{
	struct seel_ace *ace = context;
	size_t length_length, payload_length;
	int rule_length;

	DBG("");

	if (err)
		return;

	rule_length = ace_rule_length(apdu, apdu_length, &length_length);
	if (rule_length < 0)
		return;

	if (apdu_length > GET_ALL_DATA_CMD_LEN + length_length +
					rule_length + APDU_STATUS_LEN)
		return;

	payload_length = apdu_length - GET_ALL_DATA_CMD_LEN -
					length_length - APDU_STATUS_LEN;

	DBG("Received %zd bytes of payload", payload_length);

	if (payload_length < (size_t)rule_length) {
		ace->rules_length = rule_length;
		ace->current_rules_length = payload_length;
		ace->rules_payload = g_try_malloc0(rule_length);
		if (!ace->rules_payload)
			return;

		memcpy(ace->rules_payload,
				apdu + GET_ALL_DATA_CMD_LEN + length_length,
								payload_length);

		return get_next_gp_data(ace);
	}

	if (build_ace_rules(ace, apdu + GET_ALL_DATA_CMD_LEN + length_length,
								payload_length))
		return;

	dump_ace(ace);

	g_hash_table_replace(ace_hash, ace->se, ace);

	return;
}

static void get_refresh_gp_data_cb(void *context,
			uint8_t *apdu, size_t apdu_length,
			int err)
{
	struct seel_se *se = context;
	struct seel_ace *ace;
	struct seel_apdu *get_all_gp_data;

	DBG("");

	if (err)
		return;

	if (apdu_length != GET_REFRESH_DATA_CMD_LEN + GET_REFRESH_DATA_TAG_LEN
				 + GET_REFRESH_TAG_LEN + APDU_STATUS_LEN)
		return;

	if (apdu[0] != 0xDF || apdu[1] != 0x20 || apdu[2] != 0x08)
		return;

	ace = g_try_malloc0(sizeof(struct seel_ace));
	if (!ace)
		return;

	ace->se = se;

	memcpy(ace->rules_tag, apdu + GET_REFRESH_DATA_CMD_LEN
			+ GET_REFRESH_DATA_TAG_LEN, GET_REFRESH_TAG_LEN);

	get_all_gp_data = __seel_apdu_get_all_gp_data();
	if (!get_all_gp_data)
		return;

	err = __seel_se_queue_io(se, get_all_gp_data, get_all_gp_data_cb, ace);
	if (err < 0) {
		near_error("GET DATA ALL err %d", err);
		return;
	}

	return ;
}

static void select_gp_aid_cb(void *context,
			uint8_t *apdu, size_t apdu_length,
			int err)
{
	struct seel_se *se = context;
	struct seel_apdu *get_refresh_gp_data;

	DBG("");

	if (err)
		return;

	get_refresh_gp_data = __seel_apdu_get_refresh_gp_data();
	if (!get_refresh_gp_data)
		return;

	err = __seel_se_queue_io(se, get_refresh_gp_data, get_refresh_gp_data_cb, se);
	if (err < 0) {
		near_error("GET REFRESH DATA err %d", err);
		return;
	}

	return ;
}

gboolean __seel_ace_add(gpointer user_data)
{
	struct seel_se *se = user_data;
	struct seel_apdu *select_gp_aid;
	int err;

	DBG("");

	select_gp_aid = __seel_apdu_select_aid(0, gp_aid, GP_AID_LEN);
	if (!select_gp_aid)
		return FALSE;

	/* Send the GP AID selection APDU */
	err = __seel_se_queue_io(se, select_gp_aid, select_gp_aid_cb, se);
	if (err < 0) {
		near_error("GP AID err %d", err);
		return FALSE;
	}

	return FALSE;
}

int __seel_ace_remove(struct seel_se *se)
{
	DBG("%p", se);

	if (!g_hash_table_remove(ace_hash, se))
		return -ENODEV;

	return 0;
}

static struct seel_ace_rule *find_specific_rule(struct seel_ace *ace,
						uint8_t *aid, size_t aid_len,
						uint8_t *hash)
{
	GSList *list;

	DBG("%zd", aid_len);

	if (!hash || !aid)
		return false;

	for (list = ace->rules; list; list = list->next) {
		struct seel_ace_rule *rule = list->data;

		if (rule->aid_len != aid_len)
			continue;

		if (rule->hash_len != APP_HASH_LEN)
			continue;

		if (!memcmp(rule->aid, aid, aid_len) &&
				!memcmp(rule->hash, hash, APP_HASH_LEN)) {
			dump_rule(rule, NULL);
			return rule;
		}
	}

	return NULL;
}

static bool find_specific_rule_for_aid(struct seel_ace *ace,
					uint8_t *aid, size_t aid_len)
{
	GSList *list;

	DBG("%zd", aid_len);

	if (!aid)
		return false;

	for (list = ace->rules; list; list = list->next) {
		struct seel_ace_rule *rule = list->data;

		if (rule->aid_len != aid_len)
			continue;

		if (rule->hash_len != APP_HASH_LEN)
			continue;

		if (!memcmp(rule->aid, aid, aid_len)) {
			dump_rule(rule, NULL);
			return true;
		}
	}

	return false;
}

static struct seel_ace_rule *find_generic_rule_for_aid(struct seel_ace *ace,
						uint8_t *aid, size_t aid_len)

{
	GSList *list;

	DBG("%zd", aid_len);

	if (!aid)
		return false;

	for (list = ace->rules; list; list = list->next) {
		struct seel_ace_rule *rule = list->data;

		if (rule->aid_len != aid_len)
			continue;

		/* This is a specific rule */
		if (rule->hash_len)
			continue;

		if (!memcmp(rule->aid, aid, aid_len)) {
			dump_rule(rule, NULL);
			return rule;
		}
	}

	return NULL;
}

static struct seel_ace_rule *find_generic_rule_for_hash(struct seel_ace *ace,
								uint8_t *hash)
{
	GSList *list;

	DBG("");

	if (!hash)
		return false;

	for (list = ace->rules; list; list = list->next) {
		struct seel_ace_rule *rule = list->data;

		/* This is a generic hash rule */
		if (rule->hash_len != APP_HASH_LEN)
			continue;

		/* This is a specific AID rule */
		if (rule->aid_len)
			continue;

		if (!memcmp(rule->hash, hash, APP_HASH_LEN)) {
			dump_rule(rule, NULL);
			return rule;
		}
	}

	return NULL;
}

static struct seel_ace_rule *find_generic_rule(struct seel_ace *ace)
{
	GSList *list;

	DBG("");

	for (list = ace->rules; list; list = list->next) {
		struct seel_ace_rule *rule = list->data;

		if (rule->hash_len || rule->aid_len)
			continue;

		dump_rule(rule, NULL);
		return rule;
	}

	return NULL;
}

static bool apdu_allowed(struct seel_ace_rule *rule,
				uint8_t *apdu, size_t apdu_len)
{
	size_t i, n_rules;
	uint32_t apdu_header;
	struct seel_ace_apdu_rule *apdu_rule;

	if (rule->apdu_rules_len == 1)
		return rule->apdu_rules[0] ? true : false;

	n_rules = rule->apdu_rules_len /
				sizeof(struct seel_ace_apdu_rule);
	apdu_header = *((uint32_t *) apdu);
	apdu_rule = (struct seel_ace_apdu_rule *)rule->apdu_rules;

	for (i = 0; i < n_rules; i++) {
		if ((apdu_header & apdu_rule->mask) == apdu_rule->header)
			return true;

		apdu_rule++;
	}

	return false;
}

bool __seel_ace_apdu_allowed(struct seel_channel *channel, uint8_t *hash,
				uint8_t *apdu, size_t apdu_len)
{
	struct seel_se *se;
	struct seel_ace *ace;
	struct seel_ace_rule *rule;
	uint8_t *aid;
	size_t aid_len;

	DBG("%zd", apdu_len);

	/* XXX Do we need to do some filtering on the basic channel ?*/
	if (__seel_channel_is_basic(channel))
	   return true;

	se = __seel_channel_get_se(channel);
	if (!se)
		return false;

	ace = g_hash_table_lookup(ace_hash, se);
	if (!ace)
		return false;

	if (!ace->rules)
		return false;

	aid = __seel_channel_get_aid(channel, &aid_len);
	if (!aid)
		return false;

	/* a) Try to find a specific rule */
	rule = find_specific_rule(ace, aid, aid_len, hash);
	if (rule)
		return apdu_allowed(rule, apdu, apdu_len) ? true : false;

	/*
	 * a') Try to find a specific rule for another hash
	 * If there is such a rule, then access is denied for the
	 * current hash: Specific rule precedence over generic ones.
	 */
	if (find_specific_rule_for_aid(ace, aid, aid_len))
		return false;

	/* b) Search for a generic rule for this specific AID */
	rule = find_generic_rule_for_aid(ace, aid, aid_len);
	if (rule)
		return apdu_allowed(rule, apdu, apdu_len) ? true : false;

	/* c) Search for a generic rule for this specific hash */
	rule = find_generic_rule_for_hash(ace, hash);
	if (rule)
		return apdu_allowed(rule, apdu, apdu_len) ? true : false;

	/* d) Search for a generic rule: All apps, all AIDs */
	rule = find_generic_rule(ace);
	if (rule)
		return apdu_allowed(rule, apdu, apdu_len) ? true : false;

	return false;
}

int __seel_ace_init(void)
{
	DBG("");

	ace_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_ace);
	return 0;
}

void __seel_ace_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(ace_hash);
	ace_hash = NULL;
}

/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "src/shared/att.h"
#include "lib/uuid.h"
#include "src/shared/gatt-helpers.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"

#include <assert.h>
#include <limits.h>

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define UUID_BYTES (BT_GATT_UUID_SIZE * sizeof(uint8_t))

#define GATT_SVC_UUID	0x1801
#define SVC_CHNGD_UUID	0x2a05

struct bt_gatt_client {
	struct bt_att *att;
	int ref_count;

	bt_gatt_client_callback_t ready_callback;
	bt_gatt_client_destroy_func_t ready_destroy;
	void *ready_data;

	bt_gatt_client_service_changed_callback_t svc_chngd_callback;
	bt_gatt_client_destroy_func_t svc_chngd_destroy;
	void *svc_chngd_data;

	bt_gatt_client_debug_func_t debug_callback;
	bt_gatt_client_destroy_func_t debug_destroy;
	void *debug_data;

	struct gatt_db *db;
	bool in_init;
	bool ready;

	/* Queue of long write requests. An error during "prepare write"
	 * requests can result in a cancel through "execute write". To prevent
	 * cancelation of prepared writes to the wrong attribute and multiple
	 * requests to the same attribute that may result in a corrupted final
	 * value, we avoid interleaving prepared writes.
	 */
	struct queue *long_write_queue;
	bool in_long_write;

	/* List of registered disconnect/notification/indication callbacks */
	struct queue *notify_list;
	struct queue *notify_chrcs;
	int next_reg_id;
	unsigned int disc_id, notify_id, ind_id;

	/* Handles of the GATT Service and the Service Changed characteristic
	 * value handle. These will have the value 0 if they are not present on
	 * the remote peripheral.
	 */
	unsigned int svc_chngd_ind_id;
	struct queue *svc_chngd_queue;  /* Queued service changed events */
	bool in_svc_chngd;
};

struct notify_chrc {
	uint16_t value_handle;
	uint16_t ccc_handle;
	uint16_t properties;
	int notify_count;  /* Reference count of registered notify callbacks */

	/* Pending calls to register_notify are queued here so that they can be
	 * processed after a write that modifies the CCC descriptor.
	 */
	struct queue *reg_notify_queue;
	unsigned int ccc_write_id;
};

struct notify_data {
	struct bt_gatt_client *client;
	bool invalid;
	unsigned int id;
	int ref_count;
	struct notify_chrc *chrc;
	bt_gatt_client_notify_id_callback_t callback;
	bt_gatt_client_notify_callback_t notify;
	void *user_data;
	bt_gatt_client_destroy_func_t destroy;
};

static struct notify_data *notify_data_ref(struct notify_data *notify_data)
{
	__sync_fetch_and_add(&notify_data->ref_count, 1);

	return notify_data;
}

static void notify_data_unref(void *data)
{
	struct notify_data *notify_data = data;

	if (__sync_sub_and_fetch(&notify_data->ref_count, 1))
		return;

	if (notify_data->destroy)
		notify_data->destroy(notify_data->user_data);

	free(notify_data);
}

static void find_ccc(struct gatt_db_attribute *attr, void *user_data)
{
	struct gatt_db_attribute **ccc_ptr = user_data;
	bt_uuid_t uuid;

	if (*ccc_ptr)
		return;

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);

	if (bt_uuid_cmp(&uuid, gatt_db_attribute_get_type(attr)))
		return;

	*ccc_ptr = attr;
}

static struct notify_chrc *notify_chrc_create(struct bt_gatt_client *client,
							uint16_t value_handle)
{
	struct gatt_db_attribute *attr, *ccc;
	struct notify_chrc *chrc;
	bt_uuid_t uuid;
	uint8_t properties;

	/* Check that chrc_value_handle belongs to a known characteristic */
	attr = gatt_db_get_attribute(client->db, value_handle - 1);
	if (!attr)
		return NULL;

	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	if (bt_uuid_cmp(&uuid, gatt_db_attribute_get_type(attr)))
		return NULL;

	if (!gatt_db_attribute_get_char_data(attr, NULL, NULL,
							&properties, NULL))
			return NULL;

	/* Find the CCC characteristic */
	ccc = NULL;
	gatt_db_service_foreach_desc(attr, find_ccc, &ccc);
	if (!ccc)
		return NULL;

	chrc = new0(struct notify_chrc, 1);
	if (!chrc)
		return NULL;

	chrc->reg_notify_queue = queue_new();
	if (!chrc->reg_notify_queue) {
		free(chrc);
		return NULL;
	}

	chrc->value_handle = value_handle;
	chrc->ccc_handle = gatt_db_attribute_get_handle(ccc);
	chrc->properties = properties;

	queue_push_tail(client->notify_chrcs, chrc);

	return chrc;
}

static void notify_chrc_free(void *data)
{
	struct notify_chrc *chrc = data;

	queue_destroy(chrc->reg_notify_queue, notify_data_unref);
	free(chrc);
}

static bool match_notify_data_id(const void *a, const void *b)
{
	const struct notify_data *notify_data = a;
	unsigned int id = PTR_TO_UINT(b);

	return notify_data->id == id;
}

struct handle_range {
	uint16_t start;
	uint16_t end;
};

static bool match_notify_data_handle_range(const void *a, const void *b)
{
	const struct notify_data *notify_data = a;
	struct notify_chrc *chrc = notify_data->chrc;
	const struct handle_range *range = b;

	return chrc->value_handle >= range->start &&
					chrc->value_handle <= range->end;
}

static bool match_notify_chrc_handle_range(const void *a, const void *b)
{
	const struct notify_chrc *chrc = a;
	const struct handle_range *range = b;

	return chrc->value_handle >= range->start &&
					chrc->value_handle <= range->end;
}

static void gatt_client_remove_all_notify_in_range(
				struct bt_gatt_client *client,
				uint16_t start_handle, uint16_t end_handle)
{
	struct handle_range range;

	range.start = start_handle;
	range.end = end_handle;

	queue_remove_all(client->notify_list, match_notify_data_handle_range,
						&range, notify_data_unref);
}

static void gatt_client_remove_notify_chrcs_in_range(
				struct bt_gatt_client *client,
				uint16_t start_handle, uint16_t end_handle)
{
	struct handle_range range;

	range.start = start_handle;
	range.end = end_handle;

	queue_remove_all(client->notify_chrcs, match_notify_chrc_handle_range,
						&range, notify_chrc_free);
}

struct discovery_op;

typedef void (*discovery_op_complete_func_t)(struct discovery_op *op,
							bool success,
							uint8_t att_ecode);
typedef void (*discovery_op_fail_func_t)(struct discovery_op *op);

struct discovery_op {
	struct bt_gatt_client *client;
	struct queue *pending_svcs;
	struct queue *pending_chrcs;
	struct queue *tmp_queue;
	struct gatt_db_attribute *cur_svc;
	bool success;
	uint16_t start;
	uint16_t end;
	int ref_count;
	discovery_op_complete_func_t complete_func;
	discovery_op_fail_func_t failure_func;
};

static void discovery_op_free(struct discovery_op *op)
{
	queue_destroy(op->pending_svcs, NULL);
	queue_destroy(op->pending_chrcs, free);
	queue_destroy(op->tmp_queue, NULL);
	free(op);
}

static struct discovery_op *discovery_op_create(struct bt_gatt_client *client,
				uint16_t start, uint16_t end,
				discovery_op_complete_func_t complete_func,
				discovery_op_fail_func_t failure_func)
{
	struct discovery_op *op;

	op = new0(struct discovery_op, 1);
	if (!op)
		return NULL;

	op->pending_svcs = queue_new();
	if (!op->pending_svcs)
		goto fail;

	op->pending_chrcs = queue_new();
	if (!op->pending_chrcs)
		goto fail;

	op->tmp_queue = queue_new();
	if (!op->tmp_queue)
		goto fail;

	op->client = client;
	op->complete_func = complete_func;
	op->failure_func = failure_func;
	op->start = start;
	op->end = end;

	return op;

fail:
	discovery_op_free(op);
	return NULL;
}

static struct discovery_op *discovery_op_ref(struct discovery_op *op)
{
	__sync_fetch_and_add(&op->ref_count, 1);

	return op;
}

static void discovery_op_unref(void *data)
{
	struct discovery_op *op = data;

	if (__sync_sub_and_fetch(&op->ref_count, 1))
		return;

	if (!op->success)
		op->failure_func(op);

	discovery_op_free(op);
}

static void discover_chrcs_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data);

static void discover_incl_cb(bool success, uint8_t att_ecode,
				struct bt_gatt_result *result, void *user_data)
{
	struct discovery_op *op = user_data;
	struct bt_gatt_client *client = op->client;
	struct bt_gatt_iter iter;
	struct gatt_db_attribute *attr, *tmp;
	uint16_t handle, start, end;
	uint128_t u128;
	bt_uuid_t uuid;
	char uuid_str[MAX_LEN_UUID_STR];
	unsigned int includes_count, i;

	if (!success) {
		if (att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND)
			goto next;

		goto failed;
	}

	/* Get the currently processed service */
	attr = op->cur_svc;
	if (!attr)
		goto failed;

	if (!result || !bt_gatt_iter_init(&iter, result))
		goto failed;

	includes_count = bt_gatt_result_included_count(result);
	if (includes_count == 0)
		goto failed;

	util_debug(client->debug_callback, client->debug_data,
						"Included services found: %u",
						includes_count);

	for (i = 0; i < includes_count; i++) {
		if (!bt_gatt_iter_next_included_service(&iter, &handle, &start,
							&end, u128.data))
			break;

		bt_uuid128_create(&uuid, u128);

		/* Log debug message */
		bt_uuid_to_string(&uuid, uuid_str, sizeof(uuid_str));
		util_debug(client->debug_callback, client->debug_data,
				"handle: 0x%04x, start: 0x%04x, end: 0x%04x,"
				"uuid: %s", handle, start, end, uuid_str);

		tmp = gatt_db_get_attribute(client->db, start);
		if (!tmp)
			goto failed;

		tmp = gatt_db_service_add_included(attr, tmp);
		if (!tmp)
			goto failed;

		/*
		 * GATT requires that all include definitions precede
		 * characteristic declarations. Based on the order we're adding
		 * these entries, the correct handle must be assigned to the new
		 * attribute.
		 */
		if (gatt_db_attribute_get_handle(tmp) != handle)
			goto failed;
	}

next:
	/* Move on to the next service */
	attr = queue_pop_head(op->pending_svcs);
	if (!attr) {
		struct queue *tmp_queue;

		tmp_queue = op->pending_svcs;
		op->pending_svcs = op->tmp_queue;
		op->tmp_queue = tmp_queue;

		/*
		 * We have processed all include definitions. Move on to
		 * characteristics.
		 */
		attr = queue_pop_head(op->pending_svcs);
		if (!attr)
			goto failed;

		if (!gatt_db_attribute_get_service_handles(attr, &start, &end))
			goto failed;

		op->cur_svc = attr;
		if (bt_gatt_discover_characteristics(client->att,
							start, end,
							discover_chrcs_cb,
							discovery_op_ref(op),
							discovery_op_unref))
			return;

		util_debug(client->debug_callback, client->debug_data,
				"Failed to start characteristic discovery");
		discovery_op_unref(op);
		goto failed;
	}

	queue_push_tail(op->tmp_queue, attr);
	op->cur_svc = attr;
	if (!gatt_db_attribute_get_service_handles(attr, &start, &end))
		goto failed;

	if (bt_gatt_discover_included_services(client->att, start, end,
							discover_incl_cb,
							discovery_op_ref(op),
							discovery_op_unref))
		return;

	util_debug(client->debug_callback, client->debug_data,
					"Failed to start included discovery");
	discovery_op_unref(op);

failed:
	op->success = false;
	op->complete_func(op, false, att_ecode);
}

struct chrc {
	uint16_t start_handle;
	uint16_t end_handle;
	uint16_t value_handle;
	uint8_t properties;
	bt_uuid_t uuid;
};

static void discover_descs_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data);

static bool discover_descs(struct discovery_op *op, bool *discovering)
{
	struct bt_gatt_client *client = op->client;
	struct gatt_db_attribute *attr;
	struct chrc *chrc_data;
	uint16_t desc_start;

	*discovering = false;

	while ((chrc_data = queue_pop_head(op->pending_chrcs))) {
		attr = gatt_db_service_add_characteristic(op->cur_svc,
							&chrc_data->uuid, 0,
							chrc_data->properties,
							NULL, NULL, NULL);

		if (!attr)
			goto failed;

		if (gatt_db_attribute_get_handle(attr) !=
							chrc_data->value_handle)
			goto failed;

		desc_start = chrc_data->value_handle + 1;

		if (desc_start > chrc_data->end_handle) {
			free(chrc_data);
			continue;
		}

		if (bt_gatt_discover_descriptors(client->att, desc_start,
							chrc_data->end_handle,
							discover_descs_cb,
							discovery_op_ref(op),
							discovery_op_unref)) {
			*discovering = true;
			goto done;
		}

		util_debug(client->debug_callback, client->debug_data,
					"Failed to start descriptor discovery");
		discovery_op_unref(op);

		goto failed;
	}

done:
	free(chrc_data);
	return true;

failed:
	free(chrc_data);
	return false;
}

static void discover_descs_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data)
{
	struct discovery_op *op = user_data;
	struct bt_gatt_client *client = op->client;
	struct bt_gatt_iter iter;
	struct gatt_db_attribute *attr;
	uint16_t handle, start, end;
	uint128_t u128;
	bt_uuid_t uuid;
	char uuid_str[MAX_LEN_UUID_STR];
	unsigned int desc_count;
	bool discovering;

	if (!success) {
		if (att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND) {
			success = true;
			goto next;
		}

		goto done;
	}

	if (!result || !bt_gatt_iter_init(&iter, result))
		goto failed;

	desc_count = bt_gatt_result_descriptor_count(result);
	if (desc_count == 0)
		goto failed;

	util_debug(client->debug_callback, client->debug_data,
					"Descriptors found: %u", desc_count);

	while (bt_gatt_iter_next_descriptor(&iter, &handle, u128.data)) {
		bt_uuid128_create(&uuid, u128);

		/* Log debug message */
		bt_uuid_to_string(&uuid, uuid_str, sizeof(uuid_str));
		util_debug(client->debug_callback, client->debug_data,
						"handle: 0x%04x, uuid: %s",
						handle, uuid_str);

		attr = gatt_db_service_add_descriptor(op->cur_svc, &uuid, 0,
							NULL, NULL, NULL);
		if (!attr)
			goto failed;

		if (gatt_db_attribute_get_handle(attr) != handle)
			goto failed;
	}

	if (!discover_descs(op, &discovering))
		goto failed;

	if (discovering)
		return;

next:
	/* Done with the current service */
	gatt_db_service_set_active(op->cur_svc, true);

	attr = queue_pop_head(op->pending_svcs);
	if (!attr)
		goto done;

	if (!gatt_db_attribute_get_service_handles(attr, &start, &end))
		goto failed;

	/* Move on to the next service */
	op->cur_svc = attr;
	if (bt_gatt_discover_characteristics(client->att, start, end,
							discover_chrcs_cb,
							discovery_op_ref(op),
							discovery_op_unref))
		return;

	util_debug(client->debug_callback, client->debug_data,
				"Failed to start characteristic discovery");
	discovery_op_unref(op);

failed:
	success = false;

done:
	op->success = success;
	op->complete_func(op, success, att_ecode);
}

static void discover_chrcs_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data)
{
	struct discovery_op *op = user_data;
	struct bt_gatt_client *client = op->client;
	struct bt_gatt_iter iter;
	struct gatt_db_attribute *attr;
	struct chrc *chrc_data;
	uint16_t start, end, value;
	uint8_t properties;
	uint128_t u128;
	bt_uuid_t uuid;
	char uuid_str[MAX_LEN_UUID_STR];
	unsigned int chrc_count;
	bool discovering;

	if (!success) {
		if (att_ecode == BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND) {
			success = true;
			goto next;
		}

		goto done;
	}

	if (!op->cur_svc || !result || !bt_gatt_iter_init(&iter, result))
		goto failed;

	chrc_count = bt_gatt_result_characteristic_count(result);
	util_debug(client->debug_callback, client->debug_data,
				"Characteristics found: %u", chrc_count);

	if (chrc_count == 0)
		goto failed;

	while (bt_gatt_iter_next_characteristic(&iter, &start, &end, &value,
						&properties, u128.data)) {
		bt_uuid128_create(&uuid, u128);

		/* Log debug message */
		bt_uuid_to_string(&uuid, uuid_str, sizeof(uuid_str));
		util_debug(client->debug_callback, client->debug_data,
				"start: 0x%04x, end: 0x%04x, value: 0x%04x, "
				"props: 0x%02x, uuid: %s",
				start, end, value, properties, uuid_str);

		chrc_data = new0(struct chrc, 1);
		if (!chrc_data)
			goto failed;

		chrc_data->start_handle = start;
		chrc_data->end_handle = end;
		chrc_data->value_handle = value;
		chrc_data->properties = properties;
		chrc_data->uuid = uuid;

		queue_push_tail(op->pending_chrcs, chrc_data);
	}

	/*
	 * Sequentially discover descriptors for each characteristic and insert
	 * the characteristics into the database as we proceed.
	 */
	if (!discover_descs(op, &discovering))
		goto failed;

	if (discovering)
		return;

next:
	/* Done with the current service */
	gatt_db_service_set_active(op->cur_svc, true);

	attr = queue_pop_head(op->pending_svcs);
	if (!attr)
		goto done;

	if (!gatt_db_attribute_get_service_handles(attr, &start, &end))
		goto failed;

	/* Move on to the next service */
	op->cur_svc = attr;
	if (bt_gatt_discover_characteristics(client->att, start, end,
							discover_chrcs_cb,
							discovery_op_ref(op),
							discovery_op_unref))
		return;

	util_debug(client->debug_callback, client->debug_data,
				"Failed to start characteristic discovery");
	discovery_op_unref(op);

failed:
	success = false;

done:
	op->success = success;
	op->complete_func(op, success, att_ecode);
}

static void discover_secondary_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data)
{
	struct discovery_op *op = user_data;
	struct bt_gatt_client *client = op->client;
	struct bt_gatt_iter iter;
	struct gatt_db_attribute *attr;
	uint16_t start, end;
	uint128_t u128;
	bt_uuid_t uuid;
	char uuid_str[MAX_LEN_UUID_STR];

	if (!success) {
		util_debug(client->debug_callback, client->debug_data,
					"Secondary service discovery failed."
					" ATT ECODE: 0x%02x", att_ecode);
		switch (att_ecode) {
		case BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND:
		case BT_ATT_ERROR_UNSUPPORTED_GROUP_TYPE:
			goto next;
		default:
			goto done;
		}
	}

	if (!result || !bt_gatt_iter_init(&iter, result)) {
		success = false;
		goto done;
	}

	util_debug(client->debug_callback, client->debug_data,
					"Secondary services found: %u",
					bt_gatt_result_service_count(result));

	while (bt_gatt_iter_next_service(&iter, &start, &end, u128.data)) {
		bt_uuid128_create(&uuid, u128);

		/* Log debug message */
		bt_uuid_to_string(&uuid, uuid_str, sizeof(uuid_str));
		util_debug(client->debug_callback, client->debug_data,
				"start: 0x%04x, end: 0x%04x, uuid: %s",
				start, end, uuid_str);

		/* Store the service */
		attr = gatt_db_insert_service(client->db, start, &uuid, false,
							end - start + 1);
		if (!attr) {
			util_debug(client->debug_callback, client->debug_data,
						"Failed to create service");
			success = false;
			goto done;
		}

		queue_push_tail(op->pending_svcs, attr);
	}

next:
	/* Sequentially discover included services */
	attr = queue_pop_head(op->pending_svcs);

	/* Complete with success if queue is empty */
	if (!attr)
		goto done;

	/*
	 * Store the service in the tmp queue to be reused during
	 * characteristics discovery later.
	 */
	queue_push_tail(op->tmp_queue, attr);
	op->cur_svc = attr;

	if (!gatt_db_attribute_get_service_handles(attr, &start, &end)) {
		success = false;
		goto done;
	}

	if (bt_gatt_discover_included_services(client->att, start, end,
							discover_incl_cb,
							discovery_op_ref(op),
							discovery_op_unref))
		return;

	util_debug(client->debug_callback, client->debug_data,
				"Failed to start included services discovery");
	discovery_op_unref(op);

done:
	op->success = success;
	op->complete_func(op, success, att_ecode);
}

static void discover_primary_cb(bool success, uint8_t att_ecode,
						struct bt_gatt_result *result,
						void *user_data)
{
	struct discovery_op *op = user_data;
	struct bt_gatt_client *client = op->client;
	struct bt_gatt_iter iter;
	struct gatt_db_attribute *attr;
	uint16_t start, end;
	uint128_t u128;
	bt_uuid_t uuid;
	char uuid_str[MAX_LEN_UUID_STR];

	if (!success) {
		util_debug(client->debug_callback, client->debug_data,
					"Primary service discovery failed."
					" ATT ECODE: 0x%02x", att_ecode);
		goto done;
	}

	if (!result || !bt_gatt_iter_init(&iter, result)) {
		success = false;
		goto done;
	}

	util_debug(client->debug_callback, client->debug_data,
					"Primary services found: %u",
					bt_gatt_result_service_count(result));

	while (bt_gatt_iter_next_service(&iter, &start, &end, u128.data)) {
		bt_uuid128_create(&uuid, u128);

		/* Log debug message. */
		bt_uuid_to_string(&uuid, uuid_str, sizeof(uuid_str));
		util_debug(client->debug_callback, client->debug_data,
				"start: 0x%04x, end: 0x%04x, uuid: %s",
				start, end, uuid_str);

		attr = gatt_db_insert_service(client->db, start, &uuid, true,
							end - start + 1);
		if (!attr) {
			util_debug(client->debug_callback, client->debug_data,
						"Failed to store service");
			success = false;
			goto done;
		}

		queue_push_tail(op->pending_svcs, attr);
	}

	/* Discover secondary services */
	if (bt_gatt_discover_secondary_services(client->att, NULL,
							op->start, op->end,
							discover_secondary_cb,
							discovery_op_ref(op),
							discovery_op_unref))
		return;

	util_debug(client->debug_callback, client->debug_data,
				"Failed to start secondary service discovery");
	discovery_op_unref(op);
	success = false;

done:
	op->success = success;
	op->complete_func(op, success, att_ecode);
}

static void notify_client_ready(struct bt_gatt_client *client, bool success,
							uint8_t att_ecode)
{
	if (!client->ready_callback)
		return;

	bt_gatt_client_ref(client);
	client->ready_callback(success, att_ecode, client->ready_data);
	bt_gatt_client_unref(client);
}

static void exchange_mtu_cb(bool success, uint8_t att_ecode, void *user_data)
{
	struct discovery_op *op = user_data;
	struct bt_gatt_client *client = op->client;

	op->success = success;

	if (!success) {
		util_debug(client->debug_callback, client->debug_data,
				"MTU Exchange failed. ATT ECODE: 0x%02x",
				att_ecode);

		client->in_init = false;
		notify_client_ready(client, success, att_ecode);

		return;
	}

	util_debug(client->debug_callback, client->debug_data,
					"MTU exchange complete, with MTU: %u",
					bt_att_get_mtu(client->att));

	/* Don't do discovery if the database was pre-populated */
	if (!gatt_db_isempty(client->db)) {
		op->complete_func(op, true, 0);
		return;
	}

	if (bt_gatt_discover_all_primary_services(client->att, NULL,
							discover_primary_cb,
							discovery_op_ref(op),
							discovery_op_unref))
		return;

	util_debug(client->debug_callback, client->debug_data,
			"Failed to initiate primary service discovery");

	client->in_init = false;
	notify_client_ready(client, false, att_ecode);

	discovery_op_unref(op);
}

struct service_changed_op {
	struct bt_gatt_client *client;
	uint16_t start_handle;
	uint16_t end_handle;
};

static void service_changed_reregister_cb(unsigned int id, uint16_t att_ecode,
								void *user_data)
{
	struct bt_gatt_client *client = user_data;

	if (!id || att_ecode) {
		util_debug(client->debug_callback, client->debug_data,
			"Failed to register handler for \"Service Changed\"");
		return;
	}

	client->svc_chngd_ind_id = id;

	util_debug(client->debug_callback, client->debug_data,
		"Re-registered handler for \"Service Changed\" after change in "
		"GATT service");
}

static void process_service_changed(struct bt_gatt_client *client,
							uint16_t start_handle,
							uint16_t end_handle);
static void service_changed_cb(uint16_t value_handle, const uint8_t *value,
					uint16_t length, void *user_data);

static void service_changed_complete(struct discovery_op *op, bool success,
							uint8_t att_ecode)
{
	struct bt_gatt_client *client = op->client;
	struct service_changed_op *next_sc_op;
	uint16_t start_handle = op->start;
	uint16_t end_handle = op->end;
	struct gatt_db_attribute *attr;
	bt_uuid_t uuid;
	struct queue *q;

	client->in_svc_chngd = false;

	if (!success && att_ecode != BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND) {
		util_debug(client->debug_callback, client->debug_data,
			"Failed to discover services within changed range - "
			"error: 0x%02x", att_ecode);

		gatt_db_clear_range(client->db, start_handle, end_handle);
	}

	/* Notify the upper layer of changed services */
	if (client->svc_chngd_callback)
		client->svc_chngd_callback(start_handle, end_handle,
							client->svc_chngd_data);

	/* Process any queued events */
	next_sc_op = queue_pop_head(client->svc_chngd_queue);
	if (next_sc_op) {
		process_service_changed(client, next_sc_op->start_handle,
							next_sc_op->end_handle);
		free(next_sc_op);
		return;
	}

	/* Check if the GATT service was among the changed services */
	q = queue_new();
	if (!q)
		return;

	bt_uuid16_create(&uuid, SVC_CHNGD_UUID);

	gatt_db_find_by_type(client->db, start_handle, end_handle, &uuid, q);
	if (queue_isempty(q)) {
		queue_destroy(q, NULL);
		return;
	}

	attr = queue_pop_head(q);
	queue_destroy(q, NULL);

	/* The GATT service was modified. Re-register the handler for
	 * indications from the "Service Changed" characteristic.
	 */
	if (bt_gatt_client_register_notify(client,
					gatt_db_attribute_get_handle(attr),
					service_changed_reregister_cb,
					service_changed_cb,
					client, NULL))
		return;

	util_debug(client->debug_callback, client->debug_data,
		"Failed to re-register handler for \"Service Changed\"");
}

static void service_changed_failure(struct discovery_op *op)
{
	gatt_db_clear_range(op->client->db, op->start, op->end);
}

static void process_service_changed(struct bt_gatt_client *client,
							uint16_t start_handle,
							uint16_t end_handle)
{
	struct discovery_op *op;

	/* Invalidate and remove all effected notify callbacks */
	gatt_client_remove_all_notify_in_range(client, start_handle,
								end_handle);
	gatt_client_remove_notify_chrcs_in_range(client, start_handle,
								end_handle);

	/* Remove all services that overlap the modified range since we'll
	 * rediscover them
	 */
	gatt_db_clear_range(client->db, start_handle, end_handle);

	op = discovery_op_create(client, start_handle, end_handle,
						service_changed_complete,
						service_changed_failure);
	if (!op)
		goto fail;

	if (bt_gatt_discover_primary_services(client->att, NULL,
						start_handle, end_handle,
						discover_primary_cb,
						discovery_op_ref(op),
						discovery_op_unref)) {
		client->in_svc_chngd = true;
		return;
	}

fail:
	util_debug(client->debug_callback, client->debug_data,
					"Failed to initiate service discovery"
					" after Service Changed");
	discovery_op_free(op);
}

static void service_changed_cb(uint16_t value_handle, const uint8_t *value,
					uint16_t length, void *user_data)
{
	struct bt_gatt_client *client = user_data;
	struct service_changed_op *op;
	uint16_t start, end;

	if (length != 4)
		return;

	start = get_le16(value);
	end = get_le16(value + 2);

	if (start > end) {
		util_debug(client->debug_callback, client->debug_data,
			"Service Changed received with invalid handles");
		return;
	}

	util_debug(client->debug_callback, client->debug_data,
			"Service Changed received - start: 0x%04x end: 0x%04x",
			start, end);

	if (!client->in_svc_chngd) {
		process_service_changed(client, start, end);
		return;
	}

	op = new0(struct service_changed_op, 1);
	if (!op)
		return;

	op->start_handle = start;
	op->end_handle = end;

	queue_push_tail(client->svc_chngd_queue, op);
}

static void service_changed_register_cb(unsigned int id, uint16_t att_ecode,
								void *user_data)
{
	bool success;
	struct bt_gatt_client *client = user_data;

	if (!id || att_ecode) {
		util_debug(client->debug_callback, client->debug_data,
			"Failed to register handler for \"Service Changed\"");
		success = false;
		goto done;
	}

	client->svc_chngd_ind_id = id;
	client->ready = true;
	success = true;
	util_debug(client->debug_callback, client->debug_data,
			"Registered handler for \"Service Changed\": %u", id);

done:
	notify_client_ready(client, success, att_ecode);
}

static void init_complete(struct discovery_op *op, bool success,
							uint8_t att_ecode)
{
	struct bt_gatt_client *client = op->client;
	bool registered;
	struct gatt_db_attribute *attr;
	bt_uuid_t uuid;
	struct queue *q;

	client->in_init = false;

	if (!success)
		goto fail;

	q = queue_new();
	if (!q)
		goto fail;

	bt_uuid16_create(&uuid, SVC_CHNGD_UUID);

	gatt_db_find_by_type(client->db, 0x0001, 0xffff, &uuid, q);
	if (queue_isempty(q)) {
		queue_destroy(q, NULL);
		client->ready = true;
		goto done;
	}

	attr = queue_pop_head(q);
	queue_destroy(q, NULL);

	/* Register an indication handler for the "Service Changed"
	 * characteristic and report ready only if the handler is registered
	 * successfully. Temporarily set "ready" to true so that we can register
	 * the handler using the existing framework.
	 */
	client->ready = true;
	registered = bt_gatt_client_register_notify(client,
					gatt_db_attribute_get_handle(attr),
					service_changed_register_cb,
					service_changed_cb,
					client, NULL);
	client->ready = false;

	if (registered)
		return;

	util_debug(client->debug_callback, client->debug_data,
			"Failed to register handler for \"Service Changed\"");

fail:
	util_debug(client->debug_callback, client->debug_data,
			"Failed to initialize gatt-client");

	op->success = false;

done:
	notify_client_ready(client, success, att_ecode);
}

static void init_fail(struct discovery_op *op)
{
	gatt_db_clear(op->client->db);
}

static bool gatt_client_init(struct bt_gatt_client *client, uint16_t mtu)
{
	struct discovery_op *op;

	if (client->in_init || client->ready)
		return false;

	op = discovery_op_create(client, 0x0001, 0xffff, init_complete,
								init_fail);
	if (!op)
		return false;

	/* Configure the MTU */
	if (!bt_gatt_exchange_mtu(client->att, MAX(BT_ATT_DEFAULT_LE_MTU, mtu),
							exchange_mtu_cb,
							discovery_op_ref(op),
							discovery_op_unref)) {
		discovery_op_free(op);
		return false;
	}

	client->in_init = true;

	return true;
}

struct pdu_data {
	const void *pdu;
	uint16_t length;
};

static void complete_notify_request(void *data)
{
	struct notify_data *notify_data = data;

	/* Increment the per-characteristic ref count of notify handlers */
	__sync_fetch_and_add(&notify_data->chrc->notify_count, 1);

	/* Add the handler to the bt_gatt_client's general list */
	queue_push_tail(notify_data->client->notify_list,
						notify_data_ref(notify_data));

	/* Assign an ID to the handler and notify the caller that it was
	 * successfully registered.
	 */
	if (notify_data->client->next_reg_id < 1)
		notify_data->client->next_reg_id = 1;

	notify_data->id = notify_data->client->next_reg_id++;
	notify_data->callback(notify_data->id, 0, notify_data->user_data);
}

static bool notify_data_write_ccc(struct notify_data *notify_data, bool enable,
						bt_att_response_func_t callback)
{
	uint8_t pdu[4];

	assert(notify_data->chrc->ccc_handle);
	memset(pdu, 0, sizeof(pdu));
	put_le16(notify_data->chrc->ccc_handle, pdu);

	if (enable) {
		/* Try to enable notifications and/or indications based on
		 * whatever the characteristic supports.
		 */
		if (notify_data->chrc->properties & BT_GATT_CHRC_PROP_NOTIFY)
			pdu[2] = 0x01;

		if (notify_data->chrc->properties & BT_GATT_CHRC_PROP_INDICATE)
			pdu[2] |= 0x02;

		if (!pdu[2])
			return false;
	}

	notify_data->chrc->ccc_write_id = bt_att_send(notify_data->client->att,
						BT_ATT_OP_WRITE_REQ,
						pdu, sizeof(pdu),
						callback,
						notify_data, notify_data_unref);

	return !!notify_data->chrc->ccc_write_id;
}

static uint8_t process_error(const void *pdu, uint16_t length)
{
	const struct bt_att_pdu_error_rsp *error_pdu;

	if (!pdu || length != sizeof(struct bt_att_pdu_error_rsp))
		return 0;

	error_pdu = pdu;

	return error_pdu->ecode;
}

static void enable_ccc_callback(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct notify_data *notify_data = user_data;
	uint16_t att_ecode;

	assert(!notify_data->chrc->notify_count);
	assert(notify_data->chrc->ccc_write_id);

	notify_data->chrc->ccc_write_id = 0;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		att_ecode = process_error(pdu, length);

		/* Failed to enable. Complete the current request and move on to
		 * the next one in the queue. If there was an error sending the
		 * write request, then just move on to the next queued entry.
		 */
		notify_data->callback(0, att_ecode, notify_data->user_data);

		while ((notify_data = queue_pop_head(
					notify_data->chrc->reg_notify_queue))) {

			if (notify_data_write_ccc(notify_data, true,
							enable_ccc_callback))
				return;
		}

		return;
	}

	/* Success! Report success for all remaining requests. */
	bt_gatt_client_ref(notify_data->client);

	complete_notify_request(notify_data);
	queue_remove_all(notify_data->chrc->reg_notify_queue, NULL, NULL,
						complete_notify_request);

	bt_gatt_client_unref(notify_data->client);
}

static void disable_ccc_callback(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct notify_data *notify_data = user_data;
	struct notify_data *next_data;

	assert(!notify_data->chrc->notify_count);
	assert(notify_data->chrc->ccc_write_id);

	notify_data->chrc->ccc_write_id = 0;

	/* This is a best effort procedure, so ignore errors and process any
	 * queued requests.
	 */
	while (1) {
		next_data = queue_pop_head(notify_data->chrc->reg_notify_queue);
		if (!next_data || notify_data_write_ccc(notify_data, true,
							enable_ccc_callback))
			return;
	}
}

static void complete_unregister_notify(void *data)
{
	struct notify_data *notify_data = data;

	if (__sync_sub_and_fetch(&notify_data->chrc->notify_count, 1)) {
		notify_data_unref(notify_data);
		return;
	}

	notify_data_write_ccc(notify_data, false, disable_ccc_callback);
}

static void notify_handler(void *data, void *user_data)
{
	struct notify_data *notify_data = data;
	struct pdu_data *pdu_data = user_data;
	uint16_t value_handle;
	const uint8_t *value = NULL;

	value_handle = get_le16(pdu_data->pdu);

	if (notify_data->chrc->value_handle != value_handle)
		return;

	if (pdu_data->length > 2)
		value = pdu_data->pdu + 2;

	if (notify_data->notify)
		notify_data->notify(value_handle, value, pdu_data->length - 2,
							notify_data->user_data);
}

static void notify_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct bt_gatt_client *client = user_data;
	struct pdu_data pdu_data;

	bt_gatt_client_ref(client);

	memset(&pdu_data, 0, sizeof(pdu_data));
	pdu_data.pdu = pdu;
	pdu_data.length = length;

	queue_foreach(client->notify_list, notify_handler, &pdu_data);

	if (opcode == BT_ATT_OP_HANDLE_VAL_IND)
		bt_att_send(client->att, BT_ATT_OP_HANDLE_VAL_CONF, NULL, 0,
							NULL, NULL, NULL);

	bt_gatt_client_unref(client);
}

static void long_write_op_unref(void *data);

static void bt_gatt_client_free(struct bt_gatt_client *client)
{
	if (client->ready_destroy)
		client->ready_destroy(client->ready_data);

	if (client->debug_destroy)
		client->debug_destroy(client->debug_data);

	if (client->att) {
		bt_att_unregister_disconnect(client->att, client->disc_id);
		bt_att_unregister(client->att, client->notify_id);
		bt_att_unregister(client->att, client->ind_id);
		bt_att_unref(client->att);
	}

	gatt_db_unref(client->db);

	queue_destroy(client->svc_chngd_queue, free);
	queue_destroy(client->long_write_queue, long_write_op_unref);
	queue_destroy(client->notify_list, notify_data_unref);
	queue_destroy(client->notify_chrcs, notify_chrc_free);

	free(client);
}

static void att_disconnect_cb(int err, void *user_data)
{
	struct bt_gatt_client *client = user_data;
	bool in_init = client->in_init;

	client->disc_id = 0;

	bt_att_unref(client->att);
	client->att = NULL;

	client->in_init = false;
	client->ready = false;

	if (in_init)
		notify_client_ready(client, false, 0);
}

struct bt_gatt_client *bt_gatt_client_new(struct gatt_db *db,
							struct bt_att *att,
							uint16_t mtu)
{
	struct bt_gatt_client *client;

	if (!att || !db)
		return NULL;

	client = new0(struct bt_gatt_client, 1);
	if (!client)
		return NULL;

	client->disc_id = bt_att_register_disconnect(att, att_disconnect_cb,
								client, NULL);
	if (!client->disc_id)
		goto fail;

	client->long_write_queue = queue_new();
	if (!client->long_write_queue)
		goto fail;

	client->svc_chngd_queue = queue_new();
	if (!client->svc_chngd_queue)
		goto fail;

	client->notify_list = queue_new();
	if (!client->notify_list)
		goto fail;

	client->notify_chrcs = queue_new();
	if (!client->notify_chrcs)
		goto fail;

	client->notify_id = bt_att_register(att, BT_ATT_OP_HANDLE_VAL_NOT,
						notify_cb, client, NULL);
	if (!client->notify_id)
		goto fail;

	client->ind_id = bt_att_register(att, BT_ATT_OP_HANDLE_VAL_IND,
						notify_cb, client, NULL);
	if (!client->ind_id)
		goto fail;

	client->att = bt_att_ref(att);
	client->db = gatt_db_ref(db);

	if (!gatt_client_init(client, mtu))
		goto fail;

	return bt_gatt_client_ref(client);

fail:
	bt_gatt_client_free(client);
	return NULL;
}

struct bt_gatt_client *bt_gatt_client_ref(struct bt_gatt_client *client)
{
	if (!client)
		return NULL;

	__sync_fetch_and_add(&client->ref_count, 1);

	return client;
}

void bt_gatt_client_unref(struct bt_gatt_client *client)
{
	if (!client)
		return;

	if (__sync_sub_and_fetch(&client->ref_count, 1))
		return;

	bt_gatt_client_free(client);
}

bool bt_gatt_client_is_ready(struct bt_gatt_client *client)
{
	return (client && client->ready);
}

bool bt_gatt_client_set_ready_handler(struct bt_gatt_client *client,
					bt_gatt_client_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy)
{
	if (!client)
		return false;

	if (client->ready_destroy)
		client->ready_destroy(client->ready_data);

	client->ready_callback = callback;
	client->ready_destroy = destroy;
	client->ready_data = user_data;

	return true;
}

bool bt_gatt_client_set_service_changed(struct bt_gatt_client *client,
			bt_gatt_client_service_changed_callback_t callback,
			void *user_data,
			bt_gatt_client_destroy_func_t destroy)
{
	if (!client)
		return false;

	if (client->svc_chngd_destroy)
		client->svc_chngd_destroy(client->svc_chngd_data);

	client->svc_chngd_callback = callback;
	client->svc_chngd_destroy = destroy;
	client->svc_chngd_data = user_data;

	return true;
}

bool bt_gatt_client_set_debug(struct bt_gatt_client *client,
					bt_gatt_client_debug_func_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy) {
	if (!client)
		return false;

	if (client->debug_destroy)
		client->debug_destroy(client->debug_data);

	client->debug_callback = callback;
	client->debug_destroy = destroy;
	client->debug_data = user_data;

	return true;
}

uint16_t bt_gatt_client_get_mtu(struct bt_gatt_client *client)
{
	if (!client || !client->att)
		return 0;

	return bt_att_get_mtu(client->att);
}

struct read_op {
	bt_gatt_client_read_callback_t callback;
	void *user_data;
	bt_gatt_client_destroy_func_t destroy;
};

static void destroy_read_op(void *data)
{
	struct read_op *op = data;

	if (op->destroy)
		op->destroy(op->user_data);

	free(op);
}

static void read_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct read_op *op = user_data;
	bool success;
	uint8_t att_ecode = 0;
	const uint8_t *value = NULL;
	uint16_t value_len = 0;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);
		goto done;
	}

	if (opcode != BT_ATT_OP_READ_RSP || (!pdu && length)) {
		success = false;
		goto done;
	}

	success = true;
	value_len = length;
	if (value_len)
		value = pdu;

done:
	if (op->callback)
		op->callback(success, att_ecode, value, length, op->user_data);
}

bool bt_gatt_client_read_value(struct bt_gatt_client *client,
					uint16_t value_handle,
					bt_gatt_client_read_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy)
{
	struct read_op *op;
	uint8_t pdu[2];

	if (!client)
		return false;

	op = new0(struct read_op, 1);
	if (!op)
		return false;

	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	put_le16(value_handle, pdu);

	if (!bt_att_send(client->att, BT_ATT_OP_READ_REQ, pdu, sizeof(pdu),
							read_cb, op,
							destroy_read_op)) {
		free(op);
		return false;
	}

	return true;
}

static void read_multiple_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct read_op *op = user_data;
	uint8_t att_ecode;
	bool success;

	if (opcode != BT_ATT_OP_READ_MULT_RSP || (!pdu && length)) {
		success = false;

		if (opcode == BT_ATT_OP_ERROR_RSP)
			att_ecode = process_error(pdu, length);
		else
			att_ecode = 0;

		pdu = NULL;
		length = 0;
	} else {
		success = true;
		att_ecode = 0;
	}

	if (op->callback)
		op->callback(success, att_ecode, pdu, length, op->user_data);
}

bool bt_gatt_client_read_multiple(struct bt_gatt_client *client,
					uint16_t *handles, uint8_t num_handles,
					bt_gatt_client_read_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy)
{
	uint8_t pdu[num_handles * 2];
	struct read_op *op;
	int i;

	if (!client)
		return false;

	if (num_handles < 2)
		return false;

	if (num_handles * 2 > bt_att_get_mtu(client->att) - 1)
		return false;

	op = new0(struct read_op, 1);
	if (!op)
		return false;

	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	for (i = 0; i < num_handles; i++)
		put_le16(handles[i], pdu + (2 * i));

	if (!bt_att_send(client->att, BT_ATT_OP_READ_MULT_REQ, pdu, sizeof(pdu),
				read_multiple_cb, op, destroy_read_op)) {
		free(op);
		return false;
	}

	return true;
}

struct read_long_op {
	struct bt_gatt_client *client;
	int ref_count;
	uint16_t value_handle;
	size_t orig_offset;
	size_t offset;
	struct queue *blobs;
	bt_gatt_client_read_callback_t callback;
	void *user_data;
	bt_gatt_client_destroy_func_t destroy;
};

struct blob {
	uint8_t *data;
	uint16_t offset;
	uint16_t length;
};

static struct blob *create_blob(const uint8_t *data, uint16_t len,
								uint16_t offset)
{
	struct blob *blob;

	blob = new0(struct blob, 1);
	if (!blob)
		return NULL;

	blob->data = malloc(len);
	if (!blob->data) {
		free(blob);
		return NULL;
	}

	memcpy(blob->data, data, len);
	blob->length = len;
	blob->offset = offset;

	return blob;
}

static void destroy_blob(void *data)
{
	struct blob *blob = data;

	free(blob->data);
	free(blob);
}

static struct read_long_op *read_long_op_ref(struct read_long_op *op)
{
	__sync_fetch_and_add(&op->ref_count, 1);

	return op;
}

static void read_long_op_unref(void *data)
{
	struct read_long_op *op = data;

	if (__sync_sub_and_fetch(&op->ref_count, 1))
		return;

	if (op->destroy)
		op->destroy(op->user_data);

	queue_destroy(op->blobs, destroy_blob);

	free(op);
}

static void append_blob(void *data, void *user_data)
{
	struct blob *blob = data;
	uint8_t *value = user_data;

	memcpy(value + blob->offset, blob->data, blob->length);
}

static void complete_read_long_op(struct read_long_op *op, bool success,
							uint8_t att_ecode)
{
	uint8_t *value = NULL;
	uint16_t length = 0;

	if (!success)
		goto done;

	length = op->offset - op->orig_offset;

	if (!length)
		goto done;

	value = malloc(length);
	if (!value) {
		success = false;
		goto done;
	}

	queue_foreach(op->blobs, append_blob, value - op->orig_offset);

done:
	if (op->callback)
		op->callback(success, att_ecode, value, length, op->user_data);

	free(value);
}

static void read_long_cb(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	struct read_long_op *op = user_data;
	struct blob *blob;
	bool success;
	uint8_t att_ecode = 0;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);
		goto done;
	}

	if (opcode != BT_ATT_OP_READ_BLOB_RSP || (!pdu && length)) {
		success = false;
		goto done;
	}

	if (!length)
		goto success;

	blob = create_blob(pdu, length, op->offset);
	if (!blob) {
		success = false;
		goto done;
	}

	queue_push_tail(op->blobs, blob);
	op->offset += length;
	if (op->offset > UINT16_MAX)
		goto success;

	if (length >= bt_att_get_mtu(op->client->att) - 1) {
		uint8_t pdu[4];

		put_le16(op->value_handle, pdu);
		put_le16(op->offset, pdu + 2);

		if (bt_att_send(op->client->att, BT_ATT_OP_READ_BLOB_REQ,
							pdu, sizeof(pdu),
							read_long_cb,
							read_long_op_ref(op),
							read_long_op_unref))
			return;

		read_long_op_unref(op);
		success = false;
		goto done;
	}

success:
	success = true;

done:
	complete_read_long_op(op, success, att_ecode);
}

bool bt_gatt_client_read_long_value(struct bt_gatt_client *client,
					uint16_t value_handle, uint16_t offset,
					bt_gatt_client_read_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy)
{
	struct read_long_op *op;
	uint8_t pdu[4];

	if (!client)
		return false;

	op = new0(struct read_long_op, 1);
	if (!op)
		return false;

	op->blobs = queue_new();
	if (!op->blobs) {
		free(op);
		return false;
	}

	op->client = client;
	op->value_handle = value_handle;
	op->orig_offset = offset;
	op->offset = offset;
	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	put_le16(value_handle, pdu);
	put_le16(offset, pdu + 2);

	if (!bt_att_send(client->att, BT_ATT_OP_READ_BLOB_REQ, pdu, sizeof(pdu),
							read_long_cb,
							read_long_op_ref(op),
							read_long_op_unref)) {
		queue_destroy(op->blobs, free);
		free(op);
		return false;
	}

	return true;
}

bool bt_gatt_client_write_without_response(struct bt_gatt_client *client,
					uint16_t value_handle,
					bool signed_write,
					const uint8_t *value, uint16_t length) {
	uint8_t pdu[2 + length];

	if (!client)
		return 0;

	/* TODO: Support this once bt_att_send supports signed writes. */
	if (signed_write)
		return 0;

	put_le16(value_handle, pdu);
	memcpy(pdu + 2, value, length);

	return bt_att_send(client->att, BT_ATT_OP_WRITE_CMD, pdu, sizeof(pdu),
							NULL, NULL, NULL);
}

struct write_op {
	bt_gatt_result_callback_t callback;
	void *user_data;
	bt_gatt_destroy_func_t destroy;
};

static void destroy_write_op(void *data)
{
	struct write_op *op = data;

	if (op->destroy)
		op->destroy(op->user_data);

	free(op);
}

static void write_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct write_op *op = user_data;
	bool success = true;
	uint8_t att_ecode = 0;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);
		goto done;
	}

	if (opcode != BT_ATT_OP_WRITE_RSP || pdu || length)
		success = false;

done:
	if (op->callback)
		op->callback(success, att_ecode, op->user_data);
}

bool bt_gatt_client_write_value(struct bt_gatt_client *client,
					uint16_t value_handle,
					const uint8_t *value, uint16_t length,
					bt_gatt_client_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy)
{
	struct write_op *op;
	uint8_t pdu[2 + length];

	if (!client)
		return false;

	op = new0(struct write_op, 1);
	if (!op)
		return false;

	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	put_le16(value_handle, pdu);
	memcpy(pdu + 2, value, length);

	if (!bt_att_send(client->att, BT_ATT_OP_WRITE_REQ, pdu, sizeof(pdu),
							write_cb, op,
							destroy_write_op)) {
		free(op);
		return false;
	}

	return true;
}

struct long_write_op {
	struct bt_gatt_client *client;
	int ref_count;
	bool reliable;
	bool success;
	uint8_t att_ecode;
	bool reliable_error;
	uint16_t value_handle;
	uint8_t *value;
	uint16_t length;
	uint16_t offset;
	uint16_t index;
	uint16_t cur_length;
	bt_gatt_client_write_long_callback_t callback;
	void *user_data;
	bt_gatt_client_destroy_func_t destroy;
};

static struct long_write_op *long_write_op_ref(struct long_write_op *op)
{
	__sync_fetch_and_add(&op->ref_count, 1);

	return op;
}

static void long_write_op_unref(void *data)
{
	struct long_write_op *op = data;

	if (__sync_sub_and_fetch(&op->ref_count, 1))
		return;

	if (op->destroy)
		op->destroy(op->user_data);

	free(op->value);
	free(op);
}

static void prepare_write_cb(uint8_t opcode, const void *pdu, uint16_t length,
							void *user_data);
static void complete_write_long_op(struct long_write_op *op, bool success,
					uint8_t att_ecode, bool reliable_error);

static void handle_next_prep_write(struct long_write_op *op)
{
	bool success = true;
	uint8_t *pdu;

	pdu = malloc(op->cur_length + 4);
	if (!pdu) {
		success = false;
		goto done;
	}

	put_le16(op->value_handle, pdu);
	put_le16(op->offset + op->index, pdu + 2);
	memcpy(pdu + 4, op->value + op->index, op->cur_length);

	if (!bt_att_send(op->client->att, BT_ATT_OP_PREP_WRITE_REQ,
							pdu, op->cur_length + 4,
							prepare_write_cb,
							long_write_op_ref(op),
							long_write_op_unref)) {
		long_write_op_unref(op);
		success = false;
	}

	free(pdu);

	/* If so far successful, then the operation should continue.
	 * Otherwise, there was an error and the procedure should be
	 * completed.
	 */
	if (success)
		return;

done:
	complete_write_long_op(op, success, 0, false);
}

static void start_next_long_write(struct bt_gatt_client *client)
{
	struct long_write_op *op;

	if (queue_isempty(client->long_write_queue)) {
		client->in_long_write = false;
		return;
	}

	op = queue_pop_head(client->long_write_queue);
	if (!op)
		return;

	handle_next_prep_write(op);

	/* send_next_prep_write adds an extra ref. Unref here to clean up if
	 * necessary, since we also added a ref before pushing to the queue.
	 */
	long_write_op_unref(op);
}

static void execute_write_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct long_write_op *op = user_data;
	bool success = op->success;
	uint8_t att_ecode = op->att_ecode;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);
	} else if (opcode != BT_ATT_OP_EXEC_WRITE_RSP || pdu || length)
		success = false;

	if (op->callback)
		op->callback(success, op->reliable_error, att_ecode,
								op->user_data);

	start_next_long_write(op->client);
}

static void complete_write_long_op(struct long_write_op *op, bool success,
					uint8_t att_ecode, bool reliable_error)
{
	uint8_t pdu;

	op->success = success;
	op->att_ecode = att_ecode;
	op->reliable_error = reliable_error;

	if (success)
		pdu = 0x01;  /* Write */
	else
		pdu = 0x00;  /* Cancel */

	if (bt_att_send(op->client->att, BT_ATT_OP_EXEC_WRITE_REQ,
							&pdu, sizeof(pdu),
							execute_write_cb,
							long_write_op_ref(op),
							long_write_op_unref))
		return;

	long_write_op_unref(op);
	success = false;

	if (op->callback)
		op->callback(success, reliable_error, att_ecode, op->user_data);

	start_next_long_write(op->client);
}

static void prepare_write_cb(uint8_t opcode, const void *pdu, uint16_t length,
								void *user_data)
{
	struct long_write_op *op = user_data;
	bool success = true;
	bool reliable_error = false;
	uint8_t att_ecode = 0;
	uint16_t next_index;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		success = false;
		att_ecode = process_error(pdu, length);
		goto done;
	}

	if (opcode != BT_ATT_OP_PREP_WRITE_RSP) {
		success = false;
		goto done;
	}

	if (op->reliable) {
		if (!pdu || length != (op->cur_length + 4)) {
			success = false;
			reliable_error = true;
			goto done;
		}

		if (get_le16(pdu) != op->value_handle ||
				get_le16(pdu + 2) != (op->offset + op->index)) {
			success = false;
			reliable_error = true;
			goto done;
		}

		if (memcmp(pdu + 4, op->value + op->index, op->cur_length)) {
			success = false;
			reliable_error = true;
			goto done;
		}
	}

	next_index = op->index + op->cur_length;
	if (next_index == op->length) {
		/* All bytes written */
		goto done;
	}

	/* If the last written length was greater than or equal to what can fit
	 * inside a PDU, then there is more data to send.
	 */
	if (op->cur_length >= bt_att_get_mtu(op->client->att) - 5) {
		op->index = next_index;
		op->cur_length = MIN(op->length - op->index,
					bt_att_get_mtu(op->client->att) - 5);
		handle_next_prep_write(op);
		return;
	}

done:
	complete_write_long_op(op, success, att_ecode, reliable_error);
}

bool bt_gatt_client_write_long_value(struct bt_gatt_client *client,
				bool reliable,
				uint16_t value_handle, uint16_t offset,
				const uint8_t *value, uint16_t length,
				bt_gatt_client_write_long_callback_t callback,
				void *user_data,
				bt_gatt_client_destroy_func_t destroy)
{
	struct long_write_op *op;
	uint8_t *pdu;
	bool status;

	if (!client)
		return false;

	if ((size_t)(length + offset) > UINT16_MAX)
		return false;

	/* Don't allow writing a 0-length value using this procedure. The
	 * upper-layer should use bt_gatt_write_value for that instead.
	 */
	if (!length || !value)
		return false;

	op = new0(struct long_write_op, 1);
	if (!op)
		return false;

	op->value = malloc(length);
	if (!op->value) {
		free(op);
		return false;
	}

	memcpy(op->value, value, length);

	op->client = client;
	op->reliable = reliable;
	op->value_handle = value_handle;
	op->length = length;
	op->offset = offset;
	op->cur_length = MIN(length, bt_att_get_mtu(client->att) - 5);
	op->callback = callback;
	op->user_data = user_data;
	op->destroy = destroy;

	if (client->in_long_write) {
		queue_push_tail(client->long_write_queue,
						long_write_op_ref(op));
		return true;
	}

	pdu = malloc(op->cur_length + 4);
	if (!pdu) {
		free(op->value);
		free(op);
		return false;
	}

	put_le16(value_handle, pdu);
	put_le16(offset, pdu + 2);
	memcpy(pdu + 4, op->value, op->cur_length);

	status = bt_att_send(client->att, BT_ATT_OP_PREP_WRITE_REQ,
							pdu, op->cur_length + 4,
							prepare_write_cb,
							long_write_op_ref(op),
							long_write_op_unref);

	free(pdu);

	if (!status) {
		free(op->value);
		free(op);
		return false;
	}

	client->in_long_write = true;

	return true;
}

static bool match_notify_chrc_value_handle(const void *a, const void *b)
{
	const struct notify_chrc *chrc = a;
	uint16_t value_handle = PTR_TO_UINT(b);

	return chrc->value_handle == value_handle;
}

bool bt_gatt_client_register_notify(struct bt_gatt_client *client,
				uint16_t chrc_value_handle,
				bt_gatt_client_notify_id_callback_t callback,
				bt_gatt_client_notify_callback_t notify,
				void *user_data,
				bt_gatt_client_destroy_func_t destroy)
{
	struct notify_data *notify_data;
	struct notify_chrc *chrc = NULL;

	if (!client || !client->db || !chrc_value_handle || !callback)
		return false;

	if (!bt_gatt_client_is_ready(client) || client->in_svc_chngd)
		return false;

	/* Check if a characteristic ref count has been started already */
	chrc = queue_find(client->notify_chrcs, match_notify_chrc_value_handle,
						UINT_TO_PTR(chrc_value_handle));

	if (!chrc) {
		/*
		 * Create an entry if the characteristic is known and has a CCC
		 * descriptor.
		 */
		chrc = notify_chrc_create(client, chrc_value_handle);
		if (!chrc)
			return false;

	}

	/* Fail if we've hit the maximum allowed notify sessions */
	if (chrc->notify_count == INT_MAX)
		return false;

	notify_data = new0(struct notify_data, 1);
	if (!notify_data)
		return false;

	notify_data->client = client;
	notify_data->ref_count = 1;
	notify_data->chrc = chrc;
	notify_data->callback = callback;
	notify_data->notify = notify;
	notify_data->user_data = user_data;
	notify_data->destroy = destroy;

	/*
	 * If a write to the CCC descriptor is in progress, then queue this
	 * request.
	 */
	if (chrc->ccc_write_id) {
		queue_push_tail(chrc->reg_notify_queue, notify_data);
		return true;
	}

	/*
	 * If the ref count is not zero, then notifications are already enabled.
	 */
	if (chrc->notify_count > 0) {
		complete_notify_request(notify_data);
		return true;
	}

	/* Write to the CCC descriptor */
	if (!notify_data_write_ccc(notify_data, true, enable_ccc_callback)) {
		free(notify_data);
		return false;
	}

	return true;
}

bool bt_gatt_client_unregister_notify(struct bt_gatt_client *client,
							unsigned int id)
{
	struct notify_data *notify_data;

	if (!client || !id)
		return false;

	notify_data = queue_remove_if(client->notify_list, match_notify_data_id,
							UINT_TO_PTR(id));
	if (!notify_data)
		return false;

	assert(notify_data->chrc->notify_count > 0);
	assert(!notify_data->chrc->ccc_write_id);

	complete_unregister_notify(notify_data);
	return true;
}

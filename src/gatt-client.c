/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
 *
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

#include <stdbool.h>
#include <stdint.h>

#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include <bluetooth/bluetooth.h>

#include "log.h"
#include "error.h"
#include "adapter.h"
#include "device.h"
#include "lib/uuid.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/util.h"
#include "gatt-client.h"
#include "dbus-common.h"

#define GATT_SERVICE_IFACE		"org.bluez.GattService1"
#define GATT_CHARACTERISTIC_IFACE	"org.bluez.GattCharacteristic1"
#define GATT_DESCRIPTOR_IFACE		"org.bluez.GattDescriptor1"

struct btd_gatt_client {
	struct btd_device *device;
	char devaddr[18];
	struct gatt_db *db;
	struct bt_gatt_client *gatt;

	struct queue *services;
};

struct service {
	struct btd_gatt_client *client;
	bool primary;
	uint16_t start_handle;
	uint16_t end_handle;
	bt_uuid_t uuid;
	char *path;
	struct queue *chrcs;
	bool chrcs_ready;
	struct queue *pending_ext_props;
	guint idle_id;
};

struct characteristic {
	struct service *service;
	uint16_t handle;
	uint16_t value_handle;
	uint8_t props;
	uint16_t ext_props;
	uint16_t ext_props_handle;
	bt_uuid_t uuid;
	char *path;

	int ref_count;

	bool in_read;
	bool in_write;
	bool value_known;
	uint8_t *value;
	size_t value_len;

	struct queue *descs;

	bool notifying;
	struct queue *notify_clients;
};

struct descriptor {
	struct characteristic *chrc;
	uint16_t handle;
	bt_uuid_t uuid;
	char *path;

	int ref_count;

	bool in_read;
	bool in_write;
	bool value_known;
	uint8_t *value;
	size_t value_len;
};

static struct characteristic *characteristic_ref(struct characteristic *chrc)
{
	__sync_fetch_and_add(&chrc->ref_count, 1);

	return chrc;
}

static void characteristic_unref(void *data)
{
	struct characteristic *chrc = data;

	if (__sync_sub_and_fetch(&chrc->ref_count, 1))
		return;

	queue_destroy(chrc->descs, NULL);  /* List should be empty here */
	free(chrc->value);
	g_free(chrc->path);
	free(chrc);
}

static struct descriptor *descriptor_ref(struct descriptor *desc)
{
	__sync_fetch_and_add(&desc->ref_count, 1);

	return desc;
}

static void descriptor_unref(void *data)
{
	struct descriptor *desc = data;

	if (__sync_sub_and_fetch(&desc->ref_count, 1))
		return;

	free(desc->value);
	g_free(desc->path);
	free(desc);
}

static DBusMessage *gatt_error_read_not_permitted(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".ReadNotPermitted",
				"Reading of this value is not allowed");
}

static DBusMessage *gatt_error_write_not_permitted(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".WriteNotPermitted",
				"Writing of this value is not allowed");
}

static DBusMessage *gatt_error_invalid_value_len(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidValueLength",
							"Invalid value length");
}

static DBusMessage *gatt_error_invalid_offset(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidOffset",
							"Invalid value offset");
}

static DBusMessage *gatt_error_not_paired(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotPaired",
								"Not Paired");
}

static DBusMessage *create_gatt_dbus_error(DBusMessage *msg, uint8_t att_ecode)
{
	switch (att_ecode) {
	case BT_ATT_ERROR_READ_NOT_PERMITTED:
		return gatt_error_read_not_permitted(msg);
	case BT_ATT_ERROR_WRITE_NOT_PERMITTED:
		return gatt_error_write_not_permitted(msg);
	case BT_ATT_ERROR_AUTHENTICATION:
	case BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION:
	case BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE:
		return gatt_error_not_paired(msg);
	case BT_ATT_ERROR_INVALID_OFFSET:
		return gatt_error_invalid_offset(msg);
	case BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN:
		return gatt_error_invalid_value_len(msg);
	case BT_ATT_ERROR_AUTHORIZATION:
		return btd_error_not_authorized(msg);
	case BT_ATT_ERROR_REQUEST_NOT_SUPPORTED:
		return btd_error_not_supported(msg);
	case 0:
		return btd_error_failed(msg, "Operation failed");
	default:
		return g_dbus_create_error(msg, ERROR_INTERFACE,
				"Operation failed with ATT error: 0x%02x",
				att_ecode);
	}

	return NULL;
}

static bool uuid_cmp(const bt_uuid_t *uuid, uint16_t u16)
{
	bt_uuid_t uuid16;

	bt_uuid16_create(&uuid16, u16);

	return bt_uuid_cmp(uuid, &uuid16) == 0;
}

static gboolean descriptor_property_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	char uuid[MAX_LEN_UUID_STR + 1];
	const char *ptr = uuid;
	struct descriptor *desc = data;

	bt_uuid_to_string(&desc->uuid, uuid, sizeof(uuid));
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ptr);

	return TRUE;
}

static gboolean descriptor_property_get_characteristic(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct descriptor *desc = data;
	const char *str = desc->chrc->path;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &str);

	return TRUE;
}

static gboolean descriptor_property_get_value(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct descriptor *desc = data;
	DBusMessageIter array;
	size_t i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "y", &array);

	if (desc->value_known) {
		for (i = 0; i < desc->value_len; i++)
			dbus_message_iter_append_basic(&array, DBUS_TYPE_BYTE,
							desc->value + i);
	}

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean descriptor_property_value_exists(
					const GDBusPropertyTable *property,
					void *data)
{
	struct descriptor *desc = data;

	return desc->value_known ? TRUE : FALSE;
}

static bool resize_value_buffer(size_t new_len, uint8_t **value, size_t *len)
{
	uint8_t *ptr;

	if (*len == new_len)
		return true;

	if (!new_len) {
		free(*value);
		*value = NULL;
		*len = 0;

		return true;
	}

	ptr = realloc(*value, sizeof(uint8_t) * new_len);
	if (!ptr)
		return false;

	*value = ptr;
	*len = new_len;

	return true;
}

static void update_value_property(const uint8_t *value, size_t len,
					uint8_t **cur_value, size_t *cur_len,
					bool *value_known,
					const char *path, const char *iface,
					bool notify_if_same)
{
	/*
	 * If the value is the same, then only updated it if wasn't previously
	 * known.
	 */
	if (*value_known && *cur_len == len &&
			!memcmp(*cur_value, value, sizeof(uint8_t) * len)) {
		if (notify_if_same)
			goto notify;

		return;
	}

	if (resize_value_buffer(len, cur_value, cur_len)) {
		*value_known = true;
		memcpy(*cur_value, value, sizeof(uint8_t) * len);
	} else {
		/*
		 * Failed to resize the buffer. Since we don't want to show a
		 * stale value, if the value was previously known then free and
		 * hide it.
		 */
		free(*cur_value);
		*cur_value = NULL;
		*cur_len = 0;
		*value_known = false;
	}

notify:
	g_dbus_emit_property_changed(btd_get_dbus_connection(), path, iface,
								"Value");
}

static bool parse_value_arg(DBusMessage *msg, uint8_t **value,
							size_t *value_len)
{
	DBusMessageIter iter, array;
	uint8_t *val;
	int len;

	if (!dbus_message_iter_init(msg, &iter))
		return false;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return false;

	dbus_message_iter_recurse(&iter, &array);
	dbus_message_iter_get_fixed_array(&array, &val, &len);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INVALID)
		return false;

	if (len < 0)
		return false;

	*value = val;
	*value_len = len;

	return true;
}

typedef bool (*async_dbus_op_complete_t)(void *data);
typedef void (*async_dbus_op_destroy_t)(void *data);

struct async_dbus_op {
	DBusMessage *msg;
	void *data;
	async_dbus_op_complete_t complete;
	async_dbus_op_destroy_t destroy;
};

static void async_dbus_op_free(void *data)
{
	struct async_dbus_op *op = data;

	if (op->destroy)
		op->destroy(op->data);

	if (op->msg)
		dbus_message_unref(op->msg);

	free(op);
}

static void message_append_byte_array(DBusMessage *msg, const uint8_t *bytes,
								size_t len)
{
	DBusMessageIter iter, array;
	size_t i;

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "y", &array);

	for (i = 0; i < len; i++)
		dbus_message_iter_append_basic(&array, DBUS_TYPE_BYTE,
								bytes + i);

	dbus_message_iter_close_container(&iter, &array);
}

struct async_read_op {
	DBusMessage *msg;
	int ref_count;
	uint8_t *value;
	size_t len;
	struct bt_gatt_client *gatt;
	uint16_t handle;
	void *data;
	bool (*complete)(const uint8_t *value, size_t len, void *data);
	void (*destroy)(void *data);
};

static struct async_read_op *async_read_op_ref(struct async_read_op *op)
{
	__sync_fetch_and_add(&op->ref_count, 1);

	return op;
}

static void async_read_op_unref(void *data)
{
	struct async_read_op *op = data;

	if (__sync_sub_and_fetch(&op->ref_count, 1))
		return;

	if (op->destroy)
		op->destroy(op->data);

	dbus_message_unref(op->msg);
	free(op->value);
	free(op);
}

static void complete_read(struct async_read_op *op, bool success,
					uint8_t att_ecode, const uint8_t *value,
					uint16_t length)
{
	DBusMessage *reply;

	if (!success) {
		reply = create_gatt_dbus_error(op->msg, att_ecode);
		goto done;
	}

	if (!op->complete(value, length, op->data)) {
		reply = btd_error_failed(op->msg, "Operation failed");
		goto done;
	}

	reply = g_dbus_create_reply(op->msg, DBUS_TYPE_INVALID);
	if (!reply) {
		error("Failed to allocate D-Bus message reply");
		return;
	}

	message_append_byte_array(reply, value, length);

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);
}

static void read_long_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct async_read_op *op = user_data;
	uint8_t *final_value = NULL;
	size_t final_len = 0;

	if (!success) {
		if (att_ecode != BT_ATT_ERROR_REQUEST_NOT_SUPPORTED &&
				att_ecode != BT_ATT_ERROR_ATTRIBUTE_NOT_LONG &&
				att_ecode != BT_ATT_ERROR_INVALID_OFFSET)
			goto done;

		success = true;
		att_ecode = 0;
	}

	if (length == 0) {
		final_len = op->len;
		final_value = op->value;
	} else {
		final_len = op->len + length;
		final_value = malloc(sizeof(uint8_t) * (op->len + length));
		if (!final_value) {
			success = false;
			goto done;
		}

		memcpy(final_value, op->value, op->len);
		memcpy(final_value + op->len, value, length);
	}

done:
	complete_read(op, success, att_ecode, final_value, final_len);

	if (final_value && final_value != op->value)
		free(final_value);
}

static void read_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct async_read_op *op = user_data;

	if (!success)
		goto done;

	/*
	 * If the value length is exactly MTU-1, then we may not have read the
	 * entire value. Perform a long read to obtain the rest, otherwise,
	 * we're done.
	 */
	if (length < bt_gatt_client_get_mtu(op->gatt) - 1)
		goto done;

	op->value = malloc(sizeof(uint8_t) * length);
	if (!op->value) {
		success = false;
		goto done;
	}

	memcpy(op->value, value, sizeof(uint8_t) * length);
	op->len = length;

	if (bt_gatt_client_read_long_value(op->gatt, op->handle, length,
							read_long_cb,
							async_read_op_ref(op),
							async_read_op_unref))
		return;

	async_read_op_unref(op);
	success = false;

done:
	complete_read(op, success, att_ecode, value, length);
}

static bool desc_read_complete(const uint8_t *value, size_t len, void *data)
{
	struct descriptor *desc = data;

	desc->in_read = false;

	/*
	 * The descriptor might have been unregistered during the read. Return
	 * failure.
	 */
	if (!desc->chrc)
		return false;

	update_value_property(value, len, &desc->value, &desc->value_len,
						&desc->value_known, desc->path,
						GATT_DESCRIPTOR_IFACE, false);

	return true;
}

static DBusMessage *descriptor_read_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct descriptor *desc = user_data;
	struct bt_gatt_client *gatt = desc->chrc->service->client->gatt;
	struct async_read_op *op;

	if (desc->in_read)
		return btd_error_in_progress(msg);

	op = new0(struct async_read_op, 1);
	if (!op)
		return btd_error_failed(msg, "Failed to initialize request");

	op->msg = dbus_message_ref(msg);
	op->gatt = gatt;
	op->handle = desc->handle;
	op->data = descriptor_ref(desc);
	op->complete = desc_read_complete;
	op->destroy = descriptor_unref;

	if (bt_gatt_client_read_value(gatt, desc->handle, read_cb,
							async_read_op_ref(op),
							async_read_op_unref)) {
		desc->in_read = true;
		return NULL;
	}

	async_read_op_unref(op);

	return btd_error_failed(msg, "Failed to send read request");
}

static void write_result_cb(bool success, bool reliable_error,
					uint8_t att_ecode, void *user_data)
{
	struct async_dbus_op *op = user_data;
	DBusMessage *reply;

	if (op->complete && !op->complete(op->data)) {
		reply = btd_error_failed(op->msg, "Operation failed");
		goto done;
	}

	if (!success) {
		if (reliable_error)
			reply = btd_error_failed(op->msg,
						"Reliable write failed");
		else
			reply = create_gatt_dbus_error(op->msg, att_ecode);

		goto done;
	}

	reply = g_dbus_create_reply(op->msg, DBUS_TYPE_INVALID);
	if (!reply) {
		error("Failed to allocate D-Bus message reply");
		return;
	}

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);
}


static void write_cb(bool success, uint8_t att_ecode, void *user_data)
{
	write_result_cb(success, false, att_ecode, user_data);
}

static bool start_long_write(DBusMessage *msg, uint16_t handle,
					struct bt_gatt_client *gatt,
					bool reliable, const uint8_t *value,
					size_t value_len, void *data,
					async_dbus_op_complete_t complete,
					async_dbus_op_destroy_t destroy)
{
	struct async_dbus_op *op;

	op = new0(struct async_dbus_op, 1);
	if (!op)
		return false;

	op->msg = dbus_message_ref(msg);
	op->data = data;
	op->complete = complete;
	op->destroy = destroy;

	if (bt_gatt_client_write_long_value(gatt, reliable, handle,
							0, value, value_len,
							write_result_cb, op,
							async_dbus_op_free))
		return true;

	async_dbus_op_free(op);

	return false;
}

static bool start_write_request(DBusMessage *msg, uint16_t handle,
					struct bt_gatt_client *gatt,
					const uint8_t *value, size_t value_len,
					void *data,
					async_dbus_op_complete_t complete,
					async_dbus_op_destroy_t destroy)
{
	struct async_dbus_op *op;

	op = new0(struct async_dbus_op, 1);
	if (!op)
		return false;

	op->msg = dbus_message_ref(msg);
	op->data = data;
	op->complete = complete;
	op->destroy = destroy;

	if (bt_gatt_client_write_value(gatt, handle, value, value_len,
							write_cb, op,
							async_dbus_op_free))
		return true;

	async_dbus_op_free(op);

	return false;
}

static bool desc_write_complete(void *data)
{
	struct descriptor *desc = data;

	desc->in_write = false;

	/*
	 * The descriptor might have been unregistered during the read. Return
	 * failure.
	 */
	return !!desc->chrc;
}

static DBusMessage *descriptor_write_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct descriptor *desc = user_data;
	struct bt_gatt_client *gatt = desc->chrc->service->client->gatt;
	uint8_t *value = NULL;
	size_t value_len = 0;
	bool result;

	if (desc->in_write)
		return btd_error_in_progress(msg);

	if (!parse_value_arg(msg, &value, &value_len))
		return btd_error_invalid_args(msg);

	/*
	 * Don't allow writing to Client Characteristic Configuration
	 * descriptors. We achieve this through the StartNotify and StopNotify
	 * methods on GattCharacteristic1.
	 */
	if (uuid_cmp(&desc->uuid, GATT_CLIENT_CHARAC_CFG_UUID))
		return gatt_error_write_not_permitted(msg);

	/*
	 * Based on the value length and the MTU, either use a write or a long
	 * write.
	 */
	if (value_len <= (unsigned) bt_gatt_client_get_mtu(gatt) - 3)
		result = start_write_request(msg, desc->handle, gatt, value,
							value_len, desc,
							desc_write_complete,
							descriptor_unref);
	else
		result = start_long_write(msg, desc->handle, gatt, false, value,
							value_len, desc,
							desc_write_complete,
							descriptor_unref);

	if (!result)
		return btd_error_failed(msg, "Failed to initiate write");

	desc->in_write = true;

	return NULL;
}

static const GDBusPropertyTable descriptor_properties[] = {
	{ "UUID", "s", descriptor_property_get_uuid },
	{ "Characteristic", "o", descriptor_property_get_characteristic },
	{ "Value", "ay", descriptor_property_get_value, NULL,
					descriptor_property_value_exists },
	{ }
};

static const GDBusMethodTable descriptor_methods[] = {
	{ GDBUS_ASYNC_METHOD("ReadValue", NULL, GDBUS_ARGS({ "value", "ay" }),
						descriptor_read_value) },
	{ GDBUS_ASYNC_METHOD("WriteValue", GDBUS_ARGS({ "value", "ay" }),
					NULL, descriptor_write_value) },
	{ }
};

static struct descriptor *descriptor_create(struct gatt_db_attribute *attr,
						struct characteristic *chrc)
{
	struct descriptor *desc;

	desc = new0(struct descriptor, 1);
	if (!desc)
		return NULL;

	desc->chrc = chrc;
	desc->handle = gatt_db_attribute_get_handle(attr);

	bt_uuid_to_uuid128(gatt_db_attribute_get_type(attr), &desc->uuid);

	desc->path = g_strdup_printf("%s/desc%04x", chrc->path, desc->handle);

	if (!g_dbus_register_interface(btd_get_dbus_connection(), desc->path,
						GATT_DESCRIPTOR_IFACE,
						descriptor_methods, NULL,
						descriptor_properties,
						descriptor_ref(desc),
						descriptor_unref)) {
		error("Unable to register GATT descriptor with handle 0x%04x",
								desc->handle);
		descriptor_unref(desc);

		return NULL;
	}

	DBG("Exported GATT characteristic descriptor: %s", desc->path);

	if (uuid_cmp(&desc->uuid, GATT_CHARAC_EXT_PROPER_UUID))
		chrc->ext_props_handle = desc->handle;

	return desc;
}

static void unregister_descriptor(void *data)
{
	struct descriptor *desc = data;

	DBG("Removing GATT descriptor: %s", desc->path);

	desc->chrc = NULL;

	g_dbus_unregister_interface(btd_get_dbus_connection(), desc->path,
							GATT_DESCRIPTOR_IFACE);
}

static gboolean characteristic_property_get_uuid(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	char uuid[MAX_LEN_UUID_STR + 1];
	const char *ptr = uuid;
	struct characteristic *chrc = data;

	bt_uuid_to_string(&chrc->uuid, uuid, sizeof(uuid));
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ptr);

	return TRUE;
}

static gboolean characteristic_property_get_service(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chrc = data;
	const char *str = chrc->service->path;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &str);

	return TRUE;
}

static gboolean characteristic_property_get_value(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chrc = data;
	DBusMessageIter array;
	size_t i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "y", &array);

	if (chrc->value_known) {
		for (i = 0; i < chrc->value_len; i++)
			dbus_message_iter_append_basic(&array, DBUS_TYPE_BYTE,
							chrc->value + i);
	}

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean characteristic_property_value_exists(
					const GDBusPropertyTable *property,
					void *data)
{
	struct characteristic *chrc = data;

	return chrc->value_known ? TRUE : FALSE;
}

static gboolean characteristic_property_get_notifying(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chrc = data;
	dbus_bool_t notifying = chrc->notifying ? TRUE : FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &notifying);

	return TRUE;
}

static struct {
	uint8_t prop;
	char *str;
} properties[] = {
	/* Default Properties */
	{ BT_GATT_CHRC_PROP_BROADCAST,		"broadcast" },
	{ BT_GATT_CHRC_PROP_READ,		"read" },
	{ BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,	"write-without-response" },
	{ BT_GATT_CHRC_PROP_WRITE,		"write" },
	{ BT_GATT_CHRC_PROP_NOTIFY,		"notify" },
	{ BT_GATT_CHRC_PROP_INDICATE,		"indicate" },
	{ BT_GATT_CHRC_PROP_AUTH,		"authenticated-signed-writes" },
	{ BT_GATT_CHRC_PROP_EXT_PROP,		"extended-properties" },
	/* Extended Properties */
	{ BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE,	"reliable-write" },
	{ BT_GATT_CHRC_EXT_PROP_WRITABLE_AUX,	"writable-auxiliaries" },
	{ }
};
static const int ext_props_index = 8;

static gboolean characteristic_property_get_flags(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chrc = data;
	DBusMessageIter array;
	uint16_t props;
	int i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "s", &array);

	for (i = 0; properties[i].str; i++) {
		props = i < ext_props_index ? chrc->props : chrc->ext_props;
		if (props & properties[i].prop)
			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
							&properties[i].str);
	}

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static bool chrc_read_complete(const uint8_t *value, size_t len, void *data)
{
	struct characteristic *chrc = data;

	chrc->in_read = false;

	/*
	 * The characteristic might have been unregistered during the read.
	 * Return failure.
	 */
	if (!chrc->service)
		return false;

	update_value_property(value, len, &chrc->value, &chrc->value_len,
						&chrc->value_known, chrc->path,
						GATT_CHARACTERISTIC_IFACE,
						false);

	return true;
}

static DBusMessage *characteristic_read_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct characteristic *chrc = user_data;
	struct bt_gatt_client *gatt = chrc->service->client->gatt;
	struct async_read_op *op;

	if (chrc->in_read)
		return btd_error_in_progress(msg);

	if (!(chrc->props & BT_GATT_CHRC_PROP_READ))
		return gatt_error_read_not_permitted(msg);

	op = new0(struct async_read_op, 1);
	if (!op)
		return btd_error_failed(msg, "Failed to initialize request");

	op->msg = dbus_message_ref(msg);
	op->gatt = gatt;
	op->handle = chrc->value_handle;
	op->data = characteristic_ref(chrc);
	op->complete = chrc_read_complete;
	op->destroy = characteristic_unref;

	/*
	 * A remote server may support the "read" procedure but may not support
	 * a "long read". Hence, we start with the regular read procedure and
	 * proceed to a long read only if necessary.
	 */
	if (bt_gatt_client_read_value(gatt, chrc->value_handle, read_cb,
							async_read_op_ref(op),
							async_read_op_unref)) {
		chrc->in_read = true;
		return NULL;
	}

	async_read_op_unref(op);

	return btd_error_failed(msg, "Failed to send read request");
}

static bool chrc_write_complete(void *data)
{
	struct characteristic *chrc = data;

	chrc->in_write = false;

	/*
	 * The characteristic might have been unregistered during the read.
	 * Return failure.
	 */
	return !!chrc->service;
}

static DBusMessage *characteristic_write_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct characteristic *chrc = user_data;
	struct bt_gatt_client *gatt = chrc->service->client->gatt;
	uint8_t *value = NULL;
	size_t value_len = 0;

	if (chrc->in_write)
		return btd_error_in_progress(msg);

	if (!parse_value_arg(msg, &value, &value_len))
		return btd_error_invalid_args(msg);

	if (!(chrc->props & (BT_GATT_CHRC_PROP_WRITE |
					BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP)))
		if (!(chrc->ext_props & BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE))
			return btd_error_not_supported(msg);

	/*
	 * Decide which write to use based on characteristic properties. For now
	 * we don't perform signed writes since gatt-client doesn't support them
	 * and the user can always encrypt the through pairing. The procedure to
	 * use is determined based on the following priority:
	 *
	 *   * "reliable-write" property set -> reliable long-write.
	 *   * "write" property set -> write request.
	 *     - If value is larger than MTU - 3: long-write
	 *   * "write-without-response" property set -> write command.
	 */
	if ((chrc->ext_props & BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE) &&
			start_long_write(msg, chrc->value_handle, gatt, true,
						value, value_len,
						characteristic_ref(chrc),
						chrc_write_complete,
						characteristic_unref))
		goto done_async;

	if (chrc->props & BT_GATT_CHRC_PROP_WRITE) {
		uint16_t mtu;
		bool result;

		mtu = bt_gatt_client_get_mtu(gatt);
		if (!mtu)
			return btd_error_failed(msg, "No ATT transport");

		if (value_len <= (unsigned) mtu - 3)
			result = start_write_request(msg, chrc->value_handle,
						gatt, value, value_len,
						characteristic_ref(chrc),
						chrc_write_complete,
						characteristic_unref);
		else
			result = start_long_write(msg, chrc->value_handle, gatt,
						false, value, value_len,
						characteristic_ref(chrc),
						chrc_write_complete,
						characteristic_unref);

		if (result)
			goto done_async;
	}

	if ((chrc->props & BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP) &&
			bt_gatt_client_write_without_response(gatt,
							chrc->value_handle,
							false, value,
							value_len))
		return dbus_message_new_method_return(msg);

	return btd_error_failed(msg, "Failed to initiate write");

done_async:
	chrc->in_write = true;

	return NULL;
}

struct notify_client {
	struct characteristic *chrc;
	int ref_count;
	char *owner;
	guint watch;
	unsigned int notify_id;
};

static void notify_client_free(struct notify_client *client)
{
	DBG("owner %s", client->owner);

	g_dbus_remove_watch(btd_get_dbus_connection(), client->watch);
	free(client->owner);
	free(client);
}

static void notify_client_unref(void *data)
{
	struct notify_client *client = data;

	DBG("owner %s", client->owner);

	if (__sync_sub_and_fetch(&client->ref_count, 1))
		return;

	notify_client_free(client);
}

static struct notify_client *notify_client_ref(struct notify_client *client)
{
	DBG("owner %s", client->owner);

	__sync_fetch_and_add(&client->ref_count, 1);

	return client;
}

static bool match_notifying(const void *a, const void *b)
{
	const struct notify_client *client = a;

	return !!client->notify_id;
}

static void update_notifying(struct characteristic *chrc)
{
	if (!chrc->notifying)
		return;

	if (queue_find(chrc->notify_clients, match_notifying, NULL))
		return;

	chrc->notifying = false;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), chrc->path,
						GATT_CHARACTERISTIC_IFACE,
						"Notifying");
}

static void notify_client_disconnect(DBusConnection *conn, void *user_data)
{
	struct notify_client *client = user_data;
	struct characteristic *chrc = client->chrc;
	struct bt_gatt_client *gatt = chrc->service->client->gatt;

	DBG("owner %s", client->owner);

	queue_remove(chrc->notify_clients, client);
	bt_gatt_client_unregister_notify(gatt, client->notify_id);

	update_notifying(chrc);

	notify_client_unref(client);
}

static struct notify_client *notify_client_create(struct characteristic *chrc,
							const char *owner)
{
	struct notify_client *client;

	client = new0(struct notify_client, 1);
	if (!client)
		return NULL;

	client->chrc = chrc;
	client->owner = strdup(owner);
	if (!client->owner) {
		free(client);
		return NULL;
	}

	client->watch = g_dbus_add_disconnect_watch(btd_get_dbus_connection(),
						owner, notify_client_disconnect,
						client, NULL);
	if (!client->watch) {
		free(client->owner);
		free(client);
		return NULL;
	}

	return notify_client_ref(client);
}

static bool match_notify_sender(const void *a, const void *b)
{
	const struct notify_client *client = a;
	const char *sender = b;

	return strcmp(client->owner, sender) == 0;
}

struct register_notify_op {
	int ref_count;
	struct notify_client *client;
	struct characteristic *chrc;
};

static void register_notify_op_unref(void *data)
{
	struct register_notify_op *op = data;

	DBG("Released register_notify_op");

	if (__sync_sub_and_fetch(&op->ref_count, 1))
		return;

	notify_client_unref(op->client);
	characteristic_unref(op->chrc);

	free(op);
}

static void notify_cb(uint16_t value_handle, const uint8_t *value,
					uint16_t length, void *user_data)
{
	struct async_dbus_op *op = user_data;
	struct register_notify_op *notify_op = op->data;
	struct characteristic *chrc = notify_op->chrc;

	/*
	 * Even if the value didn't change, we want to send a PropertiesChanged
	 * signal so that we propagate the notification/indication to
	 * applications.
	 */
	update_value_property(value, length, &chrc->value, &chrc->value_len,
						&chrc->value_known, chrc->path,
						GATT_CHARACTERISTIC_IFACE,
						true);
}

static void register_notify_cb(unsigned int id, uint16_t att_ecode,
								void *user_data)
{
	struct async_dbus_op *op = user_data;
	struct register_notify_op *notify_op = op->data;
	struct notify_client *client = notify_op->client;
	struct characteristic *chrc = notify_op->chrc;
	DBusMessage *reply;

	/*
	 * Make sure that an interim disconnect or "Service Changed" did not
	 * remove the client
	 */
	if (!chrc->service || !queue_find(chrc->notify_clients, NULL, client)) {
		bt_gatt_client_unregister_notify(chrc->service->client->gatt,
									id);

		reply = btd_error_failed(op->msg,
						"Characteristic not available");
		goto done;
	}

	if (!id) {
		queue_remove(chrc->notify_clients, client);
		notify_client_free(client);

		reply = create_gatt_dbus_error(op->msg, att_ecode);

		goto done;
	}

	client->notify_id = id;

	if (!chrc->notifying) {
		chrc->notifying = true;
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
					chrc->path, GATT_CHARACTERISTIC_IFACE,
					"Notifying");
	}

	reply = g_dbus_create_reply(op->msg, DBUS_TYPE_INVALID);

done:
	if (reply)
		g_dbus_send_message(btd_get_dbus_connection(), reply);
	else
		error("Failed to construct D-Bus message reply");

	dbus_message_unref(op->msg);
	op->msg = NULL;
}

static DBusMessage *characteristic_start_notify(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct characteristic *chrc = user_data;
	struct bt_gatt_client *gatt = chrc->service->client->gatt;
	const char *sender = dbus_message_get_sender(msg);
	struct async_dbus_op *op;
	struct notify_client *client;
	struct register_notify_op *notify_op;

	if (!(chrc->props & BT_GATT_CHRC_PROP_NOTIFY ||
				chrc->props & BT_GATT_CHRC_PROP_INDICATE))
		return btd_error_not_supported(msg);

	/* Each client can only have one active notify session. */
	client = queue_find(chrc->notify_clients, match_notify_sender, sender);
	if (client)
		return client->notify_id ?
				btd_error_failed(msg, "Already notifying") :
				btd_error_in_progress(msg);

	client = notify_client_create(chrc, sender);
	if (!client)
		return btd_error_failed(msg, "Failed allocate notify session");

	notify_op = new0(struct register_notify_op, 1);
	if (!notify_op) {
		notify_client_unref(client);
		return btd_error_failed(msg, "Failed to initialize request");
	}

	notify_op->ref_count = 1;
	notify_op->client = client;
	notify_op->chrc = characteristic_ref(chrc);

	op = new0(struct async_dbus_op, 1);
	if (!op) {
		register_notify_op_unref(notify_op);
		return btd_error_failed(msg, "Failed to initialize request");
	}

	op->data = notify_op;
	op->msg = dbus_message_ref(msg);
	op->destroy = register_notify_op_unref;

	/* The characteristic owns a reference to the client */
	queue_push_tail(chrc->notify_clients, notify_client_ref(client));

	if (bt_gatt_client_register_notify(gatt, chrc->value_handle,
						register_notify_cb, notify_cb,
						op, async_dbus_op_free))
		return NULL;

	queue_remove(chrc->notify_clients, client);
	async_dbus_op_free(op);

	return btd_error_failed(msg, "Failed to register notify session");
}

static DBusMessage *characteristic_stop_notify(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct characteristic *chrc = user_data;
	struct bt_gatt_client *gatt = chrc->service->client->gatt;
	const char *sender = dbus_message_get_sender(msg);
	struct notify_client *client;

	if (!chrc->notifying)
		return btd_error_failed(msg, "Not notifying");

	client = queue_remove_if(chrc->notify_clients, match_notify_sender,
							(void *) sender);
	if (!client)
		return btd_error_failed(msg, "No notify session started");

	bt_gatt_client_unregister_notify(gatt, client->notify_id);
	update_notifying(chrc);

	notify_client_unref(client);

	return dbus_message_new_method_return(msg);
}

static void append_desc_path(void *data, void *user_data)
{
	struct descriptor *desc = data;
	DBusMessageIter *array = user_data;

	dbus_message_iter_append_basic(array, DBUS_TYPE_OBJECT_PATH,
								&desc->path);
}

static gboolean characteristic_property_get_descriptors(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chrc = data;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "o", &array);

	queue_foreach(chrc->descs, append_desc_path, &array);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static const GDBusPropertyTable characteristic_properties[] = {
	{ "UUID", "s", characteristic_property_get_uuid },
	{ "Service", "o", characteristic_property_get_service },
	{ "Value", "ay", characteristic_property_get_value, NULL,
					characteristic_property_value_exists },
	{ "Notifying", "b", characteristic_property_get_notifying },
	{ "Flags", "as", characteristic_property_get_flags },
	{ "Descriptors", "ao", characteristic_property_get_descriptors },
	{ }
};

static const GDBusMethodTable characteristic_methods[] = {
	{ GDBUS_ASYNC_METHOD("ReadValue", NULL, GDBUS_ARGS({ "value", "ay" }),
						characteristic_read_value) },
	{ GDBUS_ASYNC_METHOD("WriteValue", GDBUS_ARGS({ "value", "ay" }),
					NULL, characteristic_write_value) },
	{ GDBUS_ASYNC_METHOD("StartNotify", NULL, NULL,
						characteristic_start_notify) },
	{ GDBUS_METHOD("StopNotify", NULL, NULL, characteristic_stop_notify) },
	{ }
};

static struct characteristic *characteristic_create(
						struct gatt_db_attribute *attr,
						struct service *service)
{
	struct characteristic *chrc;
	bt_uuid_t uuid;

	chrc = new0(struct characteristic, 1);
	if (!chrc)
		return NULL;

	chrc->descs = queue_new();
	if (!chrc->descs) {
		free(chrc);
		return NULL;
	}

	chrc->notify_clients = queue_new();
	if (!chrc->notify_clients) {
		queue_destroy(chrc->descs, NULL);
		free(chrc);
		return NULL;
	}

	chrc->service = service;

	gatt_db_attribute_get_char_data(attr, &chrc->handle,
							&chrc->value_handle,
							&chrc->props, &uuid);
	bt_uuid_to_uuid128(&uuid, &chrc->uuid);

	chrc->path = g_strdup_printf("%s/char%04x", service->path,
								chrc->handle);

	if (!g_dbus_register_interface(btd_get_dbus_connection(), chrc->path,
						GATT_CHARACTERISTIC_IFACE,
						characteristic_methods, NULL,
						characteristic_properties,
						characteristic_ref(chrc),
						characteristic_unref)) {
		error("Unable to register GATT characteristic with handle "
							"0x%04x", chrc->handle);
		characteristic_unref(chrc);

		return NULL;
	}

	DBG("Exported GATT characteristic: %s", chrc->path);

	return chrc;
}

static void unregister_characteristic(void *data)
{
	struct characteristic *chrc = data;

	DBG("Removing GATT characteristic: %s", chrc->path);

	queue_remove_all(chrc->notify_clients, NULL, NULL, notify_client_unref);
	queue_remove_all(chrc->descs, NULL, NULL, unregister_descriptor);

	chrc->service = NULL;

	g_dbus_unregister_interface(btd_get_dbus_connection(), chrc->path,
						GATT_CHARACTERISTIC_IFACE);
}

static gboolean service_property_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	char uuid[MAX_LEN_UUID_STR + 1];
	const char *ptr = uuid;
	struct service *service = data;

	bt_uuid_to_string(&service->uuid, uuid, sizeof(uuid));
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ptr);

	return TRUE;
}

static gboolean service_property_get_device(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct service *service = data;
	const char *str = device_get_path(service->client->device);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &str);

	return TRUE;
}

static gboolean service_property_get_primary(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct service *service = data;
	dbus_bool_t primary;

	primary = service->primary ? TRUE : FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &primary);

	return TRUE;
}

static void append_chrc_path(void *data, void *user_data)
{
	struct characteristic *chrc = data;
	DBusMessageIter *array = user_data;

	dbus_message_iter_append_basic(array, DBUS_TYPE_OBJECT_PATH,
								&chrc->path);
}

static gboolean service_property_get_characteristics(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct service *service = data;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "o", &array);

	if (service->chrcs_ready)
		queue_foreach(service->chrcs, append_chrc_path, &array);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static const GDBusPropertyTable service_properties[] = {
	{ "UUID", "s", service_property_get_uuid },
	{ "Device", "o", service_property_get_device },
	{ "Primary", "b", service_property_get_primary },
	{ "Characteristics", "ao", service_property_get_characteristics },
	{ }
};

static void service_free(void *data)
{
	struct service *service = data;

	queue_destroy(service->chrcs, NULL);  /* List should be empty here */
	queue_destroy(service->pending_ext_props, NULL);
	g_free(service->path);
	free(service);
}

static struct service *service_create(struct gatt_db_attribute *attr,
						struct btd_gatt_client *client)
{
	struct service *service;
	const char *device_path = device_get_path(client->device);
	bt_uuid_t uuid;

	service = new0(struct service, 1);
	if (!service)
		return NULL;

	service->chrcs = queue_new();
	if (!service->chrcs) {
		free(service);
		return NULL;
	}

	service->pending_ext_props = queue_new();
	if (!service->pending_ext_props) {
		queue_destroy(service->chrcs, NULL);
		free(service);
		return NULL;
	}

	service->client = client;

	gatt_db_attribute_get_service_data(attr, &service->start_handle,
							&service->end_handle,
							&service->primary,
							&uuid);
	bt_uuid_to_uuid128(&uuid, &service->uuid);

	service->path = g_strdup_printf("%s/service%04x", device_path,
							service->start_handle);

	if (!g_dbus_register_interface(btd_get_dbus_connection(), service->path,
						GATT_SERVICE_IFACE,
						NULL, NULL,
						service_properties,
						service, service_free)) {
		error("Unable to register GATT service with handle 0x%04x for "
							"device %s:",
							service->start_handle,
							client->devaddr);
		service_free(service);

		return NULL;
	}

	DBG("Exported GATT service: %s", service->path);

	return service;
}

static void unregister_service(void *data)
{
	struct service *service = data;

	DBG("Removing GATT service: %s", service->path);

	if (service->idle_id)
		g_source_remove(service->idle_id);

	queue_remove_all(service->chrcs, NULL, NULL, unregister_characteristic);

	g_dbus_unregister_interface(btd_get_dbus_connection(), service->path,
							GATT_SERVICE_IFACE);
}

static void notify_chrcs(struct service *service)
{

	if (service->chrcs_ready ||
				!queue_isempty(service->pending_ext_props))
		return;

	service->chrcs_ready = true;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), service->path,
							GATT_SERVICE_IFACE,
							"Characteristics");
}

struct export_data {
	void *root;
	bool failed;
};

static void export_desc(struct gatt_db_attribute *attr, void *user_data)
{
	struct descriptor *desc;
	struct export_data *data = user_data;
	struct characteristic *charac = data->root;

	if (data->failed)
		return;

	desc = descriptor_create(attr, charac);
	if (!desc) {
		data->failed = true;
		return;
	}

	queue_push_tail(charac->descs, desc);
}

static void read_ext_props_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct characteristic *chrc = user_data;
	struct service *service = chrc->service;

	if (!success) {
		error("Failed to obtain extended properties - error: 0x%02x",
								att_ecode);
		return;
	}

	if (!value || length != 2) {
		error("Malformed extended properties value");
		return;
	}

	chrc->ext_props = get_le16(value);
	if (chrc->ext_props)
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
						service->path,
						GATT_SERVICE_IFACE, "Flags");

	queue_remove(service->pending_ext_props, chrc);

	notify_chrcs(service);
}

static void read_ext_props(void *data, void *user_data)
{
	struct characteristic *chrc = data;

	bt_gatt_client_read_value(chrc->service->client->gatt,
							chrc->ext_props_handle,
							read_ext_props_cb,
							chrc, NULL);
}

static bool create_descriptors(struct gatt_db_attribute *attr,
					struct characteristic *charac)
{
	struct export_data data;

	data.root = charac;
	data.failed = false;

	gatt_db_service_foreach_desc(attr, export_desc, &data);

	return !data.failed;
}

static void export_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct characteristic *charac;
	struct export_data *data = user_data;
	struct service *service = data->root;

	if (data->failed)
		return;

	charac = characteristic_create(attr, service);
	if (!charac)
		goto fail;

	if (!create_descriptors(attr, charac)) {
		unregister_characteristic(charac);
		goto fail;
	}

	queue_push_tail(service->chrcs, charac);

	if (charac->ext_props_handle)
		queue_push_tail(service->pending_ext_props, charac);

	return;

fail:
	data->failed = true;
}

static bool create_characteristics(struct gatt_db_attribute *attr,
						struct service *service)
{
	struct export_data data;

	data.root = service;
	data.failed = false;

	gatt_db_service_foreach_char(attr, export_char, &data);

	if (data.failed)
		return false;

	/* Obtain extended properties */
	queue_foreach(service->pending_ext_props, read_ext_props, NULL);

	return true;
}

static gboolean set_chrcs_ready(gpointer user_data)
{
	struct service *service = user_data;

	notify_chrcs(service);

	return FALSE;
}

static void export_service(struct gatt_db_attribute *attr, void *user_data)
{
	struct btd_gatt_client *client = user_data;
	struct service *service;

	service = service_create(attr, client);
	if (!service)
		return;

	if (!create_characteristics(attr, service)) {
		error("Exporting characteristics failed");
		unregister_service(service);
		return;
	}

	queue_push_tail(client->services, service);

	/*
	 * Asynchronously update the "Characteristics" property of the service.
	 * If there are any pending reads to obtain the value of the "Extended
	 * Properties" descriptor then wait until they are complete.
	 */
	if (!service->chrcs_ready && queue_isempty(service->pending_ext_props))
		service->idle_id = g_idle_add(set_chrcs_ready, service);
}

static void create_services(struct btd_gatt_client *client)
{
	DBG("Exporting objects for GATT services: %s", client->devaddr);

	gatt_db_foreach_service(client->db, NULL, export_service, client);
}

struct btd_gatt_client *btd_gatt_client_new(struct btd_device *device)
{
	struct btd_gatt_client *client;
	struct gatt_db *db;

	if (!device)
		return NULL;

	db = btd_device_get_gatt_db(device);
	if (!db)
		return NULL;

	client = new0(struct btd_gatt_client, 1);
	if (!client)
		return NULL;

	client->services = queue_new();
	if (!client->services) {
		free(client);
		return NULL;
	}

	client->device = device;
	ba2str(device_get_address(device), client->devaddr);

	client->db = gatt_db_ref(db);

	return client;
}

void btd_gatt_client_destroy(struct btd_gatt_client *client)
{
	if (!client)
		return;

	queue_destroy(client->services, unregister_service);
	bt_gatt_client_unref(client->gatt);
	gatt_db_unref(client->db);
	free(client);
}

void btd_gatt_client_ready(struct btd_gatt_client *client)
{
	struct bt_gatt_client *gatt;

	if (!client)
		return;

	gatt = btd_device_get_gatt_client(client->device);
	if (!gatt) {
		error("GATT client not initialized");
		return;
	}

	bt_gatt_client_unref(client->gatt);
	client->gatt = bt_gatt_client_ref(gatt);

	create_services(client);
}

void btd_gatt_client_service_added(struct btd_gatt_client *client,
					struct gatt_db_attribute *attrib)
{
	if (!client)
		return;

	export_service(attrib, client);
}

static bool match_service_handle(const void *a, const void *b)
{
	const struct service *service = a;
	uint16_t start_handle = PTR_TO_UINT(b);

	return service->start_handle == start_handle;
}

void btd_gatt_client_service_removed(struct btd_gatt_client *client,
					struct gatt_db_attribute *attrib)
{
	uint16_t start_handle, end_handle;

	if (!client || !attrib)
		return;

	gatt_db_attribute_get_service_handles(attrib, &start_handle,
								&end_handle);

	DBG("GATT Services Removed - start: 0x%04x, end: 0x%04x", start_handle,
								end_handle);
	queue_remove_all(client->services, match_service_handle,
						UINT_TO_PTR(start_handle),
						unregister_service);
}

void btd_gatt_client_disconnected(struct btd_gatt_client *client)
{
	if (!client)
		return;

	DBG("Device disconnected. Cleaning up");

	/*
	 * Remove all services. We'll recreate them when a new bt_gatt_client
	 * becomes ready.
	 */
	queue_remove_all(client->services, NULL, NULL, unregister_service);

	bt_gatt_client_unref(client->gatt);
	client->gatt = NULL;
}

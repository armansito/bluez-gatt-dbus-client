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
#include "gatt-client.h"
#include "dbus-common.h"
#include "src/shared/att.h"
#include "src/shared/gatt-client.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "gatt-callbacks.h"
#include "lib/uuid.h"

#define GATT_SERVICE_IFACE		"org.bluez.GattService1"
#define GATT_CHARACTERISTIC_IFACE	"org.bluez.GattCharacteristic1"
#define GATT_DESCRIPTOR_IFACE		"org.bluez.GattDescriptor1"

struct btd_gatt_client {
	struct btd_device *device;
	char devaddr[18];
	struct bt_gatt_client *gatt;
	unsigned int gatt_cb_id;

	struct queue *services;
};

struct service {
	struct btd_gatt_client *client;
	bool primary;
	uint16_t start_handle;
	uint16_t end_handle;
	uint8_t uuid[BT_GATT_UUID_SIZE];
	char *path;
	struct queue *chrcs;
	bool chrcs_ready;
	struct queue *pending_ext_props;
};

struct characteristic {
	struct service *service;
	uint16_t handle;
	uint16_t value_handle;
	uint8_t props;
	uint16_t ext_props;
	uint16_t ext_props_handle;
	uint8_t uuid[BT_GATT_UUID_SIZE];
	char *path;

	bool in_read;
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
	uint8_t uuid[BT_GATT_UUID_SIZE];
	char *path;

	bool in_read;
	bool value_known;
	uint8_t *value;
	size_t value_len;
};

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

static bool uuid_cmp(const uint8_t uuid[16], uint16_t u16)
{
	uint128_t u128;
	bt_uuid_t uuid128;
	bt_uuid_t uuid16;

	memcpy(u128.data, uuid, sizeof(uint8_t) * 16);
	bt_uuid128_create(&uuid128, u128);
	bt_uuid16_create(&uuid16, u16);

	return bt_uuid_cmp(&uuid128, &uuid16) == 0;
}

static void uuid128_to_string(const uint8_t uuid[16], char *str, size_t n)
{
	uint128_t u128;
	bt_uuid_t uuid128;

	memcpy(u128.data, uuid, sizeof(uint8_t) * 16);
	bt_uuid128_create(&uuid128, u128);
	bt_uuid_to_string(&uuid128, str, n);
}

static gboolean descriptor_property_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	char uuid[MAX_LEN_UUID_STR + 1];
	const char *ptr = uuid;
	struct descriptor *desc = data;

	uuid128_to_string(desc->uuid, uuid, sizeof(uuid));
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

struct async_dbus_op {
	DBusMessage *msg;
	void *data;
};

static void async_dbus_op_free(void *data)
{
	struct async_dbus_op *op = data;

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

static void desc_read_long_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct async_dbus_op *op = user_data;
	struct descriptor *desc = op->data;
	DBusMessage *reply;

	desc->in_read = false;

	if (!success) {
		reply = create_gatt_dbus_error(op->msg, att_ecode);
		goto done;
	}

	update_value_property(value, length, &desc->value, &desc->value_len,
						&desc->value_known, desc->path,
						GATT_DESCRIPTOR_IFACE, false);

	reply = g_dbus_create_reply(op->msg, DBUS_TYPE_INVALID);
	if (!reply) {
		error("Failed to allocate D-Bus message reply");
		return;
	}

	message_append_byte_array(reply, value, length);

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);
}

static DBusMessage *descriptor_read_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct descriptor *desc = user_data;
	struct bt_gatt_client *gatt = desc->chrc->service->client->gatt;
	struct async_dbus_op *op;

	if (desc->in_read)
		return btd_error_in_progress(msg);

	op = new0(struct async_dbus_op, 1);
	if (!op)
		return btd_error_failed(msg, "Failed to initialize request");

	op->msg = dbus_message_ref(msg);
	op->data = desc;

	if (bt_gatt_client_read_long_value(gatt, desc->handle, 0,
							desc_read_long_cb, op,
							async_dbus_op_free)) {
		desc->in_read = true;
		return NULL;
	}

	async_dbus_op_free(op);

	return btd_error_failed(msg, "Failed to send read request");
}

static DBusMessage *descriptor_write_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	/* TODO: Implement */
	return btd_error_failed(msg, "Not implemented");
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

static void descriptor_free(void *data)
{
	struct descriptor *desc = data;

	free(desc->value);
	g_free(desc->path);
	free(desc);
}

static struct descriptor *descriptor_create(
					const bt_gatt_descriptor_t *desc_data,
					struct characteristic *chrc)
{
	struct descriptor *desc;

	desc = new0(struct descriptor, 1);
	if (!desc)
		return NULL;

	desc->path = g_strdup_printf("%s/desc%04x", chrc->path,
							desc_data->handle);
	desc->chrc = chrc;
	desc->handle = desc_data->handle;

	memcpy(desc->uuid, desc_data->uuid, sizeof(desc->uuid));

	if (!g_dbus_register_interface(btd_get_dbus_connection(), desc->path,
						GATT_DESCRIPTOR_IFACE,
						descriptor_methods, NULL,
						descriptor_properties,
						desc, descriptor_free)) {
		error("Unable to register GATT descriptor with handle 0x%04x",
								desc->handle);
		descriptor_free(desc);

		return NULL;
	}

	DBG("Exported GATT characteristic descriptor: %s", desc->path);

	if (uuid_cmp(desc->uuid, GATT_CHARAC_EXT_PROPER_UUID))
		chrc->ext_props_handle = desc->handle;

	return desc;
}

static void unregister_descriptor(void *data)
{
	struct descriptor *desc = data;

	DBG("Removing GATT descriptor: %s", desc->path);

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

	uuid128_to_string(chrc->uuid, uuid, sizeof(uuid));
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

static void chrc_read_long_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct async_dbus_op *op = user_data;
	struct characteristic *chrc = op->data;
	DBusMessage *reply;
	size_t i;

	chrc->in_read = false;

	if (!success) {
		reply = create_gatt_dbus_error(op->msg, att_ecode);
		goto done;
	}

	update_value_property(value, length, &chrc->value, &chrc->value_len,
						&chrc->value_known, chrc->path,
						GATT_CHARACTERISTIC_IFACE,
						false);

	reply = g_dbus_create_reply(op->msg, DBUS_TYPE_INVALID);
	if (!reply) {
		error("Failed to allocate D-Bus message reply");
		return;
	}

	message_append_byte_array(reply, value, length);

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);
}

static DBusMessage *characteristic_read_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct characteristic *chrc = user_data;
	struct bt_gatt_client *gatt = chrc->service->client->gatt;
	struct async_dbus_op *op;

	if (chrc->in_read)
		return btd_error_in_progress(msg);

	op = new0(struct async_dbus_op, 1);
	if (!op)
		return btd_error_failed(msg, "Failed to initialize request");

	op->msg = dbus_message_ref(msg);
	op->data = chrc;

	if (bt_gatt_client_read_long_value(gatt, chrc->value_handle, 0,
							chrc_read_long_cb, op,
							async_dbus_op_free)) {
		chrc->in_read = true;
		return NULL;
	}

	async_dbus_op_free(op);

	return btd_error_failed(msg, "Failed to send read request");
}

static DBusMessage *characteristic_write_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	/* TODO: Implement */
	return btd_error_failed(msg, "Not implemented");
}

struct notify_client {
	struct characteristic *chrc;
	int ref_count;
	char *owner;
	guint watch;
	unsigned int notify_id;
};

static void notify_client_free(void *data)
{
	struct notify_client *client = data;

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

static void notify_cb(uint16_t value_handle, const uint8_t *value,
					uint16_t length, void *user_data)
{
	struct async_dbus_op *op = user_data;
	struct notify_client *client = op->data;
	struct characteristic *chrc = client->chrc;

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
	struct notify_client *client = op->data;
	struct characteristic *chrc = client->chrc;
	DBusMessage *reply;

	/* Make sure that an interim disconnect did not remove the client */
	if (!queue_find(chrc->notify_clients, NULL, client)) {
		bt_gatt_client_unregister_notify(chrc->service->client->gatt,
									id);
		notify_client_unref(client);

		reply = btd_error_failed(op->msg,
						"Characteristic not available");
		goto done;
	}

	/*
	 * Drop the reference count that we added when registering the callback.
	 */
	notify_client_unref(client);

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

	op = new0(struct async_dbus_op, 1);
	if (!op) {
		notify_client_unref(client);
		return btd_error_failed(msg, "Failed to initialize request");
	}

	/*
	 * Add to the ref count so that a disconnect during register won't free
	 * the client instance.
	 */
	op->data = notify_client_ref(client);
	op->msg = dbus_message_ref(msg);

	queue_push_tail(chrc->notify_clients, client);

	if (bt_gatt_client_register_notify(gatt, chrc->value_handle,
						register_notify_cb, notify_cb,
						op, async_dbus_op_free))
		return NULL;

	queue_remove(chrc->notify_clients, client);
	async_dbus_op_free(op);

	/* Directly free the client */
	notify_client_free(client);

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

static void characteristic_free(void *data)
{
	struct characteristic *chrc = data;

	queue_destroy(chrc->descs, NULL);  /* List should be empty here */
	free(chrc->value);
	g_free(chrc->path);
	free(chrc);
}

static struct characteristic *characteristic_create(
				const bt_gatt_characteristic_t *chrc_data,
				struct service *service)
{
	struct characteristic *chrc;

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

	chrc->path = g_strdup_printf("%s/char%04x", service->path,
						chrc_data->start_handle);
	chrc->service = service;
	chrc->handle = chrc_data->start_handle;
	chrc->value_handle = chrc_data->value_handle;
	chrc->props = chrc_data->properties;

	memcpy(chrc->uuid, chrc_data->uuid, sizeof(chrc->uuid));

	if (!g_dbus_register_interface(btd_get_dbus_connection(), chrc->path,
						GATT_CHARACTERISTIC_IFACE,
						characteristic_methods, NULL,
						characteristic_properties,
						chrc, characteristic_free)) {
		error("Unable to register GATT characteristic with handle "
					"0x%04x", chrc->handle);
		characteristic_free(chrc);

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

	g_dbus_unregister_interface(btd_get_dbus_connection(), chrc->path,
						GATT_CHARACTERISTIC_IFACE);
}

static gboolean service_property_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	char uuid[MAX_LEN_UUID_STR + 1];
	const char *ptr = uuid;
	struct service *service = data;

	uuid128_to_string(service->uuid, uuid, sizeof(uuid));
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

static struct service *service_create(const bt_gatt_service_t *svc_data,
						struct btd_gatt_client *client)
{
	struct service *service;
	const char *device_path = device_get_path(client->device);

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

	service->path = g_strdup_printf("%s/service%04x", device_path,
							svc_data->start_handle);
	service->client = client;
	service->primary = svc_data->primary;
	service->start_handle = svc_data->start_handle;
	service->end_handle = svc_data->end_handle;

	memcpy(service->uuid, svc_data->uuid, sizeof(service->uuid));

	if (!g_dbus_register_interface(btd_get_dbus_connection(), service->path,
						GATT_SERVICE_IFACE,
						NULL, NULL,
						service_properties,
						service, service_free)) {
		error("Unable to register GATT service with handle 0x%04x for "
							"device %s:",
							svc_data->start_handle,
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

	queue_remove_all(service->chrcs, NULL, NULL, unregister_characteristic);

	g_dbus_unregister_interface(btd_get_dbus_connection(), service->path,
							GATT_SERVICE_IFACE);
}

static void notify_chrcs(void *data, void *user_data)
{
	struct service *service = data;

	service->chrcs_ready = true;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), service->path,
							GATT_SERVICE_IFACE,
							"Characteristics");
}

static bool create_descriptors(const bt_gatt_characteristic_t *chrc,
					struct characteristic *dbus_chrc)
{
	size_t i;
	struct descriptor *dbus_desc;

	for (i = 0; i < chrc->num_descs; i++) {
		dbus_desc = descriptor_create(chrc->descs + i, dbus_chrc);
		if (!dbus_desc)
			return false;

		queue_push_tail(dbus_chrc->descs, dbus_desc);
	}

	return true;
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

	if (queue_isempty(service->pending_ext_props))
		notify_chrcs(service, NULL);
}

static void read_ext_props(void *data, void *user_data)
{
	struct characteristic *chrc = data;

	bt_gatt_client_read_value(chrc->service->client->gatt,
							chrc->ext_props_handle,
							read_ext_props_cb,
							chrc, NULL);
}

static bool create_characteristics(const bt_gatt_service_t *service,
						struct service *dbus_service)
{
	struct bt_gatt_characteristic_iter citer;
	const bt_gatt_characteristic_t *chrc = NULL;
	struct characteristic *dbus_chrc;

	if (!bt_gatt_characteristic_iter_init(&citer, service)) {
		error("Failed to initialize characteristic iterator");
		return false;
	}

	while (bt_gatt_characteristic_iter_next(&citer, &chrc)) {
		dbus_chrc = characteristic_create(chrc, dbus_service);
		if (!dbus_chrc)
			return false;

		if (!create_descriptors(chrc, dbus_chrc)) {
			error("Exporting descriptors failed");
			unregister_characteristic(dbus_chrc);

			return false;
		}

		queue_push_tail(dbus_service->chrcs, dbus_chrc);

		if (dbus_chrc->ext_props_handle)
			queue_push_tail(dbus_service->pending_ext_props,
								dbus_chrc);
	}

	/* Obtain extended properties */
	queue_foreach(dbus_service->pending_ext_props, read_ext_props, NULL);

	return true;
}

static gboolean set_chrcs_ready(gpointer user_data)
{
	struct btd_gatt_client *client = user_data;

	if (!client->gatt)
		return FALSE;

	queue_foreach(client->services, notify_chrcs, NULL);

	return FALSE;
}

static void create_services(struct btd_gatt_client *client)
{
	struct bt_gatt_service_iter iter;
	const bt_gatt_service_t *service = NULL;
	struct service *dbus_service;

	DBG("Exporting objects for GATT services: %s", client->devaddr);

	if (!bt_gatt_service_iter_init(&iter, client->gatt)) {
		error("Failed to initialize service iterator");
		return;
	}

	while (bt_gatt_service_iter_next(&iter, &service)) {
		dbus_service = service_create(service, client);
		if (!dbus_service)
			continue;

		if (!create_characteristics(service, dbus_service)) {
			error("Exporing characteristics failed");
			unregister_service(dbus_service);

			continue;
		}

		queue_push_tail(client->services, dbus_service);
	}

	/*
	 * Asynchronously update the "Characteristics" property of each service.
	 * We do this so that users have a way to know that all characteristics
	 * of a service have been exported.
	 *
	 * If there are any pending reads to obtain the value of the "Extended
	 * Properties" descriptor then wait until they are complete.
	 */
	if (!dbus_service->chrcs_ready &&
				queue_isempty(dbus_service->pending_ext_props))
		g_idle_add(set_chrcs_ready, client);
}

static void gatt_ready_cb(struct bt_gatt_client *gatt, void *user_data)
{
	struct btd_gatt_client *client = user_data;

	client->gatt = bt_gatt_client_ref(gatt);

	create_services(client);
}

static void gatt_svc_chngd_cb(struct bt_gatt_client *client,
						uint16_t start_handle,
						uint16_t end_handle,
						void *user_data)
{
	/* TODO */
}

static void gatt_disconn_cb(void *user_data)
{
	struct btd_gatt_client *client = user_data;

	DBG("Device disconnected. Cleaning up");

	/*
	 * Remove all services. We'll recreate them when a new bt_gatt_client
	 * becomes ready.
	 */
	queue_remove_all(client->services, NULL, NULL, unregister_service);
	bt_gatt_client_unref(client->gatt);
	client->gatt = NULL;
}

struct btd_gatt_client *btd_gatt_client_new(struct btd_device *device)
{
	struct btd_gatt_client *client;

	if (!device)
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
	client->gatt_cb_id = btd_device_add_gatt_callbacks(device,
						gatt_ready_cb,
						gatt_svc_chngd_cb,
						gatt_disconn_cb, client);

	return client;
}

void btd_gatt_client_destroy(struct btd_gatt_client *client)
{
	if (!client)
		return;

	bt_gatt_client_unref(client->gatt);
	btd_device_remove_gatt_callbacks(client->device, client->gatt_cb_id);
	queue_destroy(client->services, unregister_service);
	free(client);
}

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
};

struct characteristic {
	struct service *service;
	uint16_t handle;
	uint16_t value_handle;
	uint8_t props;
	uint8_t uuid[BT_GATT_UUID_SIZE];
	char *path;
	struct queue *descs;
};

struct descriptor {
	struct characteristic *chrc;
	uint16_t handle;
	uint8_t uuid[BT_GATT_UUID_SIZE];
	char *path;
};

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
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "y", &array);

	/* TODO: Implement this once the value is cached */

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static DBusMessage *descriptor_read_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	/* TODO: Implement */
	return btd_error_failed(msg, "Not implemented");
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
	{ "Value", "ay", descriptor_property_get_value },
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
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "y", &array);

	/* TODO: Implement this once the value is cached */

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean characteristic_property_get_notifying(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	dbus_bool_t notifying = FALSE;

	/*
	 * TODO: Return the correct value here once StartNotify and StopNotify
	 * methods are implemented.
	 */

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
	{ },
	/* Extended Properties */
	{ BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE,	"reliable-write" },
	{ BT_GATT_CHRC_EXT_PROP_WRITABLE_AUX,	"writable-auxiliaries" },
	{ }
};

static gboolean characteristic_property_get_flags(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chrc = data;
	DBusMessageIter array;
	int i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "s", &array);

	for (i = 0; properties[i].str; i++) {
		if (chrc->props & properties[i].prop)
			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
							&properties[i].str);
	}

	/*
	 * TODO: Handle extended properties if the descriptor is
	 * present.
	 */

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static DBusMessage *characteristic_read_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	/* TODO: Implement */
	return btd_error_failed(msg, "Not implemented");
}

static DBusMessage *characteristic_write_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	/* TODO: Implement */
	return btd_error_failed(msg, "Not implemented");
}

static DBusMessage *characteristic_start_notify(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	/* TODO: Implement */
	return btd_error_failed(msg, "Not implemented");
}

static DBusMessage *characteristic_stop_notify(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	/* TODO: Implement */
	return btd_error_failed(msg, "Not implemented");
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
	{ "Value", "ay", characteristic_property_get_value },
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
	}

	return true;
}

static void notify_chrcs(void *data, void *user_data)
{
	struct service *service = data;

	service->chrcs_ready = true;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), service->path,
							GATT_SERVICE_IFACE,
							"Characteristics");
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
	 */
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

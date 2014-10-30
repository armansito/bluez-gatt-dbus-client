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

#define GATT_SERVICE_IFACE "org.bluez.GattService1"

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
};

static void uuid128_to_string(const uint8_t uuid[16], char *str, size_t n)
{
	uint128_t u128;
	bt_uuid_t uuid128;

	memcpy(u128.data, uuid, sizeof(uint8_t) * 16);
	bt_uuid128_create(&uuid128, u128);
	bt_uuid_to_string(&uuid128, str, n);
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

static gboolean service_property_get_characteristics(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "o", &array);

	/* TODO: Implement this once characteristics are exported */

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

	g_dbus_unregister_interface(btd_get_dbus_connection(), service->path,
							GATT_SERVICE_IFACE);
}

static void create_services(struct btd_gatt_client *client)
{
	struct bt_gatt_service_iter iter;
	const bt_gatt_service_t *service = NULL;

	DBG("Exporting objects for GATT services: %s", client->devaddr);

	if (!bt_gatt_service_iter_init(&iter, client->gatt)) {
		error("Failed to initialize service iterator");
		return;
	}

	while (bt_gatt_service_iter_next(&iter, &service)) {
		struct service *dbus_service;

		dbus_service = service_create(service, client);
		if (!dbus_service)
			continue;

		queue_push_tail(client->services, dbus_service);
	}
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

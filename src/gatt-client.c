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

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "dbus-common.h"
#include "adapter.h"
#include "device.h"
#include "lib/uuid.h"
#include "gatt-client.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "log.h"

#define GATT_SERVICE_IFACE		"org.bluez.GattService1"

struct btd_gatt_client {
	struct btd_device *device;
	GAttrib *attrib;
	guint attioid;
	guint request;

	bool initialized;  /* true, if services have been discovered */

	GSList *services;  /* Replace this with a map */
};

struct gatt_dbus_service {
	struct btd_gatt_client *client;
	struct att_range handle_range;
	bt_uuid_t uuid;
	bool is_primary;
	char *path;

	bool characteristics_discovered;
};

/* ====== Service properties/methods ====== */
static gboolean service_property_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	char uuid[MAX_LEN_UUID_STR + 1];
	const char *ptr = uuid;
	struct gatt_dbus_service *service = data;

	bt_uuid_to_string(&service->uuid, uuid, sizeof(uuid));
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ptr);

	return TRUE;
}

static gboolean service_property_get_device(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct gatt_dbus_service *service = data;
	const char *str = device_get_path(service->client->device);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &str);

	return TRUE;
}

static gboolean service_property_get_is_primary(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct gatt_dbus_service *service = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN,
					&service->is_primary);

	return TRUE;
}

static const GDBusPropertyTable service_properties[] = {
	{ "UUID", "s", service_property_get_uuid, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Device", "o", service_property_get_device, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Primary", "b", service_property_get_is_primary, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{}
};

static void destroy_service(gpointer user_data)
{
	struct gatt_dbus_service *service = user_data;

	g_free(service->path);
	g_free(service);
}

static void unregister_service(gpointer user_data)
{
	struct gatt_dbus_service *service = user_data;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
					service->path, GATT_SERVICE_IFACE);
}

static struct gatt_dbus_service *gatt_dbus_service_create(
						struct btd_gatt_client *client,
						struct gatt_primary *primary)
{
	struct gatt_dbus_service *service;
	bt_uuid_t uuid;
	const char *device_path = device_get_path(client->device);

	service = g_try_new0(struct gatt_dbus_service, 1);
	if (!service)
		return NULL;

	service->path = g_strdup_printf("%s/service%04x", device_path,
							primary->range.start);
	service->client = client;
	service->handle_range = primary->range;

	if (bt_string_to_uuid(&uuid, primary->uuid)) {
		error("GATT service has invalid UUID: %s", primary->uuid);
		goto fail;
	}

	bt_uuid_to_uuid128(&uuid, &service->uuid);

	if (!g_dbus_register_interface(btd_get_dbus_connection(), service->path,
						GATT_SERVICE_IFACE, NULL, NULL,
						service_properties,
						service, destroy_service)) {
		char device_addr[18];
		ba2str(device_get_address(client->device), device_addr);
		error("Unable to register GATT service: UUID: %s, device: %s",
						primary->uuid, device_addr);
		goto fail;
	}

	DBG("Created GATT service %s", service->path);

	return service;

fail:
	destroy_service(service);
	return NULL;
}

static void attio_cleanup(struct btd_gatt_client *client)
{
	if (!client->attrib)
		return;

	if (client->request) {
		g_attrib_cancel(client->attrib, client->request);
		client->request = 0;
	}

	g_attrib_unref(client->attrib);
	client->attrib = NULL;
}

static void discover_primary_cb(uint8_t status, GSList *services,
								void *user_data)
{
	struct btd_gatt_client *client = user_data;
	struct gatt_primary *primary;
	struct gatt_dbus_service *service;
	GSList *l;

	DBG("GATT primary service discovery status: %u", status);

	client->request = 0;

	if (status)
		return;

	client->initialized = true;

	/*
	 * TODO: find included services here. This needs to be tracked
	 * separately from "initialized", as the device may get
	 * disconnected in the middle of the operation.
	 */
	for (l = services; l; l = g_slist_next(l)) {
		primary = l->data;
		service = gatt_dbus_service_create(client, primary);
		if (!service)
			continue;

		service->is_primary = true;

		client->services = g_slist_append(client->services, service);
	}
}

static void attio_connect_cb(GAttrib *attrib, gpointer user_data)
{
	struct btd_gatt_client *client = user_data;

	client->attrib = g_attrib_ref(attrib);

	/* TODO: Discover remote GATT services here and mark as "initialized".
	 * Once initialized, we will only re-discover all services here if the
	 * device is not bonded. Otherwise, we will only rediscover when we
	 * receive an indication from the Service Changed Characteristic.
	 */
	info("btd_gatt_client: device connected. Initializing GATT services\n");

	if (client->initialized)
		return;

	if (client->request)
		return;

	client->request = gatt_discover_primary(client->attrib, NULL,
						discover_primary_cb, client);
	if (!client->request)
		error("Failed to start GATT service discovery for device: %s",
					device_get_path(client->device));
}

static void attio_disconnect_cb(gpointer user_data)
{
	struct btd_gatt_client *client = user_data;

	info("btd_gatt_client: device disconnected. Cleaning up GATT "
								"services\n");

	if (client->request) {
		g_attrib_cancel(client->attrib, client->request);
		client->request = 0;
	}

	if (client->services) {
		g_slist_free_full(client->services, unregister_service);
		client->services = NULL;
	}

	attio_cleanup(client);

	client->initialized = false;
}

struct btd_gatt_client *btd_gatt_client_new(struct btd_device *device)
{
	struct btd_gatt_client *client;

	if (!device)
		return NULL;

	client = g_try_new0(struct btd_gatt_client, 1);
	if (!client)
		return NULL;

	client->device = device;

	client->attioid = btd_device_add_attio_callback(device,
							attio_connect_cb,
							attio_disconnect_cb,
							client);

	info("btd_gatt_client constructed\n");

	return client;
}

void btd_gatt_client_destroy(struct btd_gatt_client *client)
{
	if (client->attioid)
		btd_device_remove_attio_callback(client->device,
							client->attioid);

	if (client->request) {
		g_attrib_cancel(client->attrib, client->request);
		client->request = 0;
	}

	if (client->services) {
		g_slist_free_full(client->services, unregister_service);
		client->services = NULL;
	}

	attio_cleanup(client);

	g_free(client);
}

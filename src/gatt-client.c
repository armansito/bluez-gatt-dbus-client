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
#include "error.h"
#include "adapter.h"
#include "device.h"
#include "lib/uuid.h"
#include "gatt-client.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "log.h"

#define GATT_SERVICE_IFACE		"org.bluez.GattService1"
#define GATT_CHARACTERISTIC_IFACE	"org.bluez.GattCharacteristic1"

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
	bool discovering;

	guint request;

	GSList *characteristics;
};

struct gatt_dbus_characteristic {
	struct gatt_dbus_service *service;
	bt_uuid_t uuid;
	uint16_t handle;
	uint16_t value_handle;
	uint8_t properties;
	char *path;
};

/* ====== Characteristic properties/methods ====== */
static gboolean characteristic_property_get_uuid(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	char uuid[MAX_LEN_UUID_STR + 1];
	const char *ptr = uuid;
	struct gatt_dbus_characteristic *characteristic = data;

	bt_uuid_to_string(&characteristic->uuid, uuid, sizeof(uuid));
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ptr);

	return TRUE;
}

static gboolean characteristic_property_get_service(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct gatt_dbus_characteristic *characteristic = data;
	const char *str = characteristic->service->path;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &str);

	return TRUE;
}

static gboolean characteristic_property_get_flags(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct gatt_dbus_characteristic *characteristic = data;
	DBusMessageIter array;
	const int num_flags = 8;
	int i;
	const uint8_t props[] = {
		GATT_CHR_PROP_BROADCAST,
		GATT_CHR_PROP_READ,
		GATT_CHR_PROP_WRITE_WITHOUT_RESP,
		GATT_CHR_PROP_WRITE,
		GATT_CHR_PROP_NOTIFY,
		GATT_CHR_PROP_INDICATE,
		GATT_CHR_PROP_AUTH,
		GATT_CHR_PROP_EXT_PROP
	};
	const char *flags[] = {
		"broadcast",
		"read",
		"write-without-response",
		"write",
		"notify",
		"indicate",
		"authenticated-signed-writes",
		"extended-properties"
	};

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "s", &array);

	for (i = 0; i < num_flags; i++) {
		if (characteristic->properties & props[i])
			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
								&flags[i]);
	}

	/*
	 * TODO: include the extended properties here if the descriptor is
	 * present.
	 */

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static const GDBusPropertyTable characteristic_properties[] = {
	{ "UUID", "s", characteristic_property_get_uuid, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Service", "o", characteristic_property_get_service, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Flags", "as", characteristic_property_get_flags, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{}
};

static void destroy_characteristic(gpointer user_data)
{
	struct gatt_dbus_characteristic *characteristic = user_data;

	g_free(characteristic->path);
	g_free(characteristic);
}

static void unregister_characteristic(gpointer user_data)
{
	struct gatt_dbus_characteristic *characteristic = user_data;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
						characteristic->path,
						GATT_CHARACTERISTIC_IFACE);
}

struct gatt_dbus_characteristic *gatt_dbus_characteristic_create(
					struct gatt_dbus_service *service,
					struct gatt_char *chr)
{
	struct gatt_dbus_characteristic *characteristic;
	bt_uuid_t uuid;

	characteristic = g_try_new0(struct gatt_dbus_characteristic, 1);
	if (!characteristic)
		return NULL;

	characteristic->path = g_strdup_printf("%s/char%04x", service->path,
								chr->handle);

	characteristic->service = service;
	characteristic->handle = chr->handle;
	characteristic->value_handle = chr->value_handle;
	characteristic->properties = chr->properties;

	if (bt_string_to_uuid(&uuid, chr->uuid)) {
		error("GATT characteristic has invalid UUID: %s", chr->uuid);
		goto fail;
	}

	bt_uuid_to_uuid128(&uuid, &characteristic->uuid);

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
						characteristic->path,
						GATT_CHARACTERISTIC_IFACE,
						NULL, NULL,
						characteristic_properties,
						characteristic,
						destroy_characteristic)) {
		error("Failed to register GATT characteristic: UUID: %s",
								chr->uuid);
		goto fail;
	}

	DBG("GATT characteristic created: %s", characteristic->path);

	return characteristic;

fail:
	destroy_characteristic(characteristic);
	return NULL;
}

/* ====== Service properties/methods ====== */
static void gatt_discover_characteristics_cb(uint8_t status,
							GSList *characteristics,
							void *user_data)
{
	struct gatt_dbus_service *service = user_data;
	struct gatt_dbus_characteristic *characteristic;
	struct gatt_char *chr;
	GSList *l;

	DBG("GATT characteristic discovery status: %u", status);

	service->request = 0;

	if (status)
		return;

	for (l = characteristics; l; l = g_slist_next(l)) {
		chr = l->data;
		characteristic = gatt_dbus_characteristic_create(service, chr);
		if (!characteristic)
			continue;

		service->characteristics = g_slist_append(
						service->characteristics,
						characteristic);
	}

	service->characteristics_discovered = true;
	service->discovering = false;
}

static void service_discover_characteristics(struct gatt_dbus_service *service)
{
	guint request;

	if (service->request)
		return;

	if (service->characteristics_discovered)
		return;

	if (service->discovering)
		return;

	if ((request = gatt_discover_char(service->client->attrib,
					service->handle_range.start,
					service->handle_range.end,
					NULL, gatt_discover_characteristics_cb,
					service)))
		return;

	service->request = request;
	service->discovering = false;
}

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

static void cancel_pending_service_requests(struct gatt_dbus_service *service)
{
	if (service->request) {
		DBG("Canceling pending characteristic discovery request");
		g_attrib_cancel(service->client->attrib, service->request);
		service->request = 0;
	}
}

static void destroy_service(gpointer user_data)
{
	struct gatt_dbus_service *service = user_data;

	cancel_pending_service_requests(service);

	/*
	 * If this happened, and there are still characteristics lying around,
	 * remove them.
	 */
	if (service->characteristics) {
		g_slist_free_full(service->characteristics, unregister_characteristic);
		service->characteristics = NULL;
	}

	DBG("Destroying GATT service: %s", service->path);

	g_free(service->path);
	g_free(service);
}

static void unregister_service(gpointer user_data)
{
	struct gatt_dbus_service *service = user_data;

	DBG("Unregister GATT service: %s", service->path);

	cancel_pending_service_requests(service);

	/* Remove characteristics before removing the service */
	if (service->characteristics) {
		g_slist_free_full(service->characteristics, unregister_characteristic);
		service->characteristics = NULL;
	}

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
						GATT_SERVICE_IFACE,
						NULL, NULL,
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

		/* Discover the characteristics */
		service_discover_characteristics(service);
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

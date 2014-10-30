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

#include <bluetooth/bluetooth.h>

#include "log.h"
#include "adapter.h"
#include "device.h"
#include "src/shared/att.h"
#include "src/shared/gatt-client.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "gatt-callbacks.h"

struct btd_gatt_client {
	struct btd_device *device;
	char devaddr[18];
	struct bt_gatt_client *gatt;
	unsigned int gatt_cb_id;

	struct queue *services;
};

static void service_free(void *data)
{
	/* TODO */
}

static void create_services(struct btd_gatt_client *client)
{
	DBG("Exporting objects for GATT services: %s", client->devaddr);

	/* TODO */
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
	queue_destroy(client->services, service_free);
	free(client);
}

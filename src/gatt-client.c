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

#include <stdbool.h>

#include "adapter.h"
#include "device.h"
#include "gatt-client.h"
#include "attrib/gattrib.h"
#include "log.h"

struct btd_gatt_client {
	struct btd_device *device;
	GAttrib *attrib;
	guint attioid;
	guint request;

	bool initialized;
};

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

static void attio_connect_cb(GAttrib *attrib, gpointer user_data)
{
	struct btd_gatt_client *client = user_data;

	client->attrib = g_attrib_ref(attrib);

	/* TODO: Discover remote GATT services here and mark as "initialized".
	 * Once initialized, we will only re-discover all services here if the
	 * device is not bonded. Otherwise, we will only rediscover when we
	 * receive an indication from the Service Changed Characteristic.
	 */
	DBG("btd_gatt_client: device connected\n");
}

static void attio_disconnect_cb(gpointer user_data)
{
	struct btd_gatt_client *client = user_data;
	attio_cleanup(client);

	DBG("btd_gatt_client: device disconnected\n");
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

	DBG("btd_gatt_client constructed\n");

	return client;
}

void btd_gatt_client_destroy(struct btd_gatt_client *client)
{
	if (client->attioid)
		btd_device_remove_attio_callback(client->device,
							client->attioid);

	attio_cleanup(client);
	g_free(client);
}

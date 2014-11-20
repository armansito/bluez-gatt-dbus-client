/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012 Texas Instruments, Inc.
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
#include <errno.h>

#include "lib/uuid.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/plugin.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/gatt-client.h"
#include "src/log.h"
#include "src/gatt-callbacks.h"

#define PNP_ID_SIZE	7

struct profile_data {
	struct btd_device *dev;
	struct bt_gatt_client *client;
	uint16_t start_handle, end_handle;
	unsigned int gatt_cb_id;
};

static void read_pnpid_cb(bool success, uint8_t att_ecode, const uint8_t *value,
					uint16_t length, void *user_data)
{
	struct profile_data *pdata = user_data;

	if (!success) {
		error("Error reading PNP_ID value: %s",
					bt_att_ecode_to_string(att_ecode));
		return;
	}

	if (length < PNP_ID_SIZE) {
		error("Error reading PNP_ID: Invalid pdu length received");
		return;
	}

	btd_device_set_pnpid(pdata->dev, value[0], get_le16(&value[1]),
				get_le16(&value[3]), get_le16(&value[5]));
}

static void handle_pnpid(struct profile_data *pdata,
					const bt_gatt_characteristic_t *chrc)
{
	if (!bt_gatt_client_read_long_value(pdata->client, chrc->value_handle,
						0, read_pnpid_cb, pdata, NULL))
		DBG("Request to read value of PNP_ID failed");
}

static bool uuid_match(uint16_t u16, const uint8_t uuid[16])
{
	uint128_t u128;
	bt_uuid_t lhs, rhs;

	memcpy(u128.data, uuid, sizeof(uint8_t) * 16);
	bt_uuid16_create(&lhs, u16);
	bt_uuid128_create(&rhs, u128);

	return bt_uuid_cmp(&lhs, &rhs) == 0;
}


static void init_deviceinfo_service(struct profile_data *pdata)
{
	struct bt_gatt_service_iter iter;
	struct bt_gatt_characteristic_iter chrc_iter;
	const bt_gatt_service_t *service = NULL;
	const bt_gatt_characteristic_t *chrc = NULL;
	bt_uuid_t deviceinfo_uuid;

	bt_string_to_uuid(&deviceinfo_uuid, DEVICE_INFORMATION_UUID);

	if (!bt_gatt_service_iter_init(&iter, pdata->client)) {
		DBG("Cannot initialize service iterator");
		return;
	}

	if (!bt_gatt_service_iter_next_by_uuid(&iter,
						deviceinfo_uuid.value.u128.data,
						&service)) {
		error("Device info service not found on device");
		return;
	}

	pdata->start_handle = service->start_handle;
	pdata->end_handle = service->end_handle;


	if (!bt_gatt_characteristic_iter_init(&chrc_iter, service)) {
		DBG("Failed to initialize characteristic iterator");
		return;
	}

	while (bt_gatt_characteristic_iter_next(&chrc_iter, &chrc)) {
		if (uuid_match(GATT_CHARAC_PNP_ID, chrc->uuid))
			handle_pnpid(pdata, chrc);
	}
}

static void gatt_ready_cb(struct bt_gatt_client *client, void *user_data)
{
	struct profile_data *pdata = user_data;

	pdata->client = client;

	init_deviceinfo_service(pdata);
}

static void gatt_changed_cb(struct bt_gatt_client *client,
				uint16_t start_handle, uint16_t end_handle,
				void *user_data) {
	struct profile_data *pdata = user_data;

	if (!pdata->client || !pdata->start_handle || !pdata->end_handle)
		return;

	if (pdata->end_handle < start_handle ||
					pdata->start_handle > end_handle)
		return;

	DBG("deviceinfo changed, updating.");

	init_deviceinfo_service(pdata);
}

static int deviceinfo_driver_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct profile_data *pdata;

	pdata = new0(struct profile_data, 1);
	pdata->dev = btd_device_ref(device);

	if (!pdata->gatt_cb_id) {
		pdata->gatt_cb_id = btd_device_add_gatt_callbacks(device,
								gatt_ready_cb,
								gatt_changed_cb,
								NULL, pdata);
	}

	btd_service_set_user_data(service, pdata);

	return 0;
}

static void deviceinfo_driver_remove(struct btd_service *service)
{
	struct profile_data *pdata = btd_service_get_user_data(service);

	if (pdata->gatt_cb_id)
		btd_device_remove_gatt_callbacks(pdata->dev, pdata->gatt_cb_id);

	btd_device_unref(pdata->dev);

	free(pdata);
}

static struct btd_profile deviceinfo_profile = {
	.name		= "deviceinfo",
	.remote_uuid	= DEVICE_INFORMATION_UUID,
	.device_probe	= deviceinfo_driver_probe,
	.device_remove	= deviceinfo_driver_remove
};

static int deviceinfo_init(void)
{
	return btd_profile_register(&deviceinfo_profile);
}

static void deviceinfo_exit(void)
{
	btd_profile_unregister(&deviceinfo_profile);
}

BLUETOOTH_PLUGIN_DEFINE(deviceinfo, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
					deviceinfo_init, deviceinfo_exit)

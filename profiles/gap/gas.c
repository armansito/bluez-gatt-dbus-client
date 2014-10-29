/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
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

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <glib.h>

#include "btio/btio.h"
#include "lib/uuid.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/shared/util.h"
#include "src/log.h"
#include "src/textfile.h"
#include "src/shared/att.h"
#include "src/shared/gatt-client.h"
#include "src/gatt-callbacks.h"

/* Generic Attribute/Access Service */
struct gas {
	struct btd_device *device;
	struct bt_gatt_client *client;
	uint16_t start_handle, end_handle;
	unsigned int gatt_cb_id;
};

static GSList *devices = NULL;

static void gas_free(struct gas *gas)
{
	if (gas->gatt_cb_id)
		btd_device_remove_gatt_callbacks(gas->device,
							gas->gatt_cb_id);

	btd_device_unref(gas->device);
	g_free(gas);
}

static int cmp_device(gconstpointer a, gconstpointer b)
{
	const struct gas *gas = a;
	const struct btd_device *device = b;

	return (gas->device == device ? 0 : -1);
}

static char *name2utf8(const uint8_t *name, uint8_t len)
{
	char utf8_name[HCI_MAX_NAME_LENGTH + 2];
	int i;

	if (g_utf8_validate((const char *) name, len, NULL))
		return g_strndup((char *) name, len);

	memset(utf8_name, 0, sizeof(utf8_name));
	strncpy(utf8_name, (char *) name, len);

	/* Assume ASCII, and replace all non-ASCII with spaces */
	for (i = 0; utf8_name[i] != '\0'; i++) {
		if (!isascii(utf8_name[i]))
			utf8_name[i] = ' ';
	}

	/* Remove leading and trailing whitespace characters */
	g_strstrip(utf8_name);

	return g_strdup(utf8_name);
}

static void read_device_name_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct gas *gas = user_data;
	char *name = name2utf8(value, length);

	DBG("GAP Device Name: %s", name);

	btd_device_device_set_name(gas->device, name);
}

static void handle_device_name(struct gas *gas,
					const bt_gatt_characteristic_t *chrc)
{
	if (!bt_gatt_client_read_long_value(gas->client, chrc->value_handle, 0,
						read_device_name_cb, gas, NULL))
		DBG("Failed to send request to read device name");
}

static void read_appearance_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct gas *gas = user_data;
	uint16_t appearance;

	if (!success) {
		DBG("Reading appearance failed with ATT error: %u", att_ecode);
		return;
	}

	/* The appearance value is a 16-bit unsigned integer */
	if (length != 2) {
		DBG("Malformed appearance value");
		return;
	}

	appearance = get_le16(value);

	DBG("GAP Appearance: 0x%04x", appearance);

	device_set_appearance(gas->device, appearance);
}

static void handle_appearance(struct gas *gas,
					const bt_gatt_characteristic_t *chrc)
{
	uint16_t appearance;

	if (device_get_appearance(gas->device, &appearance) >= 0)
		return;

	if (!bt_gatt_client_read_value(gas->client, chrc->value_handle,
				read_appearance_cb, gas, NULL))
		DBG("Failed to send request to read appearance");
}

static bool uuid_cmp(uint16_t u16, const uint8_t uuid[16])
{
	uint128_t u128;
	bt_uuid_t lhs, rhs;

	memcpy(u128.data, uuid, sizeof(uint8_t) * 16);
	bt_uuid16_create(&lhs, u16);
	bt_uuid128_create(&rhs, u128);

	return bt_uuid_cmp(&lhs, &rhs) == 0;
}

static void reset_gap_service(struct gas *gas)
{
	struct bt_gatt_service_iter iter;
	struct bt_gatt_characteristic_iter chrc_iter;
	const bt_gatt_service_t *service = NULL;
	const bt_gatt_characteristic_t *chrc = NULL;
	bt_uuid_t gap_uuid;

	bt_string_to_uuid(&gap_uuid, GAP_UUID);

	if (!bt_gatt_service_iter_init(&iter, gas->client)) {
		DBG("Failed to initialize service iterator");
		return;
	}

	if (!bt_gatt_service_iter_next_by_uuid(&iter, gap_uuid.value.u128.data,
								&service)) {
		error("GAP service not found on device");
		return;
	}

	gas->start_handle = service->start_handle;
	gas->end_handle = service->end_handle;

	if (!bt_gatt_characteristic_iter_init(&chrc_iter, service)) {
		DBG("Failed to initialize characteristic iterator");
		return;
	}

	while (bt_gatt_characteristic_iter_next(&chrc_iter, &chrc)) {
		if (uuid_cmp(GATT_CHARAC_DEVICE_NAME, chrc->uuid))
			handle_device_name(gas, chrc);
		else if (uuid_cmp(GATT_CHARAC_APPEARANCE, chrc->uuid))
			handle_appearance(gas, chrc);

		/*
		 * TODO: Implement peripheral privacy feature.
		 */
	}
}

static void gatt_client_ready_cb(struct bt_gatt_client *client, void *user_data)
{
	struct gas *gas = user_data;

	gas->client = client;

	reset_gap_service(gas);
}

static void gatt_svc_chngd_cb(struct bt_gatt_client *client,
						uint16_t start_handle,
						uint16_t end_handle,
						void *user_data)
{
	struct gas *gas = user_data;

	if (!gas->client || !gas->start_handle || !gas->end_handle)
		return;

	if (gas->end_handle < start_handle || gas->start_handle > end_handle)
		return;

	DBG("GAP service changed!");

	reset_gap_service(gas);
}

static int gas_register(struct btd_device *device)
{
	struct gas *gas;

	gas = g_new0(struct gas, 1);

	gas->device = btd_device_ref(device);
	devices = g_slist_append(devices, gas);

	if (!gas->gatt_cb_id)
		gas->gatt_cb_id = btd_device_add_gatt_callbacks(device,
							gatt_client_ready_cb,
							gatt_svc_chngd_cb,
							NULL, gas);

	return 0;
}

static void gas_unregister(struct btd_device *device)
{
	struct gas *gas;
	GSList *l;

	l = g_slist_find_custom(devices, device, cmp_device);
	if (l == NULL)
		return;

	gas = l->data;
	devices = g_slist_remove(devices, gas);
	gas_free(gas);
}

static int gap_driver_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);

	return gas_register(device);
}

static void gap_driver_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);

	gas_unregister(device);
}

static struct btd_profile gap_profile = {
	.name		= "gap-profile",
	.remote_uuid	= GAP_UUID,
	.device_probe	= gap_driver_probe,
	.device_remove	= gap_driver_remove
};

static int gap_init(void)
{
	btd_profile_register(&gap_profile);

	return 0;
}

static void gap_exit(void)
{
	btd_profile_unregister(&gap_profile);
}

BLUETOOTH_PLUGIN_DEFINE(gap, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							gap_init, gap_exit)

/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdint.h>
#include <stdbool.h>

typedef void (*btd_gatt_client_ready_t) (struct bt_gatt_client *client,
							void *user_data);
typedef void (*btd_gatt_client_service_changed_t) (
						struct bt_gatt_client *client,
						uint16_t start_handle,
						uint16_t end_handle,
						void *user_data);
typedef void (*btd_gatt_disconnect_t) (void *user_data);

unsigned int btd_device_add_gatt_callbacks(struct btd_device *device,
			btd_gatt_client_ready_t ready_func,
			btd_gatt_client_service_changed_t service_changed_func,
			btd_gatt_disconnect_t disconnect_func,
			void *user_data);
bool btd_device_remove_gatt_callbacks(struct btd_device *device,
							unsigned int id);

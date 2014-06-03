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
#include "src/shared/util.h"

#define GATT_SERVICE_IFACE		"org.bluez.GattService1"
#define GATT_CHARACTERISTIC_IFACE	"org.bluez.GattCharacteristic1"
#define GATT_DESCRIPTOR_IFACE		"org.bluez.GattDescriptor1"

#define GATT_CHR_EXT_PROP_RELIABLE_WRITE	0x01
#define GATT_CHR_EXT_PROP_WRITABLE_AUX		0x02

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
	uint16_t ext_properties;
	char *path;

	guint read_request;
	guint write_request;
	guint desc_request;

	guint not_id;
	guint ind_id;

	GSList *descriptors;
};

struct gatt_dbus_descriptor {
	struct gatt_dbus_characteristic *chrc;
	bt_uuid_t uuid;
	uint16_t handle;
	char *path;

	guint read_request;
	guint write_request;
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

static DBusMessage *gatt_error_authentication(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Authentication",
						"Insufficient authentication");
}

static DBusMessage *gatt_error_authorization(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Authorization",
						"Insufficient authorization");
}

static DBusMessage *gatt_error_encryption(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Encryption",
						"Insufficient encryption");
}

static DBusMessage *error_from_att_ecode(DBusMessage *msg, guint8 ecode)
{
	switch (ecode) {
	case ATT_ECODE_READ_NOT_PERM:
		return gatt_error_read_not_permitted(msg);
	case ATT_ECODE_WRITE_NOT_PERM:
		return gatt_error_write_not_permitted(msg);
	case ATT_ECODE_AUTHENTICATION:
		return gatt_error_authentication(msg);
	case ATT_ECODE_AUTHORIZATION:
		return gatt_error_authentication(msg);
	case ATT_ECODE_INSUFF_ENC:
	case ATT_ECODE_INSUFF_ENCR_KEY_SIZE:
		return gatt_error_authentication(msg);
	default:
		return g_dbus_create_error(msg, ERROR_INTERFACE,
				"Operation failed with ATT error code: 0x%02x",
				ecode);
	}

	return NULL;
}

static void discover_primary_cb(uint8_t status, GSList *services,
							void *user_data);
static void unregister_service(gpointer user_data);

static void gatt_client_initialize_services(struct btd_gatt_client *client)
{
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

static void gatt_client_uninitialize_services(struct btd_gatt_client *client)
{
	if (client->request) {
		g_attrib_cancel(client->attrib, client->request);
		client->request = 0;
	}

	if (client->services) {
		g_slist_free_full(client->services, unregister_service);
		client->services = NULL;
	}

	client->initialized = false;
}

/* ====== Descriptor properties/methods ====== */
static gboolean descriptor_property_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	char uuid[MAX_LEN_UUID_STR + 1];
	const char *ptr = uuid;
	struct gatt_dbus_descriptor *descr = data;

	bt_uuid_to_string(&descr->uuid, uuid, sizeof(uuid));
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ptr);

	return TRUE;
}

static gboolean descriptor_property_get_chrc(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct gatt_dbus_descriptor *descr = data;
	const char *str = descr->chrc->path;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &str);

	return TRUE;
}

struct gatt_desc_read_op {
	struct gatt_dbus_descriptor *desc;
	DBusMessage *msg;
};

static void read_desc_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct gatt_desc_read_op *op = user_data;
	uint8_t value[len];
	ssize_t vlen;
	DBusMessageIter iter, array;
	DBusMessage *reply;
	int i;

	if (status) {
		reply = error_from_att_ecode(op->msg, status);
		goto done;
	}

	vlen = dec_read_resp(pdu, len, value, sizeof(value));
	if (vlen < 0) {
		reply = btd_error_failed(op->msg, "Invalid response received");
		goto done;
	}

	reply = g_dbus_create_reply(op->msg, DBUS_TYPE_INVALID);
	if (!reply)
		goto fail;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "y", &array);

	for (i = 0; i < vlen; i++)
		dbus_message_iter_append_basic(&array, DBUS_TYPE_BYTE,
								value + i);

	dbus_message_iter_close_container(&iter, &array);

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);

fail:
	dbus_message_unref(op->msg);
	op->desc->read_request = 0;
	g_free(op);
}

static DBusMessage *descriptor_read_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct gatt_dbus_descriptor *desc = user_data;
	struct gatt_desc_read_op *op;
	GAttrib *attrib = desc->chrc->service->client->attrib;

	if (!attrib)
		return btd_error_failed(msg,
					"ATT data connection uninitialized");

	if (desc->read_request)
		return btd_error_in_progress(msg);

	op = g_try_new0(struct gatt_desc_read_op, 1);
	if (!op)
		return btd_error_failed(msg, "Failed to initialize request");

	op->desc = desc;
	op->msg = msg;

	desc->read_request = gatt_read_char(attrib, desc->handle,
							read_desc_cb, op);
	if (!desc->read_request) {
		g_free(op);
		return btd_error_failed(msg, "Failed to issue request");
	}

	dbus_message_ref(msg);

	return NULL;
}

struct gatt_desc_write_op {
	struct gatt_dbus_descriptor *desc;
	DBusMessage *msg;
};

static void write_desc_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct gatt_desc_write_op *op = user_data;
	DBusMessage *reply;

	if (status) {
		reply = error_from_att_ecode(op->msg, status);
		goto done;
	}

	reply = g_dbus_create_reply(op->msg, DBUS_TYPE_INVALID);
	if (!reply)
		goto fail;

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);

fail:
	dbus_message_unref(op->msg);
	op->desc->write_request = 0;
	g_free(op);
}

static DBusMessage *descriptor_write_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct gatt_dbus_descriptor *desc = user_data;
	struct gatt_desc_write_op *op = NULL;
	uint8_t *value = NULL;
	int vlen = 0;
	GAttrib *attrib = desc->chrc->service->client->attrib;
	DBusMessageIter iter, array;
	bt_uuid_t uuid;

	if (!attrib)
		return btd_error_failed(msg,
					"ATT data connection uninitialized");

	if (desc->write_request)
		return btd_error_in_progress(msg);

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return btd_error_invalid_args(msg);

	dbus_message_iter_recurse(&iter, &array);
	dbus_message_iter_get_fixed_array(&array, &value, &vlen);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INVALID)
		return btd_error_invalid_args(msg);

	/*
	 * Since we explicitly enable notifications and indications, don't
	 * allow writing to the "Client Characteristic Configuration"
	 * descriptor.
	 */
	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	if (bt_uuid_cmp(&uuid, &desc->uuid) == 0)
		return btd_error_failed(msg, "Writing to the \"Client "
						"Characteristic Configuration\""
						"descriptor not allowed");

	op = g_try_new0(struct gatt_desc_write_op, 1);
	if (!op)
		return btd_error_failed(msg, "Failed to initialize request");

	op->desc = desc;
	op->msg = msg;

	desc->write_request = gatt_write_char(attrib, desc->handle, value, vlen,
							write_desc_cb, op);
	if (!desc->write_request) {
		g_free(op);
		return btd_error_failed(msg, "Failed to issue request");
	}

	dbus_message_ref(msg);

	return NULL;
}

static const GDBusMethodTable descriptor_methods[] = {
	{ GDBUS_ASYNC_METHOD("ReadValue", NULL, GDBUS_ARGS({ "value", "ay" }),
						descriptor_read_value) },
	{ GDBUS_ASYNC_METHOD("WriteValue", GDBUS_ARGS({ "value", "ay" }),
						NULL,
						descriptor_write_value) },
	{ }
};

static const GDBusPropertyTable descriptor_properties[] = {
	{ "UUID", "s", descriptor_property_get_uuid },
	{ "Characteristic", "o", descriptor_property_get_chrc },
	{ }
};

static void cancel_pending_descr_requests(struct gatt_dbus_descriptor *descr)
{
	if (descr->read_request) {
		DBG("Canceling pending descriptor read request");
		g_attrib_cancel(descr->chrc->service->client->attrib,
							descr->read_request);
		descr->read_request = 0;
	}

	if (descr->write_request) {
		DBG("Canceling pending descriptor write request");
		g_attrib_cancel(descr->chrc->service->client->attrib,
							descr->write_request);
		descr->write_request = 0;
	}
}

static void destroy_descr(gpointer user_data)
{
	struct gatt_dbus_descriptor *descr = user_data;

	/*
	 * This could have happened without going through unregister_descr.
	 * Cancel pending requests.
	 */
	cancel_pending_descr_requests(descr);

	DBG("Destroying GATT descriptor: %s", descr->path);

	g_free(descr->path);
	g_free(descr);
}

static void unregister_descr(gpointer user_data)
{
	struct gatt_dbus_descriptor *descr = user_data;

	cancel_pending_descr_requests(descr);

	DBG("Unregistering GATT descriptor: %s", descr->path);

	g_dbus_unregister_interface(btd_get_dbus_connection(), descr->path,
							GATT_DESCRIPTOR_IFACE);
}

static struct gatt_dbus_descriptor *gatt_dbus_descriptor_create(
					struct gatt_dbus_characteristic *chrc,
					struct gatt_desc *desc)
{
	struct gatt_dbus_descriptor *descr;
	bt_uuid_t uuid;

	descr = g_try_new0(struct gatt_dbus_descriptor, 1);
	if (!descr)
		return NULL;

	descr->path = g_strdup_printf("%s/desc%04x", chrc->path, desc->handle);

	descr->chrc = chrc;
	descr->handle = desc->handle;

	if (bt_string_to_uuid(&uuid, desc->uuid)) {
		error("GATT descriptor has invalid UUID: %s", desc->uuid);
		goto fail;
	}

	bt_uuid_to_uuid128(&uuid, &descr->uuid);

	if (!g_dbus_register_interface(btd_get_dbus_connection(), descr->path,
							GATT_DESCRIPTOR_IFACE,
							descriptor_methods, NULL,
							descriptor_properties,
							descr, destroy_descr)) {
		error("Failed to register GATT descriptor: UUID: %s",
								desc->uuid);
		goto fail;
	}

	DBG("GATT descriptor created: %s", descr->path);

	return descr;

fail:
	destroy_descr(descr);
	return NULL;
}

/* ====== Characteristic properties/methods ====== */
static void handle_service_changed_event(const uint8_t *value, uint16_t len,
						struct btd_gatt_client *client)
{
	uint16_t start, end;
	uint8_t bdaddr_type;
	GSList *l;

	if (len != 4) {
		error("Received malformed indication from Service Changed "
							"characteristic");
		return;
	}

	start = get_le16(&value[0]);
	end = get_le16(&value[2]);

	DBG("Service Changed indication: start: 0x%04x, end: 0x%04x",
								start, end);

	bdaddr_type = btd_device_get_bdaddr_type(client->device);
	if (!device_is_bonded(client->device, bdaddr_type)) {
		DBG("Device is not bonded; ignoring Service Changed");
		return;
	}

	/*
	 * Be lazy and reinitialize all services here
	 * TODO: Once the database is integrated, only rediscover the affected
	 * handles.
	 */
	gatt_client_uninitialize_services(client);
	gatt_client_initialize_services(client);
}

static void characteristic_not_cb(const uint8_t *pdu, uint16_t len,
							gpointer user_data)
{
	struct gatt_dbus_characteristic *chrc = user_data;
	uint16_t handle, olen;
	uint8_t *opdu;
	const uint8_t *value;
	size_t plen;
	bool ind = false;
	bt_uuid_t svc_changed;

	if (len < 3) {
		error("Received malformed notification/indication PDU");
		return;
	}

	handle = get_le16(&pdu[1]);
	DBG("Characterstic notification/indication received for handle: 0x%04x",
									handle);
	if (handle != chrc->value_handle)
		return;

	if (pdu[0] == ATT_OP_HANDLE_IND)
		ind = true;
	else if (pdu[0] != ATT_OP_HANDLE_NOTIFY)
		return;

	value = pdu + 3;

	if (!g_dbus_emit_signal(btd_get_dbus_connection(), chrc->path,
						GATT_CHARACTERISTIC_IFACE,
						"ValueUpdated",
						DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
						&value, len - 3,
						DBUS_TYPE_INVALID))
		DBG("Failed to emit ValueUpdated signal");

	if (!ind)
		return;

	opdu = g_attrib_get_buffer(chrc->service->client->attrib, &plen);
	olen = enc_confirmation(opdu, plen);
	if (olen > 0)
		g_attrib_send(chrc->service->client->attrib, 0, opdu, olen,
							NULL, NULL, NULL);

	/* Handle "Service Changed" characteristic. */
	bt_uuid16_create(&svc_changed, GATT_CHARAC_SERVICE_CHANGED);
	if (bt_uuid_cmp(&svc_changed, &chrc->uuid) == 0)
		handle_service_changed_event(value, len - 3,
							chrc->service->client);
}

static void ccc_written_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gatt_dbus_descriptor *descr = user_data;
	struct gatt_dbus_characteristic *chrc = descr->chrc;

	descr->write_request = 0;

	if (status) {
		error("Failed to enable notifications/indications for "
					"characteristic: %s", chrc->path);
		return;
	}

	DBG("Notifications/indications enabled for characteristic: %s",
								chrc->path);

	if (chrc->properties & GATT_CHR_PROP_NOTIFY)
		chrc->not_id = g_attrib_register(chrc->service->client->attrib,
							ATT_OP_HANDLE_NOTIFY,
							chrc->value_handle,
							characteristic_not_cb,
							chrc, NULL);

	if (chrc->properties & GATT_CHR_PROP_INDICATE)
		chrc->ind_id = g_attrib_register(chrc->service->client->attrib,
							ATT_OP_HANDLE_IND,
							chrc->value_handle,
							characteristic_not_cb,
							chrc, NULL);
}

static void read_ext_props_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct gatt_dbus_descriptor *descr = user_data;
	struct gatt_dbus_characteristic *chrc = descr->chrc;
	uint8_t value[len];
	ssize_t vlen;

	descr->read_request = 0;

	if (status)
		goto fail;

	vlen = dec_read_resp(pdu, len, value, sizeof(value));
	if (vlen != 2)
		goto fail;

	chrc->ext_properties = get_le16(value);

	if (chrc->ext_properties)
		g_dbus_emit_property_changed(btd_get_dbus_connection(),
						chrc->path,
						GATT_CHARACTERISTIC_IFACE,
						"Flags");

	return;

fail:
	error("Failed to read extended properties for GATT "
					"characteristic: %s", chrc->path);
}

static void gatt_discover_desc_cb(uint8_t status, GSList *descs,
								void *user_data)
{
	struct gatt_dbus_characteristic *chrc = user_data;
	struct gatt_dbus_descriptor *descr;
	struct gatt_desc *desc;
	GSList *l;

	chrc->desc_request = 0;

	if (status)
		return;

	for (l = descs; l; l = g_slist_next(l)) {
		desc = l->data;
		descr = gatt_dbus_descriptor_create(chrc, desc);
		if (!descr)
			continue;

		chrc->descriptors = g_slist_append(chrc->descriptors, descr);

		/*
		 * If this is the Client Characteristic Configuration
		 * descriptor, try to enable indications/notifications.
		 * TODO: This might fail due to insufficient security if the
		 * device was not paired. In that case, we need a way to retry
		 * when the security level of the conneciton is raised.
		 */
		if (desc->uuid16 == GATT_CLIENT_CHARAC_CFG_UUID) {
			uint8_t value_buf[2];
			uint16_t value = 0;

			if (chrc->properties & GATT_CHR_PROP_NOTIFY)
				value |= GATT_CLIENT_CHARAC_CFG_NOTIF_BIT;
			if (chrc->properties & GATT_CHR_PROP_INDICATE)
				value |= GATT_CLIENT_CHARAC_CFG_IND_BIT;

			if (value) {
				put_le16(value, value_buf);
				descr->write_request = gatt_write_char(
						chrc->service->client->attrib,
						descr->handle,
						value_buf,
						sizeof(value_buf),
						ccc_written_cb, descr);

				if (!chrc->write_request)
					error("Failed to enable notifications/"
						"indications for GATT "
						"characteristic: %s", chrc->path);
			}
		}

		/* Handle Characteristic Extended Properties descriptor */
		if (desc->uuid16 == GATT_CHARAC_EXT_PROPER_UUID) {
			descr->read_request = gatt_read_char(
						chrc->service->client->attrib,
						desc->handle,
						read_ext_props_cb, descr);
			if (!descr->read_request)
				error("Failed to send request to read extended "
					"properties for GATT "
					"characteristic: %s", chrc->path);
		}
	}
}

static void characteristic_discover_descriptors(
					struct gatt_dbus_characteristic *chrc,
					uint16_t end_handle)
{
	if (chrc->desc_request)
		return;

	chrc->desc_request = gatt_discover_desc(chrc->service->client->attrib,
						chrc->value_handle + 1,
						end_handle, NULL,
						gatt_discover_desc_cb, chrc);
}

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
	struct gatt_dbus_characteristic *chrc = data;
	DBusMessageIter array;
	const int num_flags = 8;
	const int num_ext_flags = 2;
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

	const uint8_t ext_props[] = {
		GATT_CHR_EXT_PROP_RELIABLE_WRITE,
		GATT_CHR_EXT_PROP_WRITABLE_AUX
	};
	const char *ext_flags[] = {
		"reliable-write",
		"writable-auxiliaries"
	};

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "s", &array);

	for (i = 0; i < num_flags; i++) {
		if (chrc->properties & props[i])
			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
								&flags[i]);
	}

	if (chrc->properties & GATT_CHR_PROP_EXT_PROP) {
		for (i = 0; i < num_ext_flags; i++) {
			if (chrc->ext_properties & ext_props[i])
				dbus_message_iter_append_basic(&array,
							DBUS_TYPE_STRING,
							&ext_flags[i]);
		}
	}

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

struct gatt_char_read_op {
	struct gatt_dbus_characteristic *chrc;
	DBusMessage *msg;
};

static void read_chrc_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct gatt_char_read_op *op = user_data;
	uint8_t value[len];
	ssize_t vlen;
	DBusMessageIter iter, array;
	DBusMessage *reply;
	int i;

	if (status) {
		reply = error_from_att_ecode(op->msg, status);
		goto done;
	}

	vlen = dec_read_resp(pdu, len, value, sizeof(value));
	if (vlen < 0) {
		reply = btd_error_failed(op->msg, "Invalid response received");
		goto done;
	}

	reply = g_dbus_create_reply(op->msg, DBUS_TYPE_INVALID);
	if (!reply)
		goto fail;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "y", &array);

	for (i = 0; i < vlen; i++)
		dbus_message_iter_append_basic(&array, DBUS_TYPE_BYTE,
								value + i);

	dbus_message_iter_close_container(&iter, &array);

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);

fail:
	dbus_message_unref(op->msg);
	op->chrc->read_request = 0;
	g_free(op);
}

static DBusMessage *characteristic_read_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct gatt_dbus_characteristic *chrc = user_data;
	struct gatt_char_read_op *op;

	if (!chrc->service->client->attrib)
		return btd_error_failed(msg,
					"ATT data connection uninitialized");

	if (chrc->read_request)
		return btd_error_in_progress(msg);

	op = g_try_new0(struct gatt_char_read_op, 1);
	if (!op)
		return btd_error_failed(msg, "Failed to initialize request");

	op->chrc = chrc;
	op->msg = msg;

	chrc->read_request = gatt_read_char(chrc->service->client->attrib,
							chrc->value_handle,
							read_chrc_cb, op);
	if (!chrc->read_request) {
		g_free(op);
		return btd_error_failed(msg, "Failed to issue request");
	}

	dbus_message_ref(msg);

	return NULL;
}

struct gatt_char_write_op {
	struct gatt_dbus_characteristic *chrc;
	DBusMessage *msg;
};

static void write_chrc_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct gatt_char_write_op *op = user_data;
	DBusMessage *reply;

	if (status) {
		reply = error_from_att_ecode(op->msg, status);
		goto done;
	}

	reply = g_dbus_create_reply(op->msg, DBUS_TYPE_INVALID);
	if (!reply)
		goto fail;

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);

fail:
	dbus_message_unref(op->msg);
	op->chrc->write_request = 0;
	g_free(op);
}

static DBusMessage *characteristic_write_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct gatt_dbus_characteristic *chrc = user_data;
	struct gatt_char_write_op *op = NULL;
	uint8_t *value = NULL;
	int vlen = 0;
	guint req;
	DBusMessageIter iter, array;

	if (!chrc->service->client->attrib)
		return btd_error_failed(msg,
					"ATT data connection uninitialized");

	if (chrc->write_request)
		return btd_error_in_progress(msg);

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return btd_error_invalid_args(msg);

	dbus_message_iter_recurse(&iter, &array);
	dbus_message_iter_get_fixed_array(&array, &value, &vlen);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INVALID)
		return btd_error_invalid_args(msg);

	/*
	 * TODO: For now, only go on with the write if "write" and
	 * "write-without-response" are supported and return an error
	 * if the characteristic only allows "authenticated-signed-writes"
	 * and "reliable-write"
	 */
	if (chrc->properties & GATT_CHR_PROP_WRITE) {
		op = g_try_new0(struct gatt_char_write_op, 1);
		if (!op)
			return btd_error_failed(msg,
						"Failed to initialize request");

		op->chrc = chrc;
		op->msg = msg;

		req = gatt_write_char(chrc->service->client->attrib,
							chrc->value_handle,
							value, vlen,
							write_chrc_cb, op);
		if (!req) {
			g_free(op);
			return btd_error_failed(msg, "Failed to issue request");
		}

		chrc->write_request = req;

		dbus_message_ref(msg);
		return NULL;
	}

	if (!(chrc->properties & GATT_CHR_PROP_WRITE_WITHOUT_RESP))
		return btd_error_failed(msg, "Only long writes and writes "
					"without response are supported");

	req = gatt_write_cmd(chrc->service->client->attrib,
						chrc->value_handle,
						value, vlen,
						NULL, NULL);

	if (!req)
		return btd_error_failed(msg, "Failed to issue request");

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable characteristic_methods[] = {
	{ GDBUS_ASYNC_METHOD("ReadValue", NULL, GDBUS_ARGS({ "value", "ay" }),
						characteristic_read_value) },
	{ GDBUS_ASYNC_METHOD("WriteValue", GDBUS_ARGS({ "value", "ay" }),
						NULL,
						characteristic_write_value) },
	{ }
};

static const GDBusSignalTable characteristic_signals[] = {
	{ GDBUS_SIGNAL("ValueUpdated", GDBUS_ARGS({ "value", "ay" })) },
	{ }
};

static const GDBusPropertyTable characteristic_properties[] = {
	{ "UUID", "s", characteristic_property_get_uuid },
	{ "Service", "o", characteristic_property_get_service },
	{ "Flags", "as", characteristic_property_get_flags },
	{ }
};

static void cancel_pending_chrc_requests(struct gatt_dbus_characteristic *chrc)
{
	if (chrc->read_request) {
		DBG("Canceling pending characteristic read request");
		g_attrib_cancel(chrc->service->client->attrib,
							chrc->read_request);
		chrc->read_request = 0;
	}

	if (chrc->write_request) {
		DBG("Canceling pending characteristic write request");
		g_attrib_cancel(chrc->service->client->attrib,
							chrc->write_request);
		chrc->write_request = 0;
	}

	if (chrc->desc_request) {
		DBG("Canceling pending descriptor discovery request");
		g_attrib_cancel(chrc->service->client->attrib,
							chrc->desc_request);
		chrc->desc_request = 0;
	}

	if (chrc->not_id) {
		DBG("Canceling registered notifications");
		g_attrib_unregister(chrc->service->client->attrib,
								chrc->not_id);
		chrc->not_id = 0;
	}

	if (chrc->ind_id) {
		DBG("Canceling registered indications");
		g_attrib_unregister(chrc->service->client->attrib,
								chrc->ind_id);
		chrc->ind_id = 0;
	}
}

static void destroy_characteristic(gpointer user_data)
{
	struct gatt_dbus_characteristic *chrc = user_data;

	cancel_pending_chrc_requests(chrc);

	/*
	 * If this happened, and there are still descriptors lying around,
	 * remove them. Also make sure all pending requests have been canceled.
	 */
	if (chrc->descriptors) {
		g_slist_free_full(chrc->descriptors, unregister_descr);
		chrc->descriptors = NULL;
	}

	DBG("Destroying GATT characteristic: %s", chrc->path);

	g_free(chrc->path);
	g_free(chrc);
}

static void unregister_characteristic(gpointer user_data)
{
	struct gatt_dbus_characteristic *chrc = user_data;

	cancel_pending_chrc_requests(chrc);

	/* Remove descriptors before removing the characteristic */
	if (chrc->descriptors) {
		g_slist_free_full(chrc->descriptors, unregister_descr);
		chrc->descriptors = NULL;
	}

	DBG("Unregistering GATT characteristic: %s", chrc->path);

	g_dbus_unregister_interface(btd_get_dbus_connection(),
						chrc->path,
						GATT_CHARACTERISTIC_IFACE);
}

static struct gatt_dbus_characteristic *gatt_dbus_characteristic_create(
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
						characteristic_methods,
						characteristic_signals,
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
	struct gatt_dbus_characteristic *chrc;
	struct gatt_char *chr, *next_chr;
	uint16_t end_handle;
	GSList *l, *next;

	DBG("GATT characteristic discovery status: %u", status);

	service->request = 0;

	if (status)
		return;

	for (l = characteristics; l; l = g_slist_next(l)) {
		chr = l->data;
		chrc = gatt_dbus_characteristic_create(service, chr);
		if (!chrc)
			continue;

		service->characteristics = g_slist_append(
						service->characteristics,
						chrc);

		next = g_slist_next(l);
		if (next) {
			next_chr = next->data;
			end_handle = next_chr->handle - 1;
		} else
			end_handle = service->handle_range.end;

		/* Discover the desriptors */
		characteristic_discover_descriptors(chrc, end_handle);
	}

	service->characteristics_discovered = true;
	service->discovering = false;
	service->request = 0;
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
	{ "UUID", "s", service_property_get_uuid },
	{ "Device", "o", service_property_get_device },
	{ "Primary", "b", service_property_get_is_primary },
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

	/*
	 * Discover remote GATT services here and mark as "initialized".
	 * Once initialized, we will only re-discover all services here if the
	 * device is not bonded. Otherwise, we will only rediscover when we
	 * receive an indication from the Service Changed Characteristic.
	 *
	 * TODO: For now, we always rediscover all services. Change this
	 * behavior once src/shared/gatt-db is integrated.
	 */
	info("btd_gatt_client: device connected. Initializing GATT services\n");

	gatt_client_initialize_services(client);
}

static void attio_disconnect_cb(gpointer user_data)
{
	struct btd_gatt_client *client = user_data;

	info("btd_gatt_client: device disconnected. Cleaning up GATT "
								"services\n");

	gatt_client_uninitialize_services(client);

	attio_cleanup(client);
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

	gatt_client_uninitialize_services(client);

	attio_cleanup(client);

	g_free(client);
}

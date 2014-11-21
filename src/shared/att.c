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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "src/shared/io.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "src/shared/timeout.h"
#include "lib/uuid.h"
#include "src/shared/att.h"

#define ATT_MIN_PDU_LEN			1  /* At least 1 byte for the opcode. */
#define ATT_OP_CMD_MASK			0x40
#define ATT_OP_SIGNED_MASK		0x80
#define ATT_TIMEOUT_INTERVAL		30000  /* 30000 ms */

/*
 * Common Profile and Service Error Code descriptions (see Supplement to the
 * Bluetooth Core Specification, sections 1.2 and 2). The error codes within
 * 0xE0-0xFC are reserved for future use. The remaining 3 are defined as the
 * following:
 */
#define BT_ERROR_CCC_IMPROPERLY_CONFIGURED	0xfd
#define BT_ERROR_ALREADY_IN_PROGRESS		0xfe
#define BT_ERROR_OUT_OF_RANGE			0xff

struct att_send_op;

struct bt_att {
	int ref_count;
	int fd;
	struct io *io;

	struct queue *req_queue;	/* Queued ATT protocol requests */
	struct att_send_op *pending_req;
	struct queue *ind_queue;	/* Queued ATT protocol indications */
	struct att_send_op *pending_ind;
	struct queue *write_queue;	/* Queue of PDUs ready to send */
	bool writer_active;

	struct queue *notify_list;	/* List of registered callbacks */
	bool in_notify;
	bool need_notify_cleanup;

	struct queue *disconn_list;	/* List of disconnect handlers */
	bool in_disconn;
	bool need_disconn_cleanup;

	bool in_req;			/* There's a pending incoming request */

	uint8_t *buf;
	uint16_t mtu;

	unsigned int next_send_id;	/* IDs for "send" ops */
	unsigned int next_reg_id;	/* IDs for registered callbacks */

	bt_att_timeout_func_t timeout_callback;
	bt_att_destroy_func_t timeout_destroy;
	void *timeout_data;

	bt_att_debug_func_t debug_callback;
	bt_att_destroy_func_t debug_destroy;
	void *debug_data;
};

enum att_op_type {
	ATT_OP_TYPE_REQ,
	ATT_OP_TYPE_RSP,
	ATT_OP_TYPE_CMD,
	ATT_OP_TYPE_IND,
	ATT_OP_TYPE_NOT,
	ATT_OP_TYPE_CONF,
	ATT_OP_TYPE_UNKNOWN,
};

static const struct {
	uint8_t opcode;
	enum att_op_type type;
} att_opcode_type_table[] = {
	{ BT_ATT_OP_ERROR_RSP,			ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_MTU_REQ,			ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_MTU_RSP,			ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_FIND_INFO_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_FIND_INFO_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_FIND_BY_TYPE_VAL_REQ,	ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_FIND_BY_TYPE_VAL_RSP,	ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_READ_BY_TYPE_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_READ_BY_TYPE_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_READ_REQ,			ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_READ_RSP,			ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_READ_BLOB_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_READ_BLOB_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_READ_MULT_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_READ_MULT_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_READ_BY_GRP_TYPE_REQ,	ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_READ_BY_GRP_TYPE_RSP,	ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_WRITE_REQ,			ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_WRITE_RSP,			ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_WRITE_CMD,			ATT_OP_TYPE_CMD },
	{ BT_ATT_OP_SIGNED_WRITE_CMD,		ATT_OP_TYPE_CMD },
	{ BT_ATT_OP_PREP_WRITE_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_PREP_WRITE_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_EXEC_WRITE_REQ,		ATT_OP_TYPE_REQ },
	{ BT_ATT_OP_EXEC_WRITE_RSP,		ATT_OP_TYPE_RSP },
	{ BT_ATT_OP_HANDLE_VAL_NOT,		ATT_OP_TYPE_NOT },
	{ BT_ATT_OP_HANDLE_VAL_IND,		ATT_OP_TYPE_IND },
	{ BT_ATT_OP_HANDLE_VAL_CONF,		ATT_OP_TYPE_CONF },
	{ }
};

static enum att_op_type get_op_type(uint8_t opcode)
{
	int i;

	for (i = 0; att_opcode_type_table[i].opcode; i++) {
		if (att_opcode_type_table[i].opcode == opcode)
			return att_opcode_type_table[i].type;
	}

	return ATT_OP_TYPE_UNKNOWN;
}

static const struct {
	uint8_t req_opcode;
	uint8_t rsp_opcode;
} att_req_rsp_mapping_table[] = {
	{ BT_ATT_OP_MTU_REQ,			BT_ATT_OP_MTU_RSP },
	{ BT_ATT_OP_FIND_INFO_REQ,		BT_ATT_OP_FIND_INFO_RSP},
	{ BT_ATT_OP_FIND_BY_TYPE_VAL_REQ,	BT_ATT_OP_FIND_BY_TYPE_VAL_RSP },
	{ BT_ATT_OP_READ_BY_TYPE_REQ,		BT_ATT_OP_READ_BY_TYPE_RSP },
	{ BT_ATT_OP_READ_REQ,			BT_ATT_OP_READ_RSP },
	{ BT_ATT_OP_READ_BLOB_REQ,		BT_ATT_OP_READ_BLOB_RSP },
	{ BT_ATT_OP_READ_MULT_REQ,		BT_ATT_OP_READ_MULT_RSP },
	{ BT_ATT_OP_READ_BY_GRP_TYPE_REQ,	BT_ATT_OP_READ_BY_GRP_TYPE_RSP },
	{ BT_ATT_OP_WRITE_REQ,			BT_ATT_OP_WRITE_RSP },
	{ BT_ATT_OP_PREP_WRITE_REQ,		BT_ATT_OP_PREP_WRITE_RSP },
	{ BT_ATT_OP_EXEC_WRITE_REQ,		BT_ATT_OP_EXEC_WRITE_RSP },
	{ }
};

static uint8_t get_req_opcode(uint8_t rsp_opcode)
{
	int i;

	for (i = 0; att_req_rsp_mapping_table[i].rsp_opcode; i++) {
		if (att_req_rsp_mapping_table[i].rsp_opcode == rsp_opcode)
			return att_req_rsp_mapping_table[i].req_opcode;
	}

	return 0;
}

struct att_send_op {
	unsigned int id;
	unsigned int timeout_id;
	enum att_op_type type;
	uint16_t opcode;
	void *pdu;
	uint16_t len;
	bt_att_response_func_t callback;
	bt_att_destroy_func_t destroy;
	void *user_data;
};

static void destroy_att_send_op(void *data)
{
	struct att_send_op *op = data;

	if (op->timeout_id)
		timeout_remove(op->timeout_id);

	if (op->destroy)
		op->destroy(op->user_data);

	free(op->pdu);
	free(op);
}

static void cancel_att_send_op(struct att_send_op *op)
{
	if (op->destroy)
		op->destroy(op->user_data);

	op->user_data = NULL;
	op->callback = NULL;
	op->destroy = NULL;
}

struct att_notify {
	unsigned int id;
	uint16_t opcode;
	bool removed;
	bt_att_notify_func_t callback;
	bt_att_destroy_func_t destroy;
	void *user_data;
};

static void destroy_att_notify(void *data)
{
	struct att_notify *notify = data;

	if (notify->destroy)
		notify->destroy(notify->user_data);

	free(notify);
}

static bool match_notify_id(const void *a, const void *b)
{
	const struct att_notify *notify = a;
	unsigned int id = PTR_TO_UINT(b);

	return notify->id == id;
}

static bool match_notify_removed(const void *a, const void *b)
{
	const struct att_notify *notify = a;

	return notify->removed;
}

static void mark_notify_removed(void *data, void *user_data)
{
	struct att_notify *notify = data;

	notify->removed = true;
}

struct att_disconn {
	unsigned int id;
	bool removed;
	bt_att_disconnect_func_t callback;
	bt_att_destroy_func_t destroy;
	void *user_data;
};

static void destroy_att_disconn(void *data)
{
	struct att_disconn *disconn = data;

	if (disconn->destroy)
		disconn->destroy(disconn->user_data);

	free(disconn);
}

static bool match_disconn_id(const void *a, const void *b)
{
	const struct att_disconn *disconn = a;
	unsigned int id = PTR_TO_UINT(b);

	return disconn->id == id;
}

static bool match_disconn_removed(const void *a, const void *b)
{
	const struct att_disconn *disconn = a;

	return disconn->removed;
}

static void mark_disconn_removed(void *data, void *user_data)
{
	struct att_disconn *disconn = data;

	disconn->removed = true;
}

static bool encode_pdu(struct att_send_op *op, const void *pdu,
						uint16_t length, uint16_t mtu)
{
	uint16_t pdu_len = 1;

	if (length && pdu)
		pdu_len += length;

	if (pdu_len > mtu)
		return false;

	op->len = pdu_len;
	op->pdu = malloc(op->len);
	if (!op->pdu)
		return false;

	((uint8_t *) op->pdu)[0] = op->opcode;
	if (pdu_len > 1)
		memcpy(op->pdu + 1, pdu, length);

	return true;
}

static struct att_send_op *create_att_send_op(uint8_t opcode, const void *pdu,
						uint16_t length, uint16_t mtu,
						bt_att_response_func_t callback,
						void *user_data,
						bt_att_destroy_func_t destroy)
{
	struct att_send_op *op;
	enum att_op_type op_type;

	if (length && !pdu)
		return NULL;

	op_type = get_op_type(opcode);
	if (op_type == ATT_OP_TYPE_UNKNOWN)
		return NULL;

	/* If the opcode corresponds to an operation type that does not elicit a
	 * response from the remote end, then no callback should have been
	 * provided, since it will never be called.
	 */
	if (callback && op_type != ATT_OP_TYPE_REQ && op_type != ATT_OP_TYPE_IND)
		return NULL;

	/* Similarly, if the operation does elicit a response then a callback
	 * must be provided.
	 */
	if (!callback && (op_type == ATT_OP_TYPE_REQ || op_type == ATT_OP_TYPE_IND))
		return NULL;

	op = new0(struct att_send_op, 1);
	if (!op)
		return NULL;

	op->type = op_type;
	op->opcode = opcode;
	op->callback = callback;
	op->destroy = destroy;
	op->user_data = user_data;

	if (!encode_pdu(op, pdu, length, mtu)) {
		free(op);
		return NULL;
	}

	return op;
}

static struct att_send_op *pick_next_send_op(struct bt_att *att)
{
	struct att_send_op *op;

	/* See if any operations are already in the write queue */
	op = queue_pop_head(att->write_queue);
	if (op)
		return op;

	/* If there is no pending request, pick an operation from the
	 * request queue.
	 */
	if (!att->pending_req) {
		op = queue_pop_head(att->req_queue);
		if (op)
			return op;
	}

	/* There is either a request pending or no requests queued. If there is
	 * no pending indication, pick an operation from the indication queue.
	 */
	if (!att->pending_ind) {
		op = queue_pop_head(att->ind_queue);
		if (op)
			return op;
	}

	return NULL;
}

struct timeout_data {
	struct bt_att *att;
	unsigned int id;
};

static bool timeout_cb(void *user_data)
{
	struct timeout_data *timeout = user_data;
	struct bt_att *att = timeout->att;
	struct att_send_op *op = NULL;

	if (att->pending_req && att->pending_req->id == timeout->id) {
		op = att->pending_req;
		att->pending_req = NULL;
	} else if (att->pending_ind && att->pending_ind->id == timeout->id) {
		op = att->pending_ind;
		att->pending_ind = NULL;
	}

	if (!op)
		return false;

	util_debug(att->debug_callback, att->debug_data,
				"Operation timed out: 0x%02x", op->opcode);

	if (att->timeout_callback)
		att->timeout_callback(op->id, op->opcode, att->timeout_data);

	op->timeout_id = 0;
	destroy_att_send_op(op);

	/*
	 * Directly terminate the connection as required by the ATT protocol.
	 * This should trigger an io disconnect event which will clean up the
	 * io and notify the upper layer.
	 */
	close(att->fd);

	return false;
}

static void write_watch_destroy(void *user_data)
{
	struct bt_att *att = user_data;

	att->writer_active = false;
}

static bool can_write_data(struct io *io, void *user_data)
{
	struct bt_att *att = user_data;
	struct att_send_op *op;
	struct timeout_data *timeout;
	ssize_t ret;
	struct iovec iov;

	op = pick_next_send_op(att);
	if (!op)
		return false;

	iov.iov_base = op->pdu;
	iov.iov_len = op->len;

	ret = io_send(io, &iov, 1);
	if (ret < 0) {
		util_debug(att->debug_callback, att->debug_data,
					"write failed: %s", strerror(-ret));
		if (op->callback)
			op->callback(BT_ATT_OP_ERROR_RSP, NULL, 0,
							op->user_data);

		destroy_att_send_op(op);
		return true;
	}

	util_debug(att->debug_callback, att->debug_data,
					"ATT op 0x%02x", op->opcode);

	util_hexdump('<', op->pdu, ret, att->debug_callback, att->debug_data);

	/* Based on the operation type, set either the pending request or the
	 * pending indication. If it came from the write queue, then there is
	 * no need to keep it around.
	 */
	switch (op->type) {
	case ATT_OP_TYPE_REQ:
		att->pending_req = op;
		break;
	case ATT_OP_TYPE_IND:
		att->pending_ind = op;
		break;
	case ATT_OP_TYPE_RSP:
		/* Set in_req to false to indicate that no request is pending */
		att->in_req = false;
	default:
		destroy_att_send_op(op);
		return true;
	}

	timeout = new0(struct timeout_data, 1);
	if (!timeout)
		return true;

	timeout->att = att;
	timeout->id = op->id;
	op->timeout_id = timeout_add(ATT_TIMEOUT_INTERVAL, timeout_cb,
								timeout, free);

	/* Return true as there may be more operations ready to write. */
	return true;
}

static void wakeup_writer(struct bt_att *att)
{
	if (att->writer_active)
		return;

	/* Set the write handler only if there is anything that can be sent
	 * at all.
	 */
	if (queue_isempty(att->write_queue)) {
		if ((att->pending_req || queue_isempty(att->req_queue)) &&
			(att->pending_ind || queue_isempty(att->ind_queue)))
			return;
	}

	if (!io_set_write_handler(att->io, can_write_data, att,
							write_watch_destroy))
		return;

	att->writer_active = true;
}

static void disconn_handler(void *data, void *user_data)
{
	struct att_disconn *disconn = data;

	if (disconn->removed)
		return;

	if (disconn->callback)
		disconn->callback(disconn->user_data);
}

static bool disconnect_cb(struct io *io, void *user_data)
{
	struct bt_att *att = user_data;

	io_destroy(att->io);
	att->io = NULL;

	util_debug(att->debug_callback, att->debug_data,
						"Physical link disconnected");

	bt_att_ref(att);
	att->in_disconn = true;
	queue_foreach(att->disconn_list, disconn_handler, NULL);
	att->in_disconn = false;

	if (att->need_disconn_cleanup) {
		queue_remove_all(att->disconn_list, match_disconn_removed, NULL,
							destroy_att_disconn);
		att->need_disconn_cleanup = false;
	}

	bt_att_cancel_all(att);
	bt_att_unregister_all(att);

	bt_att_unref(att);

	return false;
}

static void handle_rsp(struct bt_att *att, uint8_t opcode, uint8_t *pdu,
								ssize_t pdu_len)
{
	struct att_send_op *op = att->pending_req;
	uint8_t req_opcode;
	uint8_t rsp_opcode;
	uint8_t *rsp_pdu = NULL;
	uint16_t rsp_pdu_len = 0;

	/*
	 * If no request is pending, then the response is unexpected. Disconnect
	 * the bearer.
	 */
	if (!op) {
		util_debug(att->debug_callback, att->debug_data,
					"Received unexpected ATT response");
		disconnect_cb(att->io, att);
		return;
	}

	/*
	 * If the received response doesn't match the pending request, or if
	 * the request is malformed, end the current request with failure.
	 */
	if (opcode == BT_ATT_OP_ERROR_RSP) {
		if (pdu_len != 4)
			goto fail;

		req_opcode = pdu[0];
	} else if (!(req_opcode = get_req_opcode(opcode)))
		goto fail;

	if (req_opcode != op->opcode)
		goto fail;

	rsp_opcode = opcode;

	if (pdu_len > 0) {
		rsp_pdu = pdu;
		rsp_pdu_len = pdu_len;
	}

	goto done;

fail:
	util_debug(att->debug_callback, att->debug_data,
			"Failed to handle response PDU; opcode: 0x%02x", opcode);

	rsp_opcode = BT_ATT_OP_ERROR_RSP;

done:
	if (op->callback)
		op->callback(rsp_opcode, rsp_pdu, rsp_pdu_len, op->user_data);

	destroy_att_send_op(op);
	att->pending_req = NULL;

	wakeup_writer(att);
}

static void handle_conf(struct bt_att *att, uint8_t *pdu, ssize_t pdu_len)
{
	struct att_send_op *op = att->pending_ind;

	/*
	 * Disconnect the bearer if the confirmation is unexpected or the PDU is
	 * invalid.
	 */
	if (!op || pdu_len) {
		util_debug(att->debug_callback, att->debug_data,
				"Received unexpected/invalid ATT confirmation");
		disconnect_cb(att->io, att);
		return;
	}

	if (op->callback)
		op->callback(BT_ATT_OP_HANDLE_VAL_CONF, NULL, 0, op->user_data);

	destroy_att_send_op(op);
	att->pending_ind = NULL;

	wakeup_writer(att);
}

struct notify_data {
	uint8_t opcode;
	uint8_t *pdu;
	ssize_t pdu_len;
	bool handler_found;
};

static bool opcode_match(uint8_t opcode, uint8_t test_opcode)
{
	if (opcode == BT_ATT_ALL_REQUESTS &&
				    get_op_type(test_opcode) == ATT_OP_TYPE_REQ)
		return true;

	return opcode == test_opcode;
}

static void notify_handler(void *data, void *user_data)
{
	struct att_notify *notify = data;
	struct notify_data *not_data = user_data;

	if (notify->removed)
		return;

	if (!opcode_match(notify->opcode, not_data->opcode))
		return;

	not_data->handler_found = true;

	if (notify->callback)
		notify->callback(not_data->opcode, not_data->pdu,
					not_data->pdu_len, notify->user_data);
}

static void respond_not_supported(struct bt_att *att, uint8_t opcode)
{
	uint8_t pdu[4];

	pdu[0] = opcode;
	pdu[1] = 0;
	pdu[2] = 0;
	pdu[3] = BT_ATT_ERROR_REQUEST_NOT_SUPPORTED;

	bt_att_send(att, BT_ATT_OP_ERROR_RSP, pdu, sizeof(pdu), NULL, NULL,
									NULL);
}

static void handle_notify(struct bt_att *att, uint8_t opcode, uint8_t *pdu,
								ssize_t pdu_len)
{
	struct notify_data data;

	bt_att_ref(att);
	att->in_notify = true;

	memset(&data, 0, sizeof(data));
	data.opcode = opcode;

	if (pdu_len > 0) {
		data.pdu = pdu;
		data.pdu_len = pdu_len;
	}

	queue_foreach(att->notify_list, notify_handler, &data);

	att->in_notify = false;

	if (att->need_notify_cleanup) {
		queue_remove_all(att->notify_list, match_notify_removed, NULL,
							destroy_att_notify);
		att->need_notify_cleanup = false;
	}

	bt_att_unref(att);

	/*
	 * If this was a request and no handler was registered for it, respond
	 * with "Not Supported"
	 */
	if (!data.handler_found && get_op_type(opcode) == ATT_OP_TYPE_REQ)
		respond_not_supported(att, opcode);
}

static bool can_read_data(struct io *io, void *user_data)
{
	struct bt_att *att = user_data;
	uint8_t opcode;
	uint8_t *pdu;
	ssize_t bytes_read;

	bytes_read = read(att->fd, att->buf, att->mtu);
	if (bytes_read < 0)
		return false;

	util_hexdump('>', att->buf, bytes_read,
					att->debug_callback, att->debug_data);

	if (bytes_read < ATT_MIN_PDU_LEN)
		return true;

	pdu = att->buf;
	opcode = pdu[0];

	/* Act on the received PDU based on the opcode type */
	switch (get_op_type(opcode)) {
	case ATT_OP_TYPE_RSP:
		util_debug(att->debug_callback, att->debug_data,
				"ATT response received: 0x%02x", opcode);
		handle_rsp(att, opcode, pdu + 1, bytes_read - 1);
		break;
	case ATT_OP_TYPE_CONF:
		util_debug(att->debug_callback, att->debug_data,
				"ATT confirmation received: 0x%02x", opcode);
		handle_conf(att, pdu + 1, bytes_read - 1);
		break;
	case ATT_OP_TYPE_REQ:
		/*
		 * If a request is currently pending, then the sequential
		 * protocol was violated. Disconnect the bearer, which will
		 * promptly notify the upper layer via disconnect handlers.
		 */
		if (att->in_req) {
			util_debug(att->debug_callback, att->debug_data,
					"Received request while another is "
					"pending: 0x%02x", opcode);
			close(att->fd);

			return false;
		}

		att->in_req = true;

		/* Fall through to the next case */
	default:
		/* For all other opcodes notify the upper layer of the PDU and
		 * let them act on it.
		 */
		util_debug(att->debug_callback, att->debug_data,
					"ATT PDU received: 0x%02x", opcode);
		handle_notify(att, opcode, pdu + 1, bytes_read - 1);
		break;
	}

	return true;
}

struct bt_att *bt_att_new(int fd)
{
	struct bt_att *att;

	if (fd < 0)
		return NULL;

	att = new0(struct bt_att, 1);
	if (!att)
		return NULL;

	att->fd = fd;

	att->mtu = BT_ATT_DEFAULT_LE_MTU;
	att->buf = malloc(att->mtu);
	if (!att->buf)
		goto fail;

	att->io = io_new(fd);
	if (!att->io)
		goto fail;

	att->req_queue = queue_new();
	if (!att->req_queue)
		goto fail;

	att->ind_queue = queue_new();
	if (!att->ind_queue)
		goto fail;

	att->write_queue = queue_new();
	if (!att->write_queue)
		goto fail;

	att->notify_list = queue_new();
	if (!att->notify_list)
		goto fail;

	att->disconn_list = queue_new();
	if (!att->disconn_list)
		goto fail;

	if (!io_set_read_handler(att->io, can_read_data, att, NULL))
		goto fail;

	if (!io_set_disconnect_handler(att->io, disconnect_cb, att, NULL))
		goto fail;

	return bt_att_ref(att);

fail:
	queue_destroy(att->req_queue, NULL);
	queue_destroy(att->ind_queue, NULL);
	queue_destroy(att->write_queue, NULL);
	queue_destroy(att->notify_list, NULL);
	queue_destroy(att->disconn_list, NULL);
	io_destroy(att->io);
	free(att->buf);
	free(att);

	return NULL;
}

struct bt_att *bt_att_ref(struct bt_att *att)
{
	if (!att)
		return NULL;

	__sync_fetch_and_add(&att->ref_count, 1);

	return att;
}

void bt_att_unref(struct bt_att *att)
{
	if (!att)
		return;

	if (__sync_sub_and_fetch(&att->ref_count, 1))
		return;

	bt_att_unregister_all(att);
	bt_att_cancel_all(att);

	if (att->pending_req)
		destroy_att_send_op(att->pending_req);

	if (att->pending_ind)
		destroy_att_send_op(att->pending_ind);

	io_destroy(att->io);
	att->io = NULL;

	queue_destroy(att->req_queue, NULL);
	queue_destroy(att->ind_queue, NULL);
	queue_destroy(att->write_queue, NULL);
	queue_destroy(att->notify_list, NULL);
	queue_destroy(att->disconn_list, NULL);
	att->req_queue = NULL;
	att->ind_queue = NULL;
	att->write_queue = NULL;
	att->notify_list = NULL;

	if (att->timeout_destroy)
		att->timeout_destroy(att->timeout_data);

	if (att->debug_destroy)
		att->debug_destroy(att->debug_data);

	free(att->buf);
	att->buf = NULL;

	free(att);
}

int bt_att_get_fd(struct bt_att *att)
{
	if (!att)
		return -1;

	return att->fd;
}

bool bt_att_set_close_on_unref(struct bt_att *att, bool do_close)
{
	if (!att || !att->io)
		return false;

	return io_set_close_on_destroy(att->io, do_close);
}

bool bt_att_set_debug(struct bt_att *att, bt_att_debug_func_t callback,
				void *user_data, bt_att_destroy_func_t destroy)
{
	if (!att)
		return false;

	if (att->debug_destroy)
		att->debug_destroy(att->debug_data);

	att->debug_callback = callback;
	att->debug_destroy = destroy;
	att->debug_data = user_data;

	return true;
}

uint16_t bt_att_get_mtu(struct bt_att *att)
{
	if (!att)
		return 0;

	return att->mtu;
}

bool bt_att_set_mtu(struct bt_att *att, uint16_t mtu)
{
	void *buf;

	if (!att)
		return false;

	if (mtu < BT_ATT_DEFAULT_LE_MTU)
		return false;

	buf = malloc(mtu);
	if (!buf)
		return false;

	free(att->buf);

	att->mtu = mtu;
	att->buf = buf;

	return true;
}

bool bt_att_set_timeout_cb(struct bt_att *att, bt_att_timeout_func_t callback,
						void *user_data,
						bt_att_destroy_func_t destroy)
{
	if (!att)
		return false;

	if (att->timeout_destroy)
		att->timeout_destroy(att->timeout_data);

	att->timeout_callback = callback;
	att->timeout_destroy = destroy;
	att->timeout_data = user_data;

	return true;
}

unsigned int bt_att_register_disconnect(struct bt_att *att,
					bt_att_disconnect_func_t callback,
					void *user_data,
					bt_att_destroy_func_t destroy)
{
	struct att_disconn *disconn;

	if (!att || !att->io)
		return 0;

	disconn = new0(struct att_disconn, 1);
	if (!disconn)
		return 0;

	disconn->callback = callback;
	disconn->destroy = destroy;
	disconn->user_data = user_data;

	if (att->next_reg_id < 1)
		att->next_reg_id = 1;

	disconn->id = att->next_reg_id++;

	if (!queue_push_tail(att->disconn_list, disconn)) {
		free(disconn);
		return 0;
	}

	return disconn->id;
}

bool bt_att_unregister_disconnect(struct bt_att *att, unsigned int id)
{
	struct att_disconn *disconn;

	if (!att || !id)
		return false;

	disconn = queue_find(att->disconn_list, match_disconn_id,
							UINT_TO_PTR(id));
	if (!disconn)
		return false;

	if (!att->in_disconn) {
		queue_remove(att->disconn_list, disconn);
		destroy_att_disconn(disconn);
		return true;
	}

	disconn->removed = true;
	att->need_disconn_cleanup = true;

	return true;
}

unsigned int bt_att_send(struct bt_att *att, uint8_t opcode,
				const void *pdu, uint16_t length,
				bt_att_response_func_t callback, void *user_data,
				bt_att_destroy_func_t destroy)
{
	struct att_send_op *op;
	bool result;

	if (!att || !att->io)
		return 0;

	op = create_att_send_op(opcode, pdu, length, att->mtu, callback,
							user_data, destroy);
	if (!op)
		return 0;

	if (att->next_send_id < 1)
		att->next_send_id = 1;

	op->id = att->next_send_id++;

	/* Add the op to the correct queue based on its type */
	switch (op->type) {
	case ATT_OP_TYPE_REQ:
		result = queue_push_tail(att->req_queue, op);
		break;
	case ATT_OP_TYPE_IND:
		result = queue_push_tail(att->ind_queue, op);
		break;
	default:
		result = queue_push_tail(att->write_queue, op);
		break;
	}

	if (!result) {
		free(op->pdu);
		free(op);
		return 0;
	}

	wakeup_writer(att);

	return op->id;
}

static bool match_op_id(const void *a, const void *b)
{
	const struct att_send_op *op = a;
	unsigned int id = PTR_TO_UINT(b);

	return op->id == id;
}

bool bt_att_cancel(struct bt_att *att, unsigned int id)
{
	struct att_send_op *op;

	if (!att || !id)
		return false;

	if (att->pending_req && att->pending_req->id == id) {
		/* Don't cancel the pending request; remove it's handlers */
		cancel_att_send_op(att->pending_req);
		return true;
	}

	if (att->pending_ind && att->pending_ind->id == id) {
		/* Don't cancel the pending indication; remove it's handlers */
		cancel_att_send_op(att->pending_ind);
		return true;
	}

	op = queue_remove_if(att->req_queue, match_op_id, UINT_TO_PTR(id));
	if (op)
		goto done;

	op = queue_remove_if(att->ind_queue, match_op_id, UINT_TO_PTR(id));
	if (op)
		goto done;

	op = queue_remove_if(att->write_queue, match_op_id, UINT_TO_PTR(id));
	if (op)
		goto done;

	if (!op)
		return false;

done:
	destroy_att_send_op(op);

	wakeup_writer(att);

	return true;
}

bool bt_att_cancel_all(struct bt_att *att)
{
	if (!att)
		return false;

	queue_remove_all(att->req_queue, NULL, NULL, destroy_att_send_op);
	queue_remove_all(att->ind_queue, NULL, NULL, destroy_att_send_op);
	queue_remove_all(att->write_queue, NULL, NULL, destroy_att_send_op);

	if (att->pending_req)
		/* Don't cancel the pending request; remove it's handlers */
		cancel_att_send_op(att->pending_req);

	if (att->pending_ind)
		/* Don't cancel the pending request; remove it's handlers */
		cancel_att_send_op(att->pending_ind);

	return true;
}

static uint8_t att_ecode_from_error(int err)
{
	/*
	 * If the error fits in a single byte, treat it as an ATT protocol
	 * error as is. Since "0" is not a valid ATT protocol error code, we map
	 * that to UNLIKELY below.
	 */
	if (err > 0 && err < UINT8_MAX)
		return err;

	/*
	 * Since we allow UNIX errnos, map them to appropriate ATT protocol
	 * and "Common Profile and Service" error codes.
	 */
	switch (err) {
	case -ENOENT:
		return BT_ATT_ERROR_INVALID_HANDLE;
	case -ENOMEM:
		return BT_ATT_ERROR_INSUFFICIENT_RESOURCES;
	case -EALREADY:
		return BT_ERROR_ALREADY_IN_PROGRESS;
	case -EOVERFLOW:
		return BT_ERROR_OUT_OF_RANGE;
	}

	return BT_ATT_ERROR_UNLIKELY;
}

unsigned int bt_att_send_error_rsp(struct bt_att *att, uint8_t opcode,
						uint16_t handle, int error)
{
	struct bt_att_pdu_error_rsp pdu;
	uint8_t ecode;

	if (!att || !opcode)
		return 0;

	ecode = att_ecode_from_error(error);

	memset(&pdu, 0, sizeof(pdu));

	pdu.opcode = opcode;
	put_le16(handle, &pdu.handle);
	pdu.ecode = ecode;

	return bt_att_send(att, BT_ATT_OP_ERROR_RSP, &pdu, sizeof(pdu),
							NULL, NULL, NULL);
}

const char *bt_att_ecode_to_string(uint8_t ecode)
{
	switch (ecode)  {
	case BT_ATT_ERROR_INVALID_HANDLE:
		return "Invalid handle";
	case BT_ATT_ERROR_READ_NOT_PERMITTED:
		return "Attribute can't be read";
	case BT_ATT_ERROR_WRITE_NOT_PERMITTED:
		return "Attribute can't be written";
	case BT_ATT_ERROR_INVALID_PDU:
		return "Attribute PDU was invalid";
	case BT_ATT_ERROR_AUTHENTICATION:
		return "Attribute requires authentication before read/write";
	case BT_ATT_ERROR_REQUEST_NOT_SUPPORTED:
		return "Server doesn't support the request received";
	case BT_ATT_ERROR_INVALID_OFFSET:
		return "Offset past the end of the attribute";
	case BT_ATT_ERROR_AUTHORIZATION:
		return "Attribute requires authorization before read/write";
	case BT_ATT_ERROR_PREPARE_QUEUE_FULL:
		return "Too many prepare writes have been queued";
	case BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND:
		return "No attribute found within the given range";
	case BT_ATT_ERROR_ATTRIBUTE_NOT_LONG:
		return "Attribute can't be read/written using Read Blob Req";
	case BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE:
		return "Encryption Key Size is insufficient";
	case BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN:
		return "Attribute value length is invalid";
	case BT_ATT_ERROR_UNLIKELY:
		return "Request attribute has encountered an unlikely error";
	case BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION:
		return "Encryption required before read/write";
	case BT_ATT_ERROR_UNSUPPORTED_GROUP_TYPE:
		return "Attribute type is not a supported grouping attribute";
	case BT_ATT_ERROR_INSUFFICIENT_RESOURCES:
		return "Insufficient Resources to complete the request";
	default:
		return "Unknown error code";
	}
}

unsigned int bt_att_register(struct bt_att *att, uint8_t opcode,
						bt_att_notify_func_t callback,
						void *user_data,
						bt_att_destroy_func_t destroy)
{
	struct att_notify *notify;

	if (!att || !callback || !att->io)
		return 0;

	notify = new0(struct att_notify, 1);
	if (!notify)
		return 0;

	notify->opcode = opcode;
	notify->callback = callback;
	notify->destroy = destroy;
	notify->user_data = user_data;

	if (att->next_reg_id < 1)
		att->next_reg_id = 1;

	notify->id = att->next_reg_id++;

	if (!queue_push_tail(att->notify_list, notify)) {
		free(notify);
		return 0;
	}

	return notify->id;
}

bool bt_att_unregister(struct bt_att *att, unsigned int id)
{
	struct att_notify *notify;

	if (!att || !id)
		return false;

	notify = queue_find(att->notify_list, match_notify_id,
							UINT_TO_PTR(id));
	if (!notify)
		return false;

	if (!att->in_notify) {
		queue_remove(att->notify_list, notify);
		destroy_att_notify(notify);
		return true;
	}

	notify->removed = true;
	att->need_notify_cleanup = true;

	return true;
}

bool bt_att_unregister_all(struct bt_att *att)
{
	if (!att)
		return false;

	if (att->in_notify) {
		queue_foreach(att->notify_list, mark_notify_removed, NULL);
		att->need_notify_cleanup = true;
	} else {
		queue_remove_all(att->notify_list, NULL, NULL,
							destroy_att_notify);
	}

	if (att->in_disconn) {
		queue_foreach(att->disconn_list, mark_disconn_removed, NULL);
		att->need_disconn_cleanup = true;
	} else {
		queue_remove_all(att->disconn_list, NULL, NULL,
							destroy_att_disconn);
	}

	return true;
}

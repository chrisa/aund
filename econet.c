/*-
 * Copyright (c) 2021-2025 Chris Andrews <chris@nodnol.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Implementation of AF_ECONET for aund. */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "aun.h"
#include "extern.h"
#include "fileserver.h"
#include "version.h"
#include "if_ec.h"

#define ECONET_PHASE_POLL_US 100000
#define ECONET_XMIT_WATCHDOG 10
#define ECONET_RECV_WATCHDOG 10
#define ECONET_SCOUT_RETRIES 5
#define ECONET_DATA_PORT 0x97

enum econet_socket_id {
	ECONET_SOCKET_FS,
	ECONET_SOCKET_DATA,
	ECONET_SOCKET_IMMEDIATE,
	ECONET_SOCKET_COUNT,
};

struct econet_addr {
	uint8_t station;
	uint8_t network;
};

union internal_addr {
	struct aun_srcaddr srcaddr;
	struct econet_addr eaddr;
};

/* Offset of packet payload in struct aun_packet. */
#define PKTOFF (offsetof(struct aun_packet, data))

enum inbound_state {
	IN_IDLE,
	IN_SEND_SCOUT_ACK,
	IN_WAIT_DATA,
	IN_SEND_DATA_ACK,
	IN_WAIT_COMPLETE,
};

enum outbound_state {
	OUT_IDLE,
	OUT_SEND_SCOUT,
	OUT_WAIT_SCOUT_ACK,
	OUT_SEND_DATA,
	OUT_WAIT_DATA_ACK,
	OUT_WAIT_COMPLETE,
	OUT_DONE,
	OUT_FAILED,
};

struct queued_request {
	struct queued_request *next;
	struct sockaddr_ec source;
	size_t length;
	unsigned char data[];
};

static int sockets[ECONET_SOCKET_COUNT];
static unsigned char rbuf[65536];
static unsigned char phasebuf[ECONET_PAYLOAD_MTU];
static struct aun_packet *const rpkt = (struct aun_packet *)rbuf;
static unsigned long next_cookie;
static struct queued_request *request_head;
static struct queued_request *request_tail;

static struct {
	enum inbound_state state;
	int sock;
	struct sockaddr_ec source;
	struct queued_request *request;
} inbound;

static struct {
	enum outbound_state state;
	int sock;
	struct sockaddr_ec destination;
	const unsigned char *data;
	size_t length;
	unsigned int retries;
	int error;
} outbound;

enum immediate_reply_state {
	IMMEDIATE_IDLE,
	IMMEDIATE_SEND,
	IMMEDIATE_WAIT_COMPLETE,
};

static struct {
	enum immediate_reply_state state;
	int sock;
	struct sockaddr_ec destination;
	unsigned char data[4];
} immediate_reply;

static unsigned long econet_next_cookie(void)
{
	if (++next_cookie == 0)
		next_cookie = 1;
	return next_cookie;
}

static bool same_peer(const struct sockaddr_ec *a,
		      const struct sockaddr_ec *b)
{
	return a->addr.net == b->addr.net &&
	       a->addr.station == b->addr.station;
}

static bool transient_send_error(void)
{
	return errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS;
}

static int econet_status_errno(uint8_t type)
{
	switch (type & ECTYPE_TRANSMIT_RESULT_MASK) {
	case EC_STATUS_OK:
		return 0;
	case EC_STATUS_BAD_STATE:
	case EC_STATUS_BAD_TOKEN:
		return EPROTO;
	case EC_STATUS_QUEUE_FULL:
		return ENOBUFS;
	case EC_STATUS_BAD_LENGTH:
		return EMSGSIZE;
	case EC_STATUS_ABORTED:
		return ECANCELED;
	case EC_STATUS_TIMEOUT:
		return ETIMEDOUT;
	case EC_STATUS_DEVICE_DOWN:
		return ENETDOWN;
	default:
		return EIO;
	}
}

static int open_socket(uint8_t port)
{
	struct sockaddr_ec local = {
		.sec_family = AF_ECONET,
		.port = port,
	};
	int sock;
	int fl;

	sock = socket(AF_ECONET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;
	if (bind(sock, (const struct sockaddr *)&local, sizeof(local)) < 0)
		goto fail;
	if ((fl = fcntl(sock, F_GETFL)) < 0)
		goto fail;
	if (fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0)
		goto fail;
	return sock;

fail:
	close(sock);
	return -1;
}

static void econet_setup(void)
{
	/*
	 * Bind the ports aund actually owns.  A single unbound socket would
	 * also receive otherwise-unclaimed traffic for unrelated services.
	 * The socket which receives a scout must send that transaction's ACKs,
	 * so remember the descriptor alongside each in-flight transaction.
	 */
	static const uint8_t ports[ECONET_SOCKET_COUNT] = {
		[ECONET_SOCKET_FS] = EC_PORT_FS,
		[ECONET_SOCKET_DATA] = ECONET_DATA_PORT,
		[ECONET_SOCKET_IMMEDIATE] = 0,
	};
	int i;

	for (i = 0; i < ECONET_SOCKET_COUNT; i++) {
		sockets[i] = open_socket(ports[i]);
		if (sockets[i] < 0)
			err(1, "AF_ECONET socket for port 0x%02x", ports[i]);
	}
}

static int send_phase(int sock, const struct sockaddr_ec *address,
		      const void *data, size_t length)
{
	ssize_t sent = sendto(sock, data, length, 0,
			      (const struct sockaddr *)address, sizeof(*address));

	if (sent == (ssize_t)length)
		return 1;
	if (sent < 0 && transient_send_error())
		return 0;
	if (sent >= 0)
		errno = EIO;
	return -1;
}

static ssize_t receive_phase(int *source_sock, struct sockaddr_ec *source,
			     bool forever)
{
	fd_set readfds;
	struct timeval timeout = {
		.tv_sec = 0,
		.tv_usec = ECONET_PHASE_POLL_US,
	};
	socklen_t source_len;
	int max_sock = -1;
	int i;
	int ready;

	FD_ZERO(&readfds);
	for (i = 0; i < ECONET_SOCKET_COUNT; i++) {
		FD_SET(sockets[i], &readfds);
		if (sockets[i] > max_sock)
			max_sock = sockets[i];
	}
	ready = select(max_sock + 1, &readfds, NULL, NULL,
		       forever ? NULL : &timeout);
	if (ready < 0)
		return -1;
	if (!ready) {
		errno = ETIMEDOUT;
		return -1;
	}
	for (i = 0; i < ECONET_SOCKET_COUNT; i++) {
		if (!FD_ISSET(sockets[i], &readfds))
			continue;
		source_len = sizeof(*source);
		*source_sock = sockets[i];
		return recvfrom(sockets[i], phasebuf, sizeof(phasebuf), 0,
				(struct sockaddr *)source, &source_len);
	}
	errno = EIO;
	return -1;
}

static struct queued_request *alloc_request(const struct sockaddr_ec *source,
					    const void *data, size_t length)
{
	struct queued_request *request;

	request = malloc(sizeof(*request) + length);
	if (!request)
		return NULL;
	request->next = NULL;
	request->source = *source;
	request->length = length;
	if (length)
		memcpy(request->data, data, length);
	return request;
}

static void queue_request(struct queued_request *request)
{
	if (request_tail)
		request_tail->next = request;
	else
		request_head = request;
	request_tail = request;
}

static void abandon_inbound(const char *reason)
{
	if (inbound.state == IN_IDLE)
		return;
	if (debug)
		warnx("abandoning inbound Econet transaction: %s", reason);
	free(inbound.request);
	inbound.request = NULL;
	memset(&inbound.source, 0, sizeof(inbound.source));
	inbound.sock = -1;
	inbound.state = IN_IDLE;
}

static bool request_matches(const struct queued_request *request,
			    const struct aun_srcaddr *from, int want_port)
{
	const union internal_addr *address =
		(const union internal_addr *)from;

	if ((address->eaddr.network || address->eaddr.station) &&
	    (address->eaddr.network != request->source.addr.net ||
	     address->eaddr.station != request->source.addr.station))
		return false;
	return !want_port || want_port == request->source.port;
}

static struct queued_request *take_request(const struct aun_srcaddr *from,
					   int want_port)
{
	struct queued_request *previous = NULL;
	struct queued_request *request = request_head;

	while (request && !request_matches(request, from, want_port)) {
		previous = request;
		request = request->next;
	}
	if (!request)
		return NULL;
	if (previous)
		previous->next = request->next;
	else
		request_head = request->next;
	if (request_tail == request)
		request_tail = previous;
	request->next = NULL;
	return request;
}

static void progress_inbound(void)
{
	struct sockaddr_ec reply;
	int sent;

	if (inbound.state != IN_SEND_SCOUT_ACK &&
	    inbound.state != IN_SEND_DATA_ACK)
		return;
	reply = inbound.source;
	reply.type = ECTYPE_PACKET_ACK;
	reply.port = 0;
	reply.cb = 0;
	sent = send_phase(inbound.sock, &reply, NULL, 0);
	if (sent <= 0)
		return;
	if (inbound.state == IN_SEND_SCOUT_ACK) {
		inbound.state = IN_WAIT_DATA;
	} else {
		inbound.state = IN_WAIT_COMPLETE;
	}
}

static void progress_outbound(void)
{
	struct sockaddr_ec destination = outbound.destination;
	int sent;

	if (outbound.state == OUT_SEND_SCOUT) {
		destination.type = ECTYPE_PACKET_SCOUT;
		destination.cookie = outbound.destination.cookie;
		sent = send_phase(outbound.sock, &destination, NULL, 0);
		if (sent > 0)
			outbound.state = OUT_WAIT_SCOUT_ACK;
		else if (sent < 0) {
			outbound.error = errno;
			outbound.state = OUT_FAILED;
		}
	} else if (outbound.state == OUT_SEND_DATA) {
		destination.type = ECTYPE_PACKET_DATA;
		destination.port = 0;
		destination.cb = 0;
		sent = send_phase(outbound.sock, &destination, outbound.data,
				  outbound.length);
		if (sent > 0)
			outbound.state = OUT_WAIT_DATA_ACK;
		else if (sent < 0) {
			outbound.error = errno;
			outbound.state = OUT_FAILED;
		}
	}
}

static void progress_immediate_reply(void)
{
	int sent;

	if (immediate_reply.state != IMMEDIATE_SEND)
		return;
	sent = send_phase(immediate_reply.sock, &immediate_reply.destination,
			  immediate_reply.data, sizeof(immediate_reply.data));
	if (sent > 0)
		immediate_reply.state = IMMEDIATE_WAIT_COMPLETE;
	else if (sent < 0) {
		if (debug)
			warn("immediate reply");
		immediate_reply.state = IMMEDIATE_IDLE;
	}
}

static void progress_transactions(void)
{
	progress_immediate_reply();
	progress_inbound();
	progress_outbound();
}

static void handle_immediate(int source_sock,
			     const struct sockaddr_ec *source)
{
	if (source->cb != 0x88 || immediate_reply.state != IMMEDIATE_IDLE)
		return;
	immediate_reply.sock = source_sock;
	immediate_reply.destination = *source;
	immediate_reply.destination.type = ECTYPE_PACKET_IMMEDIATE_REPLY;
	immediate_reply.destination.port = 0;
	immediate_reply.destination.cb = 0;
	immediate_reply.data[0] = AUND_MACHINE_PEEK_LO;
	immediate_reply.data[1] = AUND_MACHINE_PEEK_HI;
	immediate_reply.data[2] = AUND_VERSION_MINOR;
	immediate_reply.data[3] = AUND_VERSION_MAJOR;
	immediate_reply.state = IMMEDIATE_SEND;
	progress_immediate_reply();
}

static void handle_status(int source_sock, const struct sockaddr_ec *event)
{
	int error = econet_status_errno(event->type);

	if (immediate_reply.state != IMMEDIATE_IDLE &&
	    source_sock == immediate_reply.sock &&
	    event->cookie == immediate_reply.destination.cookie &&
	    same_peer(event, &immediate_reply.destination)) {
		if (debug && error)
			warnx("immediate reply failed: %s", strerror(error));
		immediate_reply.state = IMMEDIATE_IDLE;
		return;
	}
	if (inbound.state != IN_IDLE &&
	    source_sock == inbound.sock &&
	    event->cookie == inbound.source.cookie &&
	    same_peer(event, &inbound.source)) {
		if (!error && inbound.state == IN_WAIT_COMPLETE) {
			queue_request(inbound.request);
			inbound.request = NULL;
		} else {
			free(inbound.request);
			inbound.request = NULL;
			if (debug)
				warnx("inbound Econet transaction failed: %s",
				      strerror(error ? error : EPROTO));
		}
		inbound.state = IN_IDLE;
		return;
	}
	if (source_sock != outbound.sock ||
	    event->cookie != outbound.destination.cookie ||
	    !same_peer(event, &outbound.destination) ||
	    outbound.state == OUT_IDLE)
		return;
	if (!error) {
		if (outbound.state == OUT_WAIT_COMPLETE)
			outbound.state = OUT_DONE;
		else {
			outbound.error = EPROTO;
			outbound.state = OUT_FAILED;
		}
		return;
	}
	if (outbound.state == OUT_WAIT_SCOUT_ACK && error == ETIMEDOUT &&
	    ++outbound.retries < ECONET_SCOUT_RETRIES) {
		outbound.destination.cookie = econet_next_cookie();
		outbound.state = OUT_SEND_SCOUT;
		return;
	}
	outbound.error = error;
	outbound.state = OUT_FAILED;
}

static void handle_phase(int source_sock, const struct sockaddr_ec *source,
			 ssize_t length)
{
	if ((source->type & ECTYPE_TRANSMIT_STATUS_MASK) ==
	    ECTYPE_TRANSMIT_STATUS) {
		if (length == 0)
			handle_status(source_sock, source);
		return;
	}
	if (source->type == ECTYPE_PACKET_IMMEDIATE) {
		handle_immediate(source_sock, source);
		return;
	}
	if (source->type == ECTYPE_PACKET_SCOUT) {
		if (length != 0 || inbound.state != IN_IDLE)
			return;
		inbound.sock = source_sock;
		inbound.source = *source;
		inbound.state = IN_SEND_SCOUT_ACK;
		return;
	}
	if (source->type == ECTYPE_PACKET_DATA &&
	    inbound.state == IN_WAIT_DATA &&
	    source_sock == inbound.sock &&
	    source->cookie == inbound.source.cookie &&
	    same_peer(source, &inbound.source)) {
		inbound.request = alloc_request(&inbound.source, phasebuf,
						(size_t)length);
		if (inbound.request)
			inbound.state = IN_SEND_DATA_ACK;
		return;
	}
	if (source->type == ECTYPE_PACKET_ACK &&
	    length == 0 && source_sock == outbound.sock &&
	    source->cookie == outbound.destination.cookie &&
	    same_peer(source, &outbound.destination)) {
		if (outbound.state == OUT_WAIT_SCOUT_ACK)
			outbound.state = OUT_SEND_DATA;
		else if (outbound.state == OUT_WAIT_DATA_ACK)
			outbound.state = OUT_WAIT_COMPLETE;
	}
}

static int pump_phase(bool forever)
{
	struct sockaddr_ec source;
	int source_sock;
	ssize_t length = receive_phase(&source_sock, &source, forever);

	if (length < 0)
		return -1;
	handle_phase(source_sock, &source, length);
	progress_transactions();
	return 0;
}

static struct aun_packet *
econet_recv(ssize_t *outsize, struct aun_srcaddr *from, int want_port)
{
	union internal_addr *address = (union internal_addr *)from;
	bool forever = !(address->eaddr.network || address->eaddr.station);
	time_t deadline = time(NULL) + ECONET_RECV_WATCHDOG;
	struct queued_request *request;

	for (;;) {
		request = take_request(from, want_port);
		if (request)
			break;
		progress_transactions();
		if (pump_phase(false) < 0) {
			if (errno == EINTR)
				continue;
			if (errno == ETIMEDOUT &&
			    (forever || time(NULL) < deadline))
				continue;
			if (errno == ETIMEDOUT)
				abandon_inbound("receive watchdog expired");
			return NULL;
		}
	}
	if (request->length > sizeof(rbuf) - PKTOFF) {
		free(request);
		errno = EMSGSIZE;
		return NULL;
	}
	if (request->length)
		memcpy(rbuf + PKTOFF, request->data, request->length);
	rpkt->type = AUN_TYPE_UNICAST;
	rpkt->dest_port = request->source.port;
	rpkt->flag = request->source.cb;
	rpkt->retrans = 0;
	memset(rpkt->seq, 0, sizeof(rpkt->seq));
	*outsize = request->length + PKTOFF;
	memset(address, 0, sizeof(*from));
	address->eaddr.network = request->source.addr.net;
	address->eaddr.station = request->source.addr.station;
	free(request);
	return rpkt;
}

static ssize_t
econet_xmit(struct aun_packet *packet, size_t length, struct aun_srcaddr *to)
{
	union internal_addr *address = (union internal_addr *)to;
	time_t deadline = time(NULL) + ECONET_XMIT_WATCHDOG;

	if (length < PKTOFF || length - PKTOFF > ECONET_PAYLOAD_MTU) {
		errno = EMSGSIZE;
		return -1;
	}
	if (outbound.state != OUT_IDLE && outbound.state != OUT_DONE &&
	    outbound.state != OUT_FAILED) {
		errno = EBUSY;
		return -1;
	}
	memset(&outbound, 0, sizeof(outbound));
	outbound.sock = sockets[ECONET_SOCKET_FS];
	outbound.destination.sec_family = AF_ECONET;
	outbound.destination.port = packet->dest_port;
	outbound.destination.cb = 0x80 | packet->flag;
	outbound.destination.addr.net = address->eaddr.network;
	outbound.destination.addr.station = address->eaddr.station;
	outbound.destination.cookie = econet_next_cookie();
	outbound.data = packet->data;
	outbound.length = length - PKTOFF;
	outbound.state = OUT_SEND_SCOUT;

	while (outbound.state != OUT_DONE && outbound.state != OUT_FAILED) {
		progress_transactions();
		if (pump_phase(false) < 0 && errno != ETIMEDOUT && errno != EINTR) {
			outbound.error = errno;
			outbound.state = OUT_FAILED;
		}
		if (time(NULL) >= deadline) {
			outbound.error = ETIMEDOUT;
			outbound.state = OUT_FAILED;
		}
	}
	if (outbound.state == OUT_FAILED) {
		errno = outbound.error ? outbound.error : EIO;
		outbound.state = OUT_IDLE;
		return -1;
	}
	outbound.state = OUT_IDLE;
	return (ssize_t)length;
}

static char *
econet_ntoa(struct aun_srcaddr *from)
{
	union internal_addr *address = (union internal_addr *)from;
	static char text[80];

	sprintf(text, "station %d.%d", address->eaddr.network,
		address->eaddr.station);
	return text;
}

static void
econet_get_stn(struct aun_srcaddr *from, uint8_t *out)
{
	union internal_addr *address = (union internal_addr *)from;

	out[0] = address->eaddr.station;
	out[1] = address->eaddr.network;
}

const struct aun_funcs econet = {
	ECONET_PAYLOAD_MTU,
	econet_setup,
	econet_recv,
	econet_xmit,
	econet_ntoa,
	econet_get_stn,
};

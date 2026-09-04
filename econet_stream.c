/* SOCK_STREAM AF_ECONET backend for aund. */

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "aun.h"
#include "econet_common.h"
#include "extern.h"
#include "if_ec.h"
#include "version.h"

#define ECONET_STREAM_POLL_US 100000
#define ECONET_STREAM_RECV_WATCHDOG 10
#define ECONET_DATA_PORT 0x97
#define ECONET_STREAM_BACKLOG 16

enum stream_listener_id {
	STREAM_LISTENER_FS,
	STREAM_LISTENER_DATA,
	STREAM_LISTENER_COUNT,
};

struct stream_peer {
	struct stream_peer *next;
	int sock;
	struct sockaddr_ec address;
};

enum immediate_reply_state {
	IMMEDIATE_IDLE,
	IMMEDIATE_SEND,
	IMMEDIATE_WAIT_COMPLETE,
};

static int listeners[STREAM_LISTENER_COUNT];
static int immediate_sock;
static struct stream_peer *peers;
static struct econet_record_queue requests;
static unsigned char rbuf[ECONET_RBUF_SIZE];

static struct {
	enum immediate_reply_state state;
	struct sockaddr_ec destination;
	unsigned char data[4];
} immediate_reply;

static int
set_nonblocking(int sock)
{
	int flags;

	flags = fcntl(sock, F_GETFL);
	if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
		return -1;
	return 0;
}

static int
open_listener(uint8_t port)
{
	struct sockaddr_ec local = {
		.sec_family = AF_ECONET,
		.port = port,
		/* A zero cb is a wildcard for stream listeners. */
		.cb = 0,
	};
	int sock;

	sock = socket(AF_ECONET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;
	if (bind(sock, (const struct sockaddr *)&local, sizeof(local)) < 0 ||
	    listen(sock, ECONET_STREAM_BACKLOG) < 0 ||
	    set_nonblocking(sock) < 0) {
		close(sock);
		return -1;
	}
	return sock;
}

static int
open_immediate_socket(void)
{
	struct sockaddr_ec local = {
		.sec_family = AF_ECONET,
		.port = 0,
	};
	int sock;

	sock = socket(AF_ECONET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;
	if (bind(sock, (const struct sockaddr *)&local, sizeof(local)) < 0 ||
	    set_nonblocking(sock) < 0) {
		close(sock);
		return -1;
	}
	return sock;
}

static void
econet_stream_setup(void)
{
	static const uint8_t ports[STREAM_LISTENER_COUNT] = {
		[STREAM_LISTENER_FS] = EC_PORT_FS,
		[STREAM_LISTENER_DATA] = ECONET_DATA_PORT,
	};
	int i;

	for (i = 0; i < STREAM_LISTENER_COUNT; i++) {
		listeners[i] = open_listener(ports[i]);
		if (listeners[i] < 0)
			err(1, "AF_ECONET stream listener for port 0x%02x",
			    ports[i]);
	}
	immediate_sock = open_immediate_socket();
	if (immediate_sock < 0)
		err(1, "AF_ECONET immediate socket");
}

static int
status_errno(uint8_t type)
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

static bool
same_peer(const struct sockaddr_ec *a, const struct sockaddr_ec *b)
{
	return a->addr.net == b->addr.net &&
	    a->addr.station == b->addr.station;
}

static void
progress_immediate_reply(void)
{
	ssize_t sent;

	if (immediate_reply.state != IMMEDIATE_SEND)
		return;
	sent = sendto(immediate_sock, immediate_reply.data,
	    sizeof(immediate_reply.data), 0,
	    (const struct sockaddr *)&immediate_reply.destination,
	    sizeof(immediate_reply.destination));
	if (sent == (ssize_t)sizeof(immediate_reply.data)) {
		immediate_reply.state = IMMEDIATE_WAIT_COMPLETE;
	} else if (sent < 0 &&
	    (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) {
		return;
	} else {
		if (debug)
			warn("immediate reply");
		immediate_reply.state = IMMEDIATE_IDLE;
	}
}

static void
handle_immediate(const struct sockaddr_ec *source)
{
	if (source->cb != 0x88 ||
	    immediate_reply.state != IMMEDIATE_IDLE)
		return;
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

static void
handle_immediate_event(const struct sockaddr_ec *source, ssize_t length)
{
	if (source->type == ECTYPE_PACKET_IMMEDIATE) {
		handle_immediate(source);
		return;
	}
	if (length != 0 ||
	    (source->type & ECTYPE_TRANSMIT_STATUS_MASK) !=
	    ECTYPE_TRANSMIT_STATUS ||
	    immediate_reply.state == IMMEDIATE_IDLE ||
	    source->cookie != immediate_reply.destination.cookie ||
	    !same_peer(source, &immediate_reply.destination))
		return;
	if (debug && status_errno(source->type))
		warnx("immediate reply failed: %s",
		    strerror(status_errno(source->type)));
	immediate_reply.state = IMMEDIATE_IDLE;
}

static void
receive_immediate(void)
{
	unsigned char data[16];
	struct sockaddr_ec source;
	socklen_t source_length = sizeof(source);
	ssize_t length;

	length = recvfrom(immediate_sock, data, sizeof(data), 0,
	    (struct sockaddr *)&source, &source_length);
	if (length >= 0)
		handle_immediate_event(&source, length);
}

static void
accept_peer(int listener)
{
	struct stream_peer *peer;
	socklen_t address_length;
	int sock;

	for (;;) {
		peer = calloc(1, sizeof(*peer));
		if (!peer)
			err(1, "stream peer");
		address_length = sizeof(peer->address);
		sock = accept(listener, (struct sockaddr *)&peer->address,
		    &address_length);
		if (sock < 0) {
			free(peer);
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return;
			if (errno == EINTR)
				continue;
			warn("accept AF_ECONET stream");
			return;
		}
		if (set_nonblocking(sock) < 0) {
			warn("AF_ECONET stream nonblocking");
			close(sock);
			free(peer);
			continue;
		}
		peer->sock = sock;
		peer->next = peers;
		peers = peer;
		if (debug)
			printf("accepted stream from station %u.%u\n",
			    peer->address.addr.net,
			    peer->address.addr.station);
	}
}

static void
receive_record(struct stream_peer *peer)
{
	unsigned char data[ECONET_PAYLOAD_MTU];
	unsigned char control[CMSG_SPACE(ECONET_SCOUT_MAX)];
	struct sockaddr_ec source;
	struct iovec iov = {
		.iov_base = data,
		.iov_len = sizeof(data),
	};
	struct msghdr message = {
		.msg_name = &source,
		.msg_namelen = sizeof(source),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg;
	struct econet_record *record;
	size_t scout_length = 0;
	ssize_t length;

	length = recvmsg(peer->sock, &message, 0);
	if (length < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			warn("receive AF_ECONET stream");
		return;
	}
	if ((message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) ||
	    !(message.msg_flags & MSG_EOR)) {
		if (debug)
			warnx("discarding truncated AF_ECONET stream record");
		return;
	}
	for (cmsg = CMSG_FIRSTHDR(&message); cmsg;
	    cmsg = CMSG_NXTHDR(&message, cmsg)) {
		if (cmsg->cmsg_level == SOL_ECONET &&
		    cmsg->cmsg_type == ECONET_CMSG_SCOUT &&
		    cmsg->cmsg_len >= CMSG_LEN(0)) {
			scout_length = cmsg->cmsg_len - CMSG_LEN(0);
			break;
		}
	}
	if (scout_length != 0) {
		if (debug)
			warnx("discarding AF_ECONET record with %zu scout bytes",
			    scout_length);
		return;
	}
	record = econet_record_alloc(&source, data, (size_t)length);
	if (!record) {
		warn("queue AF_ECONET stream record");
		return;
	}
	econet_record_queue(&requests, record);
}

static int
pump_stream(bool forever)
{
	struct timeval timeout = {
		.tv_sec = 0,
		.tv_usec = ECONET_STREAM_POLL_US,
	};
	struct stream_peer *peer;
	struct timeval *select_timeout;
	fd_set readfds;
	int max_sock = immediate_sock;
	int ready;
	int i;

	progress_immediate_reply();
	FD_ZERO(&readfds);
	FD_SET(immediate_sock, &readfds);
	for (i = 0; i < STREAM_LISTENER_COUNT; i++) {
		FD_SET(listeners[i], &readfds);
		if (listeners[i] > max_sock)
			max_sock = listeners[i];
	}
	for (peer = peers; peer; peer = peer->next) {
		FD_SET(peer->sock, &readfds);
		if (peer->sock > max_sock)
			max_sock = peer->sock;
	}
	select_timeout = !forever || immediate_reply.state == IMMEDIATE_SEND ?
	    &timeout : NULL;
	ready = select(max_sock + 1, &readfds, NULL, NULL, select_timeout);
	if (ready <= 0) {
		if (ready == 0 && !forever)
			errno = ETIMEDOUT;
		return ready;
	}
	if (FD_ISSET(immediate_sock, &readfds))
		receive_immediate();
	for (i = 0; i < STREAM_LISTENER_COUNT; i++) {
		if (FD_ISSET(listeners[i], &readfds))
			accept_peer(listeners[i]);
	}
	for (peer = peers; peer; peer = peer->next) {
		if (FD_ISSET(peer->sock, &readfds))
			receive_record(peer);
	}
	return 1;
}

static struct aun_packet *
econet_stream_recv(ssize_t *outsize, struct aun_srcaddr *from, int want_port)
{
	struct econet_record *record;
	struct aun_packet *packet;
	bool forever = !from->bytes[0] && !from->bytes[1];
	time_t deadline = time(NULL) + ECONET_STREAM_RECV_WATCHDOG;
	int result;

	for (;;) {
		record = econet_record_take(&requests, from, want_port);
		if (record)
			break;
		result = pump_stream(forever);
		if (result < 0 && errno != EINTR)
			return NULL;
		if (!forever && time(NULL) >= deadline) {
			errno = ETIMEDOUT;
			return NULL;
		}
	}
	packet = econet_record_to_aun(record, rbuf, sizeof(rbuf), outsize,
	    from);
	free(record);
	return packet;
}

static ssize_t
econet_stream_xmit(struct aun_packet *packet, size_t length,
	struct aun_srcaddr *to)
{
	struct sockaddr_ec destination;
	const void *data;
	size_t data_length;
	ssize_t sent;
	int sock;

	if (econet_prepare_xmit(packet, length, to, &destination, &data,
	    &data_length) < 0)
		return -1;
	sock = socket(AF_ECONET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;
	if (connect(sock, (const struct sockaddr *)&destination,
	    sizeof(destination)) < 0) {
		close(sock);
		return -1;
	}
	sent = send(sock, data, data_length, 0);
	close(sock);
	if (sent < 0)
		return -1;
	if (sent != (ssize_t)data_length) {
		errno = EIO;
		return -1;
	}
	return (ssize_t)length;
}

const struct aun_funcs econet_stream = {
	ECONET_PAYLOAD_MTU,
	econet_stream_setup,
	econet_stream_recv,
	econet_stream_xmit,
	econet_ntoa_common,
	econet_get_stn_common,
};

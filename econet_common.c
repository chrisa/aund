/* Common AF_ECONET translation and queueing for aund backends. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "extern.h"
#include "econet_common.h"

struct econet_addr {
	uint8_t station;
	uint8_t network;
};

union internal_addr {
	struct aun_srcaddr srcaddr;
	struct econet_addr eaddr;
};

struct econet_record *
econet_record_alloc(const struct sockaddr_ec *source, const void *data,
	size_t length)
{
	struct econet_record *record;

	record = malloc(sizeof(*record) + length);
	if (!record)
		return NULL;
	record->next = NULL;
	record->source = *source;
	record->length = length;
	if (length)
		memcpy(record->data, data, length);
	return record;
}

void
econet_record_queue(struct econet_record_queue *queue,
	struct econet_record *record)
{
	if (queue->tail)
		queue->tail->next = record;
	else
		queue->head = record;
	queue->tail = record;
}

static int
record_matches(const struct econet_record *record,
	const struct aun_srcaddr *from, int want_port)
{
	const union internal_addr *address =
		(const union internal_addr *)from;

	if ((address->eaddr.network || address->eaddr.station) &&
	    (address->eaddr.network != record->source.addr.net ||
	     address->eaddr.station != record->source.addr.station))
		return 0;
	return !want_port || want_port == record->source.port;
}

struct econet_record *
econet_record_take(struct econet_record_queue *queue,
	const struct aun_srcaddr *from, int want_port)
{
	struct econet_record *previous = NULL;
	struct econet_record *record = queue->head;

	while (record && !record_matches(record, from, want_port)) {
		previous = record;
		record = record->next;
	}
	if (!record)
		return NULL;
	if (previous)
		previous->next = record->next;
	else
		queue->head = record->next;
	if (queue->tail == record)
		queue->tail = previous;
	record->next = NULL;
	return record;
}

struct aun_packet *
econet_record_to_aun(struct econet_record *record, unsigned char *buffer,
	size_t buffer_size, ssize_t *outsize, struct aun_srcaddr *from)
{
	union internal_addr *address = (union internal_addr *)from;
	struct aun_packet *packet = (struct aun_packet *)buffer;

	if (record->length > buffer_size - ECONET_PKTOFF) {
		errno = EMSGSIZE;
		return NULL;
	}
	if (record->length)
		memcpy(buffer + ECONET_PKTOFF, record->data, record->length);
	packet->type = AUN_TYPE_UNICAST;
	packet->dest_port = record->source.port;
	packet->flag = record->source.cb;
	packet->retrans = 0;
	memset(packet->seq, 0, sizeof(packet->seq));
	*outsize = (ssize_t)(record->length + ECONET_PKTOFF);
	memset(address, 0, sizeof(*from));
	address->eaddr.network = record->source.addr.net;
	address->eaddr.station = record->source.addr.station;
	return packet;
}

int
econet_prepare_xmit(const struct aun_packet *packet, size_t length,
	const struct aun_srcaddr *to, struct sockaddr_ec *destination,
	const void **data, size_t *data_length)
{
	const union internal_addr *address =
		(const union internal_addr *)to;

	if (length < ECONET_PKTOFF ||
	    length - ECONET_PKTOFF > ECONET_PAYLOAD_MTU) {
		errno = EMSGSIZE;
		return -1;
	}
	memset(destination, 0, sizeof(*destination));
	destination->sec_family = AF_ECONET;
	destination->port = packet->dest_port;
	destination->cb = 0x80 | packet->flag;
	destination->addr.net = address->eaddr.network;
	destination->addr.station = address->eaddr.station;
	*data = packet->data;
	*data_length = length - ECONET_PKTOFF;
	return 0;
}

char *
econet_ntoa_common(struct aun_srcaddr *from)
{
	union internal_addr *address = (union internal_addr *)from;
	static char text[80];

	sprintf(text, "station %d.%d", address->eaddr.network,
	    address->eaddr.station);
	return text;
}

void
econet_get_stn_common(struct aun_srcaddr *from, uint8_t *out)
{
	union internal_addr *address = (union internal_addr *)from;

	out[0] = address->eaddr.station;
	out[1] = address->eaddr.network;
}

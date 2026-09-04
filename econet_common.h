#ifndef AUND_ECONET_COMMON_H
#define AUND_ECONET_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "aun.h"
#include "if_ec.h"

struct aun_srcaddr;

#define ECONET_RBUF_SIZE 65536
#define ECONET_PKTOFF offsetof(struct aun_packet, data)

struct econet_record {
	struct econet_record *next;
	struct sockaddr_ec source;
	size_t length;
	unsigned char data[];
};

struct econet_record_queue {
	struct econet_record *head;
	struct econet_record *tail;
};

struct econet_record *econet_record_alloc(const struct sockaddr_ec *source,
	const void *data, size_t length);
void econet_record_queue(struct econet_record_queue *queue,
	struct econet_record *record);
struct econet_record *econet_record_take(struct econet_record_queue *queue,
	const struct aun_srcaddr *from, int want_port);
struct aun_packet *econet_record_to_aun(struct econet_record *record,
	unsigned char *buffer, size_t buffer_size, ssize_t *outsize,
	struct aun_srcaddr *from);
int econet_prepare_xmit(const struct aun_packet *packet, size_t length,
	const struct aun_srcaddr *to, struct sockaddr_ec *destination,
	const void **data, size_t *data_length);
char *econet_ntoa_common(struct aun_srcaddr *from);
void econet_get_stn_common(struct aun_srcaddr *from, uint8_t *out);

#endif

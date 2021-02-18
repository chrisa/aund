/*-
 * Copyright (c) 2010 Simon Tatham
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
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Implementation of AF_ECONET for aund.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include "aun.h"
#include "extern.h"
#include "fileserver.h"
#include "version.h"
#include "if_ec.h"

struct econet_addr {
	uint8_t station;
	uint8_t network;
};

static int sock;
static unsigned char sbuf[65536];
static unsigned char rbuf[65536];
static struct aun_packet *const rpkt = (struct aun_packet *)rbuf;

/* Offset of packet payload in struct aun_packet:
 * size of AUN header minus size of Econet header. */
#define PKTOFF (offsetof(struct aun_packet, data) - 4)

union internal_addr {
	struct aun_srcaddr srcaddr;
	struct econet_addr eaddr;
};

static void econet_setup(void)
{
	//struct sockaddr_ec name;
        int fl;

	/*
	 * Set up our Econet socket.
	 */
	sock = socket(AF_ECONET, SOCK_DGRAM, 0);
	if (sock < 0)
		err(1, "socket");

        // todo what is AF_ECONET for INADDR_ANY?
	//memset(&name, 0, sizeof(name));
        //name.addr.station = our_econet_addr & 0xff;
	//name.addr.net = our_econet_addr >> 8;
	//if (bind(sock, (struct sockaddr*)&name, sizeof(name)))
	//	err(1, "bind");

	if ((fl = fcntl(sock, F_GETFL)) < 0)
		err(1, "fcntl(F_GETFL)");
        if (fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0)
		err(1, "fcntl(F_SETFL)");
}

static ssize_t econet_listen(struct econet_addr *addr, int forever)
{
	ssize_t msgsize;
	struct sockaddr_ec from;
	fd_set r;
	struct timeval timeout;

	while (1) {
		socklen_t fromlen = sizeof(from);
		int i;

		/*
		 * We set the socket to nonblocking mode, and must
		 * therefore always select before we recvfrom. The
		 * timeout varies depending on 'forever'.
		 */
		FD_ZERO(&r);
		FD_SET(sock, &r);
		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;   /* 100ms */
		i = select(sock+1, &r, NULL, NULL, forever ? NULL : &timeout);
		if (i == 0)
			return 0;      /* nothing turned up */

		msgsize = recvfrom(sock, rbuf + PKTOFF,
				   sizeof(rbuf) - PKTOFF,
				   0, (struct sockaddr *)&from, &fromlen);
		if (msgsize == -1)
			err(1, "recvfrom");

		/* Is it for us? */
		//if (256 * rbuf[PKTOFF+1] + rbuf[PKTOFF] != our_econet_addr)
		//	continue;

		/* Who's it from? */

                addr->station = from.addr.station;
                addr->network = from.addr.net;

                if (debug)
                        printf("listen: received from %d.%d\n",
                               addr->network, addr->station);

		return msgsize;
	}
}

static void econet_send(struct econet_addr *to, const void *data, ssize_t len)
{
	struct sockaddr_ec name;

	memset(&name, 0, sizeof(name));
        name.addr.station = to->station;
        name.addr.net = to->network;

        if (sendto(sock, data, len, 0,
                   (struct sockaddr*)&name, sizeof(name)) < 0)
                err(1, "sendto");
}

static struct aun_packet *
econet_recv(ssize_t *outsize, struct aun_srcaddr *vfrom, int want_port)
{
	ssize_t msgsize;
	union internal_addr *afrom = (union internal_addr *)vfrom;
	int ctlbyte, destport;
	int count, forever;
	unsigned char ack[4];
        struct econet_addr scoutaddr;
        struct econet_addr mainaddr;

	/*
	 * If we're told to listen for a packet from a particular
	 * station, impose a time limit after which we'll give up on
	 * it, so that a client that goes away in the middle of a
	 * load or save doesn't lock everyone else out indefinitely.
	 */
	count = 50;
	forever = !(afrom->eaddr.network || afrom->eaddr.station);
	while (count > 0) {
		/*
		 * Listen for a scout packet. This should be 6 bytes
		 * long, and the second payload byte should indicate
		 * the destination port.
		 */
		msgsize = econet_listen(&scoutaddr, forever);

		if (msgsize == 0) {
			count--;
			continue;
		}

		if (rbuf[PKTOFF+5] == 0) {
			/*
			 * Port 0 means an immediate operation. We
			 * only support Machine Type Peek.
			 */
			if (rbuf[PKTOFF+4] == 0x88) {
				ack[0] = AUND_MACHINE_PEEK_LO;
				ack[1] = AUND_MACHINE_PEEK_HI;
				ack[2] = AUND_VERSION_MINOR;
				ack[3] = AUND_VERSION_MAJOR;
			}
			econet_send(&scoutaddr, ack, 4);
			continue;
		}

		/*
		 * If we've been told to listen for a particular
		 * source address and/or port, loop round again
		 * without ACK if we didn't get it.
		 */
		if (((afrom->eaddr.network || afrom->eaddr.station) &&
		     (afrom->eaddr.network != scoutaddr.network ||
		      afrom->eaddr.station != scoutaddr.station)) ||
		    (want_port && want_port != rbuf[PKTOFF+5])) {
			if (debug)
				printf("ignoring packet from %d.%d for port"
				       " %d during other transaction\n",
				       scoutaddr.network, scoutaddr.station,
				       rbuf[PKTOFF+5]);
			if (!forever) count--;
			continue;
		}

		if (msgsize != 6) {
			if (debug)
				printf("received wrong-size scout packet "
				    "(%zd) from %d.%d\n",
				    msgsize, scoutaddr.network, scoutaddr.station);
			if (!forever) count--;
			continue;
		}

		ctlbyte = rbuf[PKTOFF+4];
		destport = rbuf[PKTOFF+5];

		/*
		 * Send an ACK, repeatedly if necessary, and wait
		 * for the main packet, which should come
		 * from the same address.
		 *
		 * (This is painfully single-threaded, but I'm
		 * currently working on the assumption that it's an
		 * accurate reflection of the way a real Econet
		 * four-way handshake would tie up the bus for all
		 * other stations until it had finished.)
		 */
		count = 50;
		do {
			econet_send(&scoutaddr, ack, 0);
			msgsize = econet_listen(&mainaddr, 0);
			if (msgsize != 0) {
				if (mainaddr.network != scoutaddr.network ||
                                        mainaddr.station != scoutaddr.station) {
					if (debug)
						printf("ignoring packet from"
						       " %d.%d during other"
						       " transaction\n",
						       mainaddr.network,
						       mainaddr.station);
					msgsize = 0;   /* go round again */
				}
			}
			count--;
		} while (count > 0 && msgsize == 0);

		if (msgsize == 0) {
			if (debug)
				printf("received scout from %d.%d but "
				       "payload packet never arrived\n",
				       scoutaddr.network, scoutaddr.station);
			continue;
		}

		/*
		 * ACK that too. (We can reuse the ACK we
		 * constructed above.)
		 */
		econet_send(&scoutaddr, ack, 0);

		/*
		 * Now fake up an aun_packet structure to return.
		 */
		rpkt->type = AUN_TYPE_UNICAST;   /* shouldn't matter */
		rpkt->dest_port = destport;
		rpkt->flag = ctlbyte;
		rpkt->retrans = 0;
		memset(rpkt->seq, 0, 4);
		*outsize = msgsize + PKTOFF;
		memset(afrom, 0, sizeof(struct aun_srcaddr));
		afrom->eaddr.network = scoutaddr.network;
		afrom->eaddr.station = scoutaddr.station;
		return rpkt;
	}

	errno = ETIMEDOUT;
	return NULL;
}

static ssize_t
econet_xmit(struct aun_packet *spkt, size_t len, struct aun_srcaddr *vto)
{
	union internal_addr *ato = (union internal_addr *)vto;
	int count;
	ssize_t msgsize, payloadlen;
        struct econet_addr ackaddr;

	if (len > sizeof(sbuf) - 4) {
		if (debug)
			printf("outgoing packet too large (%zu)\n", len);
		return -1;
	}

	/*
	 * Send the scout packet, and wait for an ACK.
	 */
	sbuf[0] = 0x80 | spkt->flag;
	sbuf[1] = spkt->dest_port;
	count = 50;
	do {
		econet_send(&ato->eaddr, sbuf, 2);
		msgsize = econet_listen(&ackaddr, 0);
		if (msgsize > 0) {
			/*
			 * We expect the ACK to have come from the
			 * right address.
			 */
			if (ackaddr.network != ato->eaddr.network ||
                                ackaddr.station != ato->eaddr.station) {
				if (debug)
					printf("ignoring packet from %d.%d"
					       " during other transaction\n",
					       ackaddr.network, ackaddr.station);
				msgsize = 0;   /* so we'll go round again */
			}
		}
		count--;
	} while (count > 0 && msgsize == 0);

	if (msgsize == 0) {
		if (debug)
			printf("scout ack never arrived from "
			    "%d.%d\n", ato->eaddr.network, ato->eaddr.station);
		errno = ETIMEDOUT;
		return -1;
	}

	if (msgsize != 4) {
		if (debug)
			printf("received wrong-size ack packet (%zd) from "
			    "%d.%d\n",
			    msgsize, ato->eaddr.network, ato->eaddr.station);
		return -1;
	}

	/*
	 * Construct and send the payload packet, and wait for an
	 * ACK.
	 */
	payloadlen = len - offsetof(struct aun_packet, data);
	memcpy(sbuf, spkt->data, payloadlen);
	count = 50;
	do {
		econet_send(&ato->eaddr, sbuf, payloadlen);
		msgsize = econet_listen(&ackaddr, 0);
		if (msgsize > 0) {
			/*
			 * The second ACK, just as above, should
			 * have come from the right address.
			 */
			if (ackaddr.network != ato->eaddr.network ||
                                ackaddr.station != ato->eaddr.station) {
				if (debug)
					printf("ignoring packet from %d.%d"
					       " during other transaction\n",
					       ackaddr.network, ackaddr.station);
				msgsize = 0;   /* so we'll go round again */
			}
		}
		count--;
	} while (count > 0 && msgsize == 0);

	if (msgsize == 0) {
		if (debug)
			printf("payload ack never arrived from "
			    "%d.%d\n", ato->eaddr.network, ato->eaddr.station);
		errno = ETIMEDOUT;
		return -1;
	}

	if (msgsize != 4) {
		if (debug)
			printf("received wrong-size ack packet (%zd) "
			    "from %d.%d\n",
			    msgsize, ato->eaddr.network, ato->eaddr.station);
		return -1;
	}

	return len;
}

static char *
econet_ntoa(struct aun_srcaddr *vfrom)
{
	union internal_addr *afrom = (union internal_addr *)vfrom;
	static char retbuf[80];
	sprintf(retbuf, "station %d.%d", afrom->eaddr.network,
		afrom->eaddr.station);
	return retbuf;
}

static void
econet_get_stn(struct aun_srcaddr *vfrom, uint8_t *out)
{
	union internal_addr *afrom = (union internal_addr *)vfrom;
	out[0] = afrom->eaddr.station;
	out[1] = afrom->eaddr.network;
}

const struct aun_funcs econet = {
	512,
	econet_setup,
	econet_recv,
        econet_xmit,
        econet_ntoa,
        econet_get_stn,
};

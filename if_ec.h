/* Definitions for Econet sockets. */

#ifndef __LINUX_IF_EC
#define __LINUX_IF_EC

/* User visible stuff. Glibc provides its own but libc5 folk will use these */

struct ec_addr {
  unsigned char station;		/* Station number.  */
  unsigned char net;			/* Network number.  */
};

struct sockaddr_ec {
  unsigned short sec_family;
  unsigned char port;			/* Port number.  */
  unsigned char cb;			/* Control/flag byte.  */
  unsigned char type;			/* Type of message.  */
  struct ec_addr addr;
  unsigned long cookie;
};

#define ECTYPE_PACKET_SCOUT             1
#define ECTYPE_PACKET_DATA              2
#define ECTYPE_PACKET_ACK               3
#define ECTYPE_PACKET_BROADCAST         4
#define ECTYPE_PACKET_IMMEDIATE         5
#define ECTYPE_PACKET_IMMEDIATE_REPLY   6

#define ECTYPE_TRANSMIT_STATUS          0x10
#define ECTYPE_TRANSMIT_STATUS_MASK     0xf0
#define ECTYPE_TRANSMIT_RESULT_MASK     0x0f

#define EC_STATUS_OK                    0
#define EC_STATUS_BAD_STATE             1
#define EC_STATUS_BAD_TOKEN             2
#define EC_STATUS_QUEUE_FULL            3
#define EC_STATUS_BAD_LENGTH            4
#define EC_STATUS_ABORTED               5
#define EC_STATUS_TIMEOUT               6
#define EC_STATUS_LOCAL_ERROR           7
#define EC_STATUS_DEVICE_DOWN           8

#ifndef SOL_ECONET
#define SOL_ECONET AF_ECONET
#endif

#define ECONET_CMSG_SCOUT 1
#define ECONET_SO_PEER_SERVICE 1
#define ECONET_PAYLOAD_MTU 32768
#define ECONET_SCOUT_MAX 1024

struct econet_service {
  unsigned char port;
  unsigned char cb;
};

#ifdef __KERNEL__

#define EC_HLEN				6

/* This is what an Econet frame looks like on the wire. */
struct ec_framehdr {
  unsigned char dst_stn;
  unsigned char dst_net;
  unsigned char src_stn;
  unsigned char src_net;
  unsigned char cb;
  unsigned char port;
};

struct econet_sock {
  /* struct sock has to be the first member of econet_sock */
  struct sock	sk;
  unsigned char cb;
  unsigned char port;
  unsigned char station;
  unsigned char net;
  unsigned short num;
};

static inline struct econet_sock *ec_sk(const struct sock *sk)
{
	return (struct econet_sock *)sk;
}

struct ec_device {
  unsigned char station, net;		/* Econet protocol address */
};

#endif

#endif

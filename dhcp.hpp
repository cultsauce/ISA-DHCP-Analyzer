#ifndef DHCP_H
#define DHCP_H 1

#include <string>
#include <syslog.h>
#include <iostream>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>   
#include <unistd.h>
#include <vector>
#include <math.h>
#include <time.h>
#include <pcap.h>
#include <ncurses.h>

#define MAX_DHCP_CHADDR_LENGTH           16
#define MAX_DHCP_SNAME_LENGTH            64
#define MAX_DHCP_FILE_LENGTH             128
#define MAX_DHCP_OPTIONS_LENGTH          312

#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK         5
#define DHCPNACK        6
#define DHCPRELEASE     7

#define DHCP_OPTION_MESSAGE_TYPE        53
#define DHCP_OPTION_HOST_NAME           12
#define DHCP_OPTION_BROADCAST_ADDRESS   28
#define DHCP_OPTION_REQUESTED_ADDRESS   50
#define DHCP_OPTION_LEASE_TIME          51
#define DHCP_OPTION_RENEWAL_TIME        58
#define DHCP_OPTION_REBINDING_TIME      59
#define DHCP_OPTION_END                 255

typedef enum {
    DHCP_DISCOVER,
    DHCP_OFFER,
    DHCP_REQUEST,
    DHCP_NAK,
    DHCP_DECLINE,
    DHCP_ACK,
    DHCP_RELEASE,
    DHCP_INFORM
} dhcp_message_type;

typedef struct dhcp_packet_struct{
        uint8_t  op;                   /* packet type */
        uint8_t  htype;                /* type of hardware address for this machine (Ethernet, etc) */
        uint8_t  hlen;                 /* length of hardware address (of this machine) */
        uint8_t  hops;                 /* hops */
        uint32_t xid;                  /* random transaction id number - chosen by this machine */
        uint16_t secs;                 /* seconds used in timing */
        uint16_t flags;                /* flags */
        struct in_addr ciaddr;          /* IP address of this machine (if we already have one) */
        struct in_addr yiaddr;          /* IP address of this machine (offered by the DHCP server) */
        struct in_addr siaddr;          /* IP address of DHCP server */
        struct in_addr giaddr;          /* IP address of DHCP relay */
        uint8_t chaddr [MAX_DHCP_CHADDR_LENGTH];      /* hardware address of this machine */
        uint8_t sname [MAX_DHCP_SNAME_LENGTH];    /* name of DHCP server */
        uint8_t file [MAX_DHCP_FILE_LENGTH];      /* boot file name (used for diskless booting?) */
        uint32_t dhcp_cookie;            /* differentiated from BOOTP packet */
	    uint8_t options [MAX_DHCP_OPTIONS_LENGTH];  /* options */
    } dhcp_packet;

uint8_t get_dhcp_message_type (const dhcp_packet *packet);
time_t get_dhcp_lease_time (const dhcp_packet *packet);

bool get_dhcp_option (const dhcp_packet *packet, const uint8_t option_identifier, uint8_t *length, uint8_t * buffer);

#endif // DHCP_H
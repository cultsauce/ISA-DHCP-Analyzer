#ifndef DHCP_H
#define DHCP_H 1

#include <iostream>
#include <netinet/ip.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_DHCP_CHADDR_LENGTH 16
#define MAX_DHCP_SNAME_LENGTH 64
#define MAX_DHCP_FILE_LENGTH 128
#define MAX_DHCP_OPTIONS_LENGTH 312

#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNACK 6
#define DHCPRELEASE 7

#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_HOST_NAME 12
#define DHCP_OPTION_BROADCAST_ADDRESS 28
#define DHCP_OPTION_REQUESTED_ADDRESS 50
#define DHCP_OPTION_LEASE_TIME 51
#define DHCP_OPTION_RENEWAL_TIME 58
#define DHCP_OPTION_REBINDING_TIME 59
#define DHCP_OPTION_END 255

typedef struct dhcp_packet_struct {
    uint8_t op;                               /* packet type */
    uint8_t htype;                            /* HW type (Etherne, etc) */
    uint8_t hlen;                             /* HW address length */
    uint8_t hops;                             /* hops */
    uint32_t xid;                             /* transaction ID */
    uint16_t secs;                            /* seconds since start */
    uint16_t flags;                           /* flags */
    struct in_addr ciaddr;                    /* client address */
    struct in_addr yiaddr;                    /* offered IP address */
    struct in_addr siaddr;                    /* IP address of DHCP server */
    struct in_addr giaddr;                    /* IP address of DHCP relay */
    uint8_t chaddr[MAX_DHCP_CHADDR_LENGTH];   /* hardware address of this machine */
    uint8_t sname[MAX_DHCP_SNAME_LENGTH];     /* name of DHCP server */
    uint8_t file[MAX_DHCP_FILE_LENGTH];       /* boot file name */
    uint32_t dhcp_cookie;                     /* differentiate from BOOTP packet */
    uint8_t options[MAX_DHCP_OPTIONS_LENGTH]; /* options */
} dhcp_packet;

uint8_t get_dhcp_message_type(const dhcp_packet *packet);

#endif // DHCP_H
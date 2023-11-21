/*
** file: dhcp.hpp
** desc: dhcp packet structure and helper functions
** author : xkubin27 (Tereza Kubincova)
*/

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

#define DHCPACK 5

#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_SERVER_ADDRESS 54
#define DHCP_OPTION_DNS_ADDRESS 53
#define DHCP_OPTION_ROUTER_ADDRESS 3
#define DHCP_OPTION_END 255

/* structure of a DHCP packet */
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

/* extract dhcp option from options field */
uint8_t *get_dhcp_option(uint8_t *buff, uint8_t option_id);
/* get dhcp message type option */
uint8_t get_dhcp_message_type(const dhcp_packet *packet);
/* get dhcp server address */
in_addr get_dhcp_server_address(const dhcp_packet *packet);
/* get dns server address */
uint32_t get_dhcp_dns_address(const dhcp_packet *packet);
/* get router address */
uint32_t get_dhcp_router_address(const dhcp_packet *packet);

#endif // DHCP_H
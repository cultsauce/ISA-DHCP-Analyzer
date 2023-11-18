#ifndef SUBNET_H
#define SUBNET_H

#include <arpa/inet.h>
#include <iostream>
#include <math.h>
#include <ncurses.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

/* class for keeping information about one subnet whose statistics we are generating */
class Subnet {
public:
    const char *name;
    struct in_addr net_addr; /* network address of subnet */
    uint32_t max_alloc;      /* maximum addresses on subnet */
    uint32_t allocated;      /* number of allocated addresses on subnet */
    uint8_t prefix;          /* prefix of subnet */
    bool exceeded_half;      /* flag of whether the prefix exceeded 50% of allocations threshold */

    /* class constructor */
    Subnet(const char *addr, uint32_t alloc_addr, bool &err);
    /* calculate utilization percentage */
    double get_percentage();
    /* check if given subnet contains the supplied ip_addr */
    bool contains(const in_addr *ip_addr);

private:
    /* calculate maximum addresses on subnet */
    uint32_t get_max_addr_count();
};

#endif // SUBNET_H
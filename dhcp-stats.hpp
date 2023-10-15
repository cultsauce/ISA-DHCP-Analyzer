#ifndef DHCP_STAT
#define DHCP_STAT

#include <arpa/inet.h>
#include <math.h>
#include <ncurses.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <vector>

#include "dhcp.hpp"

class Subnet {
public:
    const char *name;
    struct in_addr net_addr;
    uint32_t max_alloc;
    uint32_t allocated;
    uint8_t prefix;

    Subnet(const char *addr, uint32_t alloc_addr);
    double get_percentage();
    bool contains(const in_addr *ip_addr);

private:
    uint32_t get_max_addr_count();
};

class DHCPAnalyzer {
public:
    char *interface_name;
    char *filename;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    std::vector<Subnet> subnet_stats;
    std::vector<in_addr_t> addrs;

    DHCPAnalyzer();
    bool initialize(const char *filename, const char *interface,
                    std::vector<const char *> prefixes);
    int next();
    bool quit(bool ret_stat);

private:
    struct bpf_program filter;
    const u_char *strip_payload(const u_char *packet);
    void interpret_dhcp_packet(const dhcp_packet *packet);
    void update_subnet_stats(const in_addr *addr, bool add);
};

#endif // DHCP_STAT
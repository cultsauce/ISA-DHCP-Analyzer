/*
** file: dhcp-stats.hpp
** desc: DHCPAnalyzer class definition
** author : xkubin27 (Tereza Kubincova)
*/

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

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "dhcp.hpp"
#include "subnet.hpp"

/* DHCP Analyzer class definition */
class DHCPAnalyzer {
public:
    char *interface_name;             /* name of the interface to listen on, if given */
    char *filename;                   /* name of pcap file, if given */
    char errbuf[PCAP_ERRBUF_SIZE];    /* buffer to store error messages */
    pcap_t *handle;                   /* handle to pcap stream */
    std::vector<Subnet> subnet_stats; /* storage of statistical info about subnets */
    std::vector<in_addr_t> addrs;     /* vector of prefix addresses to take statistics for */

    /* class constructor */
    DHCPAnalyzer();
    /* initialize analyzer class with needed parameters */
    bool initialize(const char *filename, const char *interface,
                    std::vector<const char *> prefixes);
    /* analyze next packet from stream */
    int next();
    /* quit analyzer */
    bool quit(bool ret_stat);

private:
    /* strip dhcp message of Eth, IP and UDP headers */
    const u_char *strip_payload(const u_char *packet);
    /* analyze fetched packet */
    void interpret_dhcp_message(const dhcp_packet *packet);
    /* update statistical information */
    void update_subnet_stats(const in_addr *addr);
};

#endif // DHCP_STAT
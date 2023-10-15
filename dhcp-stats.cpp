#include "dhcp-stats.hpp"

DHCPAnalyzer::DHCPAnalyzer() {
}

bool DHCPAnalyzer::quit(bool ret_stat) {
    pcap_close(handle);
    pcap_freecode(&filter);
    return ret_stat;
}

bool DHCPAnalyzer::initialize(const char *filename, const char *interface, std::vector<const char *> prefixes) {

    /* read directly from interface */
    if (filename == NULL && interface != NULL) {
        if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
            /* failed to open device */
            perror("could not open device");
            return quit(EXIT_FAILURE);
        }
    }
    /* read from pcap file */
    else if (filename != NULL && interface == NULL) {
        if ((handle = pcap_open_offline(filename, errbuf)) == NULL) {
            /* failed to read from pcap file */
            perror("could not read from file");
            return quit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < prefixes.size(); i++) {
        subnet_stats.push_back(Subnet(prefixes[i], 0));
    }

    /* compile stream filter */
    if (pcap_compile(handle, &filter, "udp port 67 or udp port 68", PCAP_OPENFLAG_PROMISCUOUS, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
        perror("could not compile packet filter");
        return quit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &filter) == PCAP_ERROR) {
        perror("could apply filter to stream");
        return quit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}

int DHCPAnalyzer::next() {
    const u_char *packet;
    struct pcap_pkthdr header;
    if ((packet = pcap_next(handle, &header)) != NULL) {
        const u_char *payload = strip_payload(packet);
        dhcp_packet *dhcp_pckt;
        dhcp_pckt = (dhcp_packet *)payload;
        interpret_dhcp_packet(dhcp_pckt);
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

const u_char *DHCPAnalyzer::strip_payload(const u_char *packet) {
    const u_char *payload = packet;
    struct ether_header *eptr = (struct ether_header *)packet;

    if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
        payload += ETH_HLEN; /* skip ethernet header */
        struct ip *my_ip = (struct ip *)(payload);

        if (my_ip->ip_p == IPPROTO_UDP) {

            /* ip header length is in 32 bit increments */
            payload += my_ip->ip_hl * 4;
            const udphdr *udphdr_;
            udphdr_ = (const udphdr *)(payload);

            /* skip udp header */
            payload += sizeof(udphdr);
        }
    }

    return payload;
}

void DHCPAnalyzer::interpret_dhcp_packet(const dhcp_packet *packet) {
    uint8_t message_type = get_dhcp_message_type(packet);
    switch (message_type) {
    case DHCP_ACK: {
        int i = 0;
        while (i < addrs.size()) {
            if (addrs[i] == packet->yiaddr.s_addr)
                break;
            i++;
        }
        /* address is new, update subnet statistics */
        if (i == addrs.size()) {
            addrs.push_back(packet->yiaddr.s_addr);
            update_subnet_stats(&packet->yiaddr, true);
        }
        break;
    }

    default:
        break;
    }
}

void DHCPAnalyzer::update_subnet_stats(const in_addr *addr, bool add) {
    for (auto &i : subnet_stats) {
        if (i.contains(addr)) {
            (add) ? i.allocated++ : i.allocated--;
        }
    }
}

Subnet::Subnet(const char *addr, uint32_t alloc_addr) {
    size_t start = ((std::string)addr).find("/") + 1;
    prefix = std::stoi(((std::string)addr).substr(((std::string)addr).find("/") + 1, std::string::npos));
    net_addr.s_addr = inet_addr((((std::string)addr).substr(0, start - 1)).c_str());
    allocated = alloc_addr;
    max_alloc = get_max_addr_count();
}

uint32_t Subnet::get_max_addr_count() {
    return pow(2, 32 - prefix) - 2;
}

double Subnet::get_percentage() {
    return ((double)allocated) / max_alloc * 100.0;
}

bool Subnet::contains(const in_addr *ip_addr) {
    uint32_t mask = (~0) << (32 - prefix);
    if ((ntohl(mask) & ip_addr->s_addr) == (ntohl(mask) & net_addr.s_addr))
        return true;

    else
        return false;
}
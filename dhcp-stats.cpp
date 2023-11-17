#include "dhcp-stats.hpp"

DHCPAnalyzer::DHCPAnalyzer() {
    handle = nullptr;
}

/* quit analyzer and free all resources */
bool DHCPAnalyzer::quit(bool ret_stat) {
    if (handle != nullptr)
        pcap_close(handle);
    handle = nullptr;
    return ret_stat;
}

bool DHCPAnalyzer::initialize(const char *filename, const char *interface, std::vector<const char *> prefixes) {
    /* read directly from interface */
    if (filename == NULL && interface != NULL) {
        if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
            /* failed to open device */
            fprintf(stderr, "error: %s\n", errbuf);
            return quit(EXIT_FAILURE);
        }
    }
    /* read from pcap file */
    else if (filename != NULL && interface == NULL) {
        if ((handle = pcap_open_offline(filename, errbuf)) == NULL) {
            /* failed to read from pcap file */
            fprintf(stderr, "error: %s\n", errbuf);
            return quit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < prefixes.size(); i++) {
        subnet_stats.push_back(Subnet(prefixes[i], 0));
    }

    struct bpf_program filter;

    /* compile stream filter */
    if (pcap_compile(handle, &filter, "udp port 68 or udp port 67 or (vlan and (udp port 67 or udp port 68))", PCAP_OPENFLAG_PROMISCUOUS, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
        fprintf(stderr, "error: could not compile packet filter\n");
        return quit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &filter) == PCAP_ERROR) {
        fprintf(stderr, "error: could not apply packet filter\n");
        return quit(EXIT_FAILURE);
    }
    pcap_freecode(&filter);
    return EXIT_SUCCESS;
}

int DHCPAnalyzer::next() {
    const u_char *packet;
    struct pcap_pkthdr header;
    if ((packet = pcap_next(handle, &header)) != NULL) {
        const u_char *payload = strip_payload(packet);
        if (payload == nullptr)
            return EXIT_SUCCESS;
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

    if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
        payload += ETH_HLEN; /* skip ethernet header */
    else
        return nullptr;

    struct ip *my_ip = (struct ip *)(payload);

    if (my_ip->ip_p == IPPROTO_UDP) {
        /* ip header length is in 32 bit increments */
        payload += my_ip->ip_hl * 4;

        /* skip udp header */
        payload += sizeof(udphdr);
    } else
        return nullptr;

    return payload;
}

void DHCPAnalyzer::interpret_dhcp_packet(const dhcp_packet *packet) {
    uint8_t message_type = get_dhcp_message_type(packet);
    if (!message_type)
        return;
    switch (message_type) {
    case DHCPACK: {
        /* add yiaddr field to statistics */
        update_subnet_stats(&packet->yiaddr);

        /* add dhcp server address to statistics */
        in_addr svr_addr = get_dhcp_server_address(packet);
        if (svr_addr.s_addr != 0x00)
            update_subnet_stats(&svr_addr);
        break;
    }

    default:
        break;
    }
}

void DHCPAnalyzer::update_subnet_stats(const in_addr *addr) {

    int i = 0;
    while (i < addrs.size()) {
        if (addrs[i] == addr->s_addr)
            break;
        i++;
    }
    /* address is new, update subnet statistics */
    if (i == addrs.size()) {
        addrs.push_back(addr->s_addr);
        for (auto &i : subnet_stats) {
            if (i.contains(addr)) {
                i.allocated++;
            }
        }
    }
}

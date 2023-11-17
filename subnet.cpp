#include "subnet.hpp"

Subnet::Subnet(const char *addr, uint32_t alloc_addr) {
    size_t start = ((std::string)addr).find("/") + 1;
    prefix = std::stoi(((std::string)addr).substr(((std::string)addr).find("/") + 1, std::string::npos));
    net_addr.s_addr = inet_addr((((std::string)addr).substr(0, start - 1)).c_str());
    allocated = alloc_addr;
    max_alloc = get_max_addr_count();
    exceeded_half = false;
}

uint32_t Subnet::get_max_addr_count() {
    return pow(2, 32 - prefix) - 2;
}

double Subnet::get_percentage() {
    return (max_alloc == 0U) ? 0.0 : ((double)allocated) / max_alloc * 100.0;
}

bool Subnet::contains(const in_addr *ip_addr) {
    uint32_t mask;
    if (prefix == 0)
        mask = 0x00000000;
    else if (prefix == 32)
        mask = 0xffffffff;
    else
        mask = ntohl((~0) << (32 - prefix));

    in_addr net, broad;
    net.s_addr = (mask & net_addr.s_addr);
    broad.s_addr = ((mask & net_addr.s_addr) | ~mask);
    if ((ip_addr->s_addr == net.s_addr) || (ip_addr->s_addr == broad.s_addr))
        return false; /* do not allow broadcast and net adresses */

    if ((mask & ip_addr->s_addr) == (mask & net_addr.s_addr))
        return true;

    else
        return false;
}
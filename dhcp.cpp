#include "dhcp.hpp"

uint8_t get_dhcp_message_type (const dhcp_packet *packet) {
    uint8_t *ptr = (uint8_t *) packet->options;
    while (*ptr != DHCP_OPTION_END) {
        uint8_t size = *(ptr + 1);
        if (*ptr == DHCP_OPTION_MESSAGE_TYPE) {
            return *(ptr + 2);
        }
        ptr += size + 1;
    }
    return 99;
}

bool get_dhcp_option (const dhcp_packet *packet, const uint8_t option_identifier, uint8_t *length, uint8_t * buffer) {
    uint8_t *ptr = (uint8_t *) packet->options;
    while (*ptr != DHCP_OPTION_END) {
        uint8_t size = *(ptr + 1);
        if (*ptr == option_identifier) {
            buffer = ptr + 2;
            *length = size;
            return true;
        }
        ptr += size + 2;
    }
    return false;
}

time_t get_dhcp_lease_time (const dhcp_packet *packet) {
    uint8_t len, *buff;
    bool status = get_dhcp_option (packet, DHCP_OPTION_LEASE_TIME, &len, buff);
    return (status) ? ((time_t *) buff) [0] :0;
}
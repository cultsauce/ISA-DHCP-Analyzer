#include "dhcp.hpp"

uint8_t get_dhcp_message_type(const dhcp_packet *packet) {
    uint8_t *ptr = (uint8_t *)packet->options;
    while (*ptr != DHCP_OPTION_END) {
        uint8_t size = *(ptr + 1);
        if (*ptr == DHCP_OPTION_MESSAGE_TYPE) {
            return *(ptr + 2);
        }
        ptr += size + 1;
    }
    return 0;
}
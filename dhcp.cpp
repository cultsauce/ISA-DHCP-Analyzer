#include "dhcp.hpp"
uint8_t *get_dhcp_option(uint8_t *buff, uint8_t option_id) {
    uint8_t *ptr = buff;
    int i = 0;
    while (*ptr != DHCP_OPTION_END && i < MAX_DHCP_OPTIONS_LENGTH) {
        uint8_t size = *(ptr + 1);
        if (*ptr == option_id) {
            return (ptr + 2);
        }
        ptr += size + 2;
        i += size + 2;
    }
    return nullptr;
}

uint8_t get_dhcp_message_type(const dhcp_packet *packet) {
    uint8_t *ptr = (uint8_t *)packet->options;
    uint8_t *msg_type = get_dhcp_option(ptr, DHCP_OPTION_MESSAGE_TYPE);
    return (msg_type == nullptr) ? 0x00 : *msg_type;
}

in_addr get_dhcp_server_address(const dhcp_packet *packet) {
    uint8_t *ptr = (uint8_t *)packet->options;
    uint8_t *data_ptr = get_dhcp_option(ptr, DHCP_OPTION_SERVER_ADDRESS);
    in_addr svr_addr;
    svr_addr.s_addr = (data_ptr == nullptr) ? 0x00 : *((uint32_t *)data_ptr);
    return svr_addr;
}

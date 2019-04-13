#pragma once
#define ARPHEADER_H

#include<stdint.h>




struct allpacket
{
    uint8_t e_dmac[6];
    uint8_t e_smac[6];
    uint16_t type;

    uint16_t hd_type;
    uint16_t protocol_type;
    uint8_t hd_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t a_s_mac[6];
    uint32_t a_s_protocol[4];
    uint8_t a_t_mac[6];
    uint32_t a_t_protocol[4];
};


#define ETHERTYPE_ARP   0x0806
#define ARPOP_REQUEST   1
#define ARPOP_REPLY     2

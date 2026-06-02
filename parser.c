#include "parser.h"
#include <string.h>
#include <arpa/inet.h>


// Ethernet header structure (src and dst mac are 6 bytes, 48 bits in order, then ethertype follows with 2 bytes, 16 bits)
struct ethernet_header {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short ethertype;
};

// IPv4 header structure (20 bytes minimum, version and ihl are 4 bits each in the first byte, total length is 2 bytes, protocol is 1 byte, src and dst ip are 4 bytes each)
struct ipv4_header {
    unsigned char version_ihl;
    unsigned char tos;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_fragment;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int src_ip;
    unsigned int dst_ip;
};

// TCP header structure (20 bytes minimum, src and dst ports are 2 bytes each, sequence and acknowledgment numbers are 4 bytes each)
struct tcp_header {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char data_offset_reserved;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};

// UDP header structure (src and dst ports are 2 bytes each, length is 2 bytes, checksum is 2 bytes)
struct udp_header {
    unsigned short src_port;
    unsigned short dst_port;
};

// ARP header structure (28 bytes, hardware type and protocol type are 2 bytes each, hardware and protocol lengths are 1 byte each, opcode is 2 bytes, sender and target MACs are 6 bytes each, sender and target IPs are 4 bytes each)
struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};

// IPv6 header structure (40 bytes, version is 4 bits in the first byte, traffic class is 8 bits, flow label is 20 bits, payload length is 2 bytes, next header is 1 byte, hop limit is 1 byte, src and dst ip are 16 bytes each)
struct ipv6_header {
    unsigned int version_traffic_flow;
    unsigned short payload_length;
    unsigned char next_header;
    unsigned char hop_limit;
    unsigned char src_ip[16];
    unsigned char dst_ip[16];
};

// ipv4 declaration
int parse_ipv4_packet(unsigned char *buffer, ssize_t bytes_received, struct ParsedPacket *pkt);

// General packet parser
int parse_packet(unsigned char *buffer, ssize_t bytes_received, struct ParsedPacket *pkt) {
    memset(pkt, 0, sizeof(*pkt));

    pkt->length = bytes_received;
    pkt->src_port = -1;
    pkt->dst_port = -1;

    if (bytes_received < 14) {
        return 0;
    }

    struct ethernet_header *eth = (struct ethernet_header *)buffer;
    pkt->ethertype = ntohs(eth->ethertype);

    if (pkt->ethertype == 0x0800) {
        return parse_ipv4_packet(buffer, bytes_received, pkt);
    }

    if (pkt->ethertype == 0x0806) {
        if (bytes_received < 42) {
            return 0;
        }

        struct arp_header *arp = (struct arp_header *)(buffer + 14);

        pkt->is_arp = 1;
        pkt->arp_opcode = ntohs(arp->opcode);

        for (int i = 0; i < 4; i++) {
            pkt->arp_sender_ip[i] = arp->sender_ip[i];
            pkt->arp_target_ip[i] = arp->target_ip[i];
        }

        return 1;
    }

    if (pkt->ethertype == 0x86DD) {
        if (bytes_received < 54) {
            return 0;
        }

        struct ipv6_header *ip6 = (struct ipv6_header *)(buffer + 14);

        pkt->is_ipv6 = 1;
        pkt->ipv6_next_header = ip6->next_header;

        for (int i = 0; i < 16; i++) {
            pkt->ipv6_src_ip[i] = ip6->src_ip[i];
            pkt->ipv6_dst_ip[i] = ip6->dst_ip[i];
        }

        return 1;
    }

    return 1;
}

// IPV4 Parsing function
int parse_ipv4_packet(unsigned char *buffer, ssize_t bytes_received, struct ParsedPacket *pkt) {

    if (bytes_received < 34) {
        return 0;
    }

    struct ipv4_header *ip = (struct ipv4_header *)(buffer + 14);

    pkt->ip_version = ip->version_ihl >> 4; // moving the first 4 bits to the right for those alone
    pkt->ihl = (ip->version_ihl & 0x0F) * 4; // Bit mask to remove the first 4 bits using & with 0000, *4 to convert from number of 32-bit words to bytes
    pkt->protocol = ip->protocol;

    unsigned char *src = (unsigned char *)&ip->src_ip;
    unsigned char *dst = (unsigned char *)&ip->dst_ip;

    for (int i = 0; i < 4; i++) {
        pkt->src_ip[i] = src[i];
        pkt->dst_ip[i] = dst[i];
    }

    int transport_start = 14 + pkt->ihl;

    if (pkt->protocol == 6 && bytes_received >= transport_start + 20) {
        struct tcp_header *tcp = (struct tcp_header *)(buffer + transport_start);

        pkt->is_tcp = 1;
        pkt->src_port = ntohs(tcp->src_port);
        pkt->dst_port = ntohs(tcp->dst_port);
        pkt->tcp_flags = tcp->flags;
        pkt->tcp_header_len = (tcp->data_offset_reserved >> 4) * 4;

    } else if (pkt->protocol == 17 && bytes_received >= transport_start + 8) {
        struct udp_header *udp = (struct udp_header *)(buffer + transport_start);

        pkt->is_udp = 1;
        pkt->src_port = ntohs(udp->src_port);
        pkt->dst_port = ntohs(udp->dst_port);

    } else if (pkt->protocol == 1) {
        pkt->is_icmp = 1;
    }

    return 1;
}

// Packet filtering
int packet_matches_filter(struct ParsedPacket *pkt, char *filter, int filter_port) {
    if (filter == NULL) {
        return 1;
    }

    if (pkt->ethertype != 0x0800) {
        return 0;
    }

    if (strcmp(filter, "tcp") == 0) {
        return pkt->is_tcp;
    }

    if (strcmp(filter, "udp") == 0) {
        return pkt->is_udp;
    }

    if (strcmp(filter, "icmp") == 0) {
        return pkt->is_icmp;
    }

    if (filter_port != -1) {
        return pkt->src_port == filter_port || pkt->dst_port == filter_port;
    }

    return 1;
}
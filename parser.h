#ifndef PARSER_H
#define PARSER_H

#include <unistd.h>

// Packet parsing structure for relevant info extraction
struct ParsedPacket {
    // General fields
    int length;
    int ethertype;

    // IPv4 fields
    int ip_version;
    int ihl;
    int protocol;
    unsigned char src_ip[16];
    unsigned char dst_ip[16];

    // Transport layer fields
    int src_port;
    int dst_port;

    int is_tcp;
    int is_udp;
    int is_icmp;
    int is_arp;
    int is_ipv6;

    // TCP fields
    unsigned char tcp_flags;
    int tcp_header_len;

    // ARP fields
    int arp_opcode;
    unsigned char arp_sender_ip[4];
    unsigned char arp_target_ip[4];

    // IPv6 fields
    int ipv6_next_header;
    unsigned char ipv6_src_ip[16];
    unsigned char ipv6_dst_ip[16];

};

// General packet parser function
int parse_packet
    (
        unsigned char *buffer, 
        ssize_t bytes_received, 
        struct ParsedPacket *pkt
    );

// Packet filtering function
int packet_matches_filter
    (struct 
        ParsedPacket *pkt, 
        char *filter, 
        int filter_port
    );

#endif
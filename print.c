#include "print.h"
#include <stdio.h>
#include <arpa/inet.h>

// DNS query parsing
void parse_dns_query(unsigned char *dns, int dns_len) {
    if (dns_len < 12) {
        return;
    }

    // DNS header is 12 bytes. Question name starts at byte 12.
    int pos = 12;

    printf("DNS ");

    while (pos < dns_len && dns[pos] != 0) {
        int label_len = dns[pos];
        pos++;

        if (pos + label_len > dns_len) {
            return;
        }

        for (int i = 0; i < label_len; i++) {
            printf("%c", dns[pos + i]);
        }

        pos += label_len;

        if (dns[pos] != 0) {
            printf(".");
        }
    }

    printf(" ");
}

// HTTP parsing
void parse_http(unsigned char *payload, int payload_len) {
    if (payload_len <= 0) {
        return;
    }

    if (
        (payload_len >= 3 &&
         payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') ||
        (payload_len >= 4 &&
         payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T')
    ) {
        printf("HTTP ");

        for (int i = 0; i < payload_len && i < 80; i++) {
            if (payload[i] == '\r' || payload[i] == '\n') {
                break;
            }
            printf("%c", payload[i]);
        }

        printf(" ");
    }
}

// print block
void print_packet(struct ParsedPacket *pkt, unsigned char *buffer, ssize_t bytes_received) {
    if (pkt->ethertype == 0x0800) {

        printf("Packet (%zd bytes): ", pkt->length);
        printf("Ethernet -> IPv4 ");

        printf("version=%d ihl=%d ", pkt->ip_version, pkt->ihl);

        printf("%d.%d.%d.%d -> %d.%d.%d.%d ",
            pkt->src_ip[0], pkt->src_ip[1], pkt->src_ip[2], pkt->src_ip[3],
            pkt->dst_ip[0], pkt->dst_ip[1], pkt->dst_ip[2], pkt->dst_ip[3]
        );

        int transport_start = 14 + pkt->ihl;
        if (bytes_received >= transport_start + 4) {
            if (pkt->protocol == 6) {

                int src_port = pkt->src_port;
                int dst_port = pkt->dst_port;

                printf("ports %d -> %d ", src_port, dst_port);

                
                printf("flags ");
                if (pkt->tcp_flags & 0x02) printf("SYN ");
                if (pkt->tcp_flags & 0x10) printf("ACK ");
                if (pkt->tcp_flags & 0x01) printf("FIN ");
                if (pkt->tcp_flags & 0x04) printf("RST ");
                if (pkt->tcp_flags & 0x08) printf("PSH ");
                if (pkt->tcp_flags & 0x20) printf("URG ");

        int tcp_header_len = pkt->tcp_header_len;
        int tcp_payload_start = transport_start + tcp_header_len;
        int tcp_payload_len = bytes_received - tcp_payload_start;

        if (src_port == 80 || dst_port == 80) {
            if (tcp_payload_len > 0) {
                parse_http(buffer + tcp_payload_start, tcp_payload_len);
            }
        }

            } else if (pkt->protocol == 17) {

                int src_port = pkt->src_port;
                int dst_port = pkt->dst_port;

                printf("ports %d -> %d ", src_port, dst_port);
                
                if (src_port == 53 || dst_port == 53) {
                    int udp_header_len = 8;
                    int dns_start = transport_start + udp_header_len;
                    int dns_len = bytes_received - dns_start;

                    if (dns_len > 0) {
                        parse_dns_query(buffer + dns_start, dns_len);
                    }
                }
            }
        }   
        
        if (pkt->protocol == 1) {
            printf("ICMP\n");
        } else if (pkt->protocol == 6) {
            printf("TCP\n");
        } else if (pkt->protocol == 17) {
            printf("UDP\n");
        } else {
            printf("protocol=%d\n", pkt->protocol);
        }

    } else if (pkt->ethertype == 0x0806) {
        printf("Ethernet -> ARP ");

        if (bytes_received < 42) {
            printf("(too short)\n");
            return;
        }

        if (pkt->arp_opcode == 1) {
            printf("who-has ");
        } else if (pkt->arp_opcode == 2) {
            printf("reply ");
        } else {
            printf("opcode %d ", pkt->arp_opcode);
        }

        printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
            pkt->arp_sender_ip[0], pkt->arp_sender_ip[1], pkt->arp_sender_ip[2], pkt->arp_sender_ip[3],
            pkt->arp_target_ip[0], pkt->arp_target_ip[1], pkt->arp_target_ip[2], pkt->arp_target_ip[3]
        );
        
    } else if (pkt->ethertype == 0x86DD) {
        printf("Ethernet -> IPv6 ");

        if (bytes_received < 54) {
            printf("(too short)\n");
            return;
        }

        printf("next_header=%d ", pkt->ipv6_next_header);

        printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
               "%02x%02x:%02x%02x:%02x%02x:%02x%02x -> "
               "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
               "%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            pkt->ipv6_src_ip[0], pkt->ipv6_src_ip[1], pkt->ipv6_src_ip[2], pkt->ipv6_src_ip[3],
            pkt->ipv6_src_ip[4], pkt->ipv6_src_ip[5], pkt->ipv6_src_ip[6], pkt->ipv6_src_ip[7],
            pkt->ipv6_src_ip[8], pkt->ipv6_src_ip[9], pkt->ipv6_src_ip[10], pkt->ipv6_src_ip[11],
            pkt->ipv6_src_ip[12], pkt->ipv6_src_ip[13], pkt->ipv6_src_ip[14], pkt->ipv6_src_ip[15],

            pkt->ipv6_dst_ip[0], pkt->ipv6_dst_ip[1], pkt->ipv6_dst_ip[2], pkt->ipv6_dst_ip[3],
            pkt->ipv6_dst_ip[4], pkt->ipv6_dst_ip[5], pkt->ipv6_dst_ip[6], pkt->ipv6_dst_ip[7],
            pkt->ipv6_dst_ip[8], pkt->ipv6_dst_ip[9], pkt->ipv6_dst_ip[10], pkt->ipv6_dst_ip[11],
            pkt->ipv6_dst_ip[12], pkt->ipv6_dst_ip[13], pkt->ipv6_dst_ip[14], pkt->ipv6_dst_ip[15]
        );

    } else {
        printf("Ethernet -> EtherType 0x%04X\n", pkt->ethertype);
    }
}

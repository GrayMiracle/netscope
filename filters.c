#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#define ETH_P_ALL 0x0003

struct ethernet_header {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short ethertype;
};

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

struct udp_header {
    unsigned short src_port;
    unsigned short dst_port;
};

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

struct ipv6_header {
    unsigned int version_traffic_flow;
    unsigned short payload_length;
    unsigned char next_header;
    unsigned char hop_limit;
    unsigned char src_ip[16];
    unsigned char dst_ip[16];
};

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

int main(int argc, char *argv[]) {
    char *filter = NULL;
    int filter_port = -1;
    
    if (argc >= 2) {
        filter = argv[1];
    }

    if (argc >= 3 && strcmp(argv[1], "port") == 0) {
        filter_port = atoi(argv[2]);
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock < 0) {
        perror("socket");
        return 1;
    }

    unsigned char buffer[65536];

    printf("NetScope capturing packets...\n");

    while (1) {
        ssize_t bytes_received = recvfrom(
            sock,
            buffer,
            sizeof(buffer),
            0,
            NULL,
            NULL
        );

        if (bytes_received < 0) {
            perror("recvfrom");
            break;
        }

    if (bytes_received < 14) {
        continue;
    }

    struct ethernet_header *eth = (struct ethernet_header *) buffer;
    unsigned short ethertype = ntohs(eth->ethertype);

    if (filter != NULL && ethertype != 0x0800) {
        continue;
    }

    if (ethertype == 0x0800) {

        if (bytes_received < 34) {
            printf("(too short)\n");
            continue;
        }

        struct ipv4_header *ip = (struct ipv4_header *)(buffer + 14);
        unsigned char ip_version = ip->version_ihl >> 4; // moving the first 4 bits to the right for those alone
        unsigned char ihl = ip->version_ihl & 0x0F; // Bit mask to remove the first 4 bits using & with 0000
        unsigned char protocol = ip->protocol; 

        if (filter != NULL) {
            if (strcmp(filter, "tcp") == 0 && protocol != 6) {
                continue;
            }
            
            if (strcmp(filter, "udp") == 0 && protocol != 17) {
                continue;
            }

            if (strcmp(filter, "icmp") == 0 && protocol != 1) {
                continue;
            }
        }

        printf("Packet (%zd bytes): ", bytes_received);
        printf("Ethernet -> IPv4 ");

        printf("version=%d ihl=%d ", ip_version, ihl * 4);
        
        unsigned char *src_ip = (unsigned char *)&ip->src_ip; // Both 32 bit 4 byte fields, split as 
        unsigned char *dst_ip = (unsigned char *)&ip->dst_ip; // individual bytes to parse througho

        printf("%d.%d.%d.%d -> %d.%d.%d.%d ",
            src_ip[0], src_ip[1], src_ip[2], src_ip[3],
            dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]
        );

        int transport_start = 14 + (ihl * 4);
        if (bytes_received >= transport_start + 4) {
            if (protocol == 6) {
                struct tcp_header *tcp = (struct tcp_header *)(buffer + transport_start);

                unsigned short src_port = ntohs(tcp->src_port);
                unsigned short dst_port = ntohs(tcp->dst_port);

                if (filter_port != -1) {
                    if (src_port != filter_port && dst_port != filter_port) {
                        continue;
                    }
                }

                printf("ports %d -> %d ", src_port, dst_port);

                
                printf("flags ");
                if (tcp->flags & 0x02) printf("SYN ");
                if (tcp->flags & 0x10) printf("ACK ");
                if (tcp->flags & 0x01) printf("FIN ");
                if (tcp->flags & 0x04) printf("RST ");
                if (tcp->flags & 0x08) printf("PSH ");
                if (tcp->flags & 0x20) printf("URG ");

        int tcp_header_len = (tcp->data_offset_reserved >> 4) * 4;
        int tcp_payload_start = transport_start + tcp_header_len;
        int tcp_payload_len = bytes_received - tcp_payload_start;

        if (src_port == 80 || dst_port == 80) {
            if (tcp_payload_len > 0) {
                parse_http(buffer + tcp_payload_start, tcp_payload_len);
            }
        }

            } else if (protocol == 17) {
                struct udp_header *udp = (struct udp_header *)(buffer + transport_start);

                unsigned short src_port = ntohs(udp->src_port);
                unsigned short dst_port = ntohs(udp->dst_port);

                if (filter_port != -1) {
                    if (src_port != filter_port && dst_port != filter_port) {
                        continue;
                    }
                }

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
        
        if (protocol == 1) {
            printf("ICMP\n");
        } else if (protocol == 6) {
            printf("TCP\n");
        } else if (protocol == 17) {
            printf("UDP\n");
        } else {
            printf("protocol=%d\n", protocol);
        }

    } else if (ethertype == 0x0806) {
        printf("Ethernet -> ARP ");

        if (bytes_received < 42) {
            printf("(too short)\n");
            continue;
        }

        struct arp_header *arp = (struct arp_header *)(buffer + 14);
        unsigned short opcode = ntohs(arp->opcode);

        if (opcode == 1) {
            printf("who-has ");
        } else if (opcode == 2) {
            printf("reply ");
        } else {
            printf("opcode %d ", opcode);
        }

        printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
            arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3],
            arp->target_ip[0], arp->target_ip[1], arp->target_ip[2], arp->target_ip[3]
        );
    } else if (ethertype == 0x86DD) {
        printf("Ethernet -> IPv6 ");

        if (bytes_received < 54) {
            printf("(too short)\n");
            continue;
        }

        struct ipv6_header *ip6 = (struct ipv6_header *)(buffer + 14);

        printf("next_header=%d ", ip6->next_header);

        printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
               "%02x%02x:%02x%02x:%02x%02x:%02x%02x -> "
               "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
               "%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            ip6->src_ip[0], ip6->src_ip[1], ip6->src_ip[2], ip6->src_ip[3],
            ip6->src_ip[4], ip6->src_ip[5], ip6->src_ip[6], ip6->src_ip[7],
            ip6->src_ip[8], ip6->src_ip[9], ip6->src_ip[10], ip6->src_ip[11],
            ip6->src_ip[12], ip6->src_ip[13], ip6->src_ip[14], ip6->src_ip[15],

            ip6->dst_ip[0], ip6->dst_ip[1], ip6->dst_ip[2], ip6->dst_ip[3],
            ip6->dst_ip[4], ip6->dst_ip[5], ip6->dst_ip[6], ip6->dst_ip[7],
            ip6->dst_ip[8], ip6->dst_ip[9], ip6->dst_ip[10], ip6->dst_ip[11],
            ip6->dst_ip[12], ip6->dst_ip[13], ip6->dst_ip[14], ip6->dst_ip[15]
        );
    } else {
        printf("Ethernet -> EtherType 0x%04X\n", ethertype);
    }
    }

    close(sock);
    return 0;
}

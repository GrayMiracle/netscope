#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include "parser.h"
#include "print.h"
#include <string.h>
#include <stdlib.h>

#define ETH_P_ALL 0x0003

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

        struct ParsedPacket pkt;

        if (!parse_packet(buffer, bytes_received, &pkt)) {
            continue;
        }

        if (!packet_matches_filter(&pkt, filter, filter_port)) {
            continue;
        }

    print_packet(&pkt, buffer, bytes_received);

    }

    close(sock);
    return 0;
}

#ifndef PRINTER_H
#define PRINTER_H

#include <unistd.h>
#include "parser.h"

void print_packet(
    struct ParsedPacket *pkt,
    unsigned char *buffer,
    ssize_t bytes_received
);

#endif
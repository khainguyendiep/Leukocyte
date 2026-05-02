#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include <pcap.h>
#include <string>

struct ParsedPacket {
    char   src_ip[20];
    short  dest_port;
    std::string protocol;  // "tcp", "udp", "icmp", "unknown"
};

// Return false if packet can not parse
bool parse_packet(const u_char *packet, ParsedPacket &out);

#endif

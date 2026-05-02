#include "packetParser.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>

bool parse_packet(const u_char *packet, ParsedPacket &out) {
    // --- Parse source IP ---
    // Byte 26-29 trong raw packet là source IPv4
    int offset = 0; // offset of source
    for (int i = 26; i < 30; i++) {//data from byte 26 to byte 30 in a packet is source of packet
        if (i == 29){
 			//after the last byte we not add '.' into string
            offset += snprintf(out.src_ip + offset, sizeof(out.src_ip) - offset, "%d", *(packet + i));
		}
        else{
            offset += snprintf(out.src_ip + offset, sizeof(out.src_ip) - offset, "%d.", *(packet + i));
		}
    }

    // --- Parse protocol and dest port --- 
	// skip Ethernet header (byte 14th is the start of protocol field)
    struct ip *ip_header = (struct ip *)(packet + 14);
	// The variable ip_hl stands for Internet Header Length. In the actual binary structure of an IP packet, this field is only 4 bits long.
	// Because 4 bits can only hold a maximum value of 15 (2^4 - 1), the designers of the IP protocol couldn't store the actual byte count there (since 15 bytes isn't even enough for the minimum 20-byte header).
	// To solve this, the protocol defines the header length in 32-bit words (units of 4 bytes).
	// If ip_hl is 5: 5 * 4 = 20 bytes (This is the standard minimum).
	// If ip_hl is 15: 15 * 4 = 60 bytes (This is the maximum possible size).
 	int ip_header_len = ip_header->ip_hl * 4;
	//identify the protocol
    int protocol_id = ip_header->ip_p;

    if (protocol_id == IPPROTO_TCP) {
        struct tcphdr *tcp_h = (struct tcphdr *)(packet + 14 + ip_header_len);
        out.dest_port = ntohs(tcp_h->th_dport);
        out.protocol = "tcp";
    }
	else if (protocol_id == IPPROTO_UDP) {
        struct udphdr *udp_h = (struct udphdr *)(packet + 14 + ip_header_len);
        out.dest_port = ntohs(udp_h->uh_dport);
        out.protocol = "udp";
    }
	else if (protocol_id == IPPROTO_ICMP) {
        out.dest_port = -1;
        out.protocol = "icmp";
    }
	else {
        out.dest_port = -1;
        out.protocol = "unknown";
    }

    return true;
}

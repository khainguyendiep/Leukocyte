// port_scan_detector.h
#ifndef PORTSCANDETECTOR_H
#define PORTSCANDETECTOR_H

#include <pcap.h>
#include "libs/uthash/src/uthash.h"

struct hash_struct{
	int port_index;
   	long scanning_times;	
	UT_hash_handle hh;
};

struct port_scanned_state{
	hash_struct *hash_head = NULL;
	int port_counter;
	pcap_t *handle;
};

void got_packet(u_char *agrs, const struct pcap_pkthdr *header, const u_char *packet);
#endif

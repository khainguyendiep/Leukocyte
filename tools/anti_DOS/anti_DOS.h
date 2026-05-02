#ifndef ANTIDOS_H
#define ANTIDOS_H

#include <pcap.h>
#include <chrono>
#include <queue>
#include <vector>
#include <utility>
#include "libs/uthash/src/uthash.h"
#include <string>

// hashtable for char array, using uthash lib
struct hash_struct{
	char source_IPv4[20];
	int number_packets_sent;
	UT_hash_handle hh;
};

struct DosDetectorState{
	struct comparator{
		bool operator()(std::pair<std::string, int> a, std::pair<std::string, int> b){ //max heap
			return a.second < b.second;
		}
	};
	pcap_t *handle;
	std::chrono::steady_clock::time_point timeBegin = std::chrono::steady_clock::now();
	std::chrono::steady_clock::time_point timeEnd = std::chrono::steady_clock::now();
	long long packetNumber;
	long long countCapturedPacket;
	std::priority_queue<std::pair<std::string, int>, std::vector<std::pair<std::string, int>>, struct comparator> most_sender;
	hash_struct *hash_head = NULL;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif

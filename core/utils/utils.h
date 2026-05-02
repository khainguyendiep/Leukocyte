#ifndef UTILS_H
#define UTILS_H

#include <string>

std::string get_timestamp();
// Converts pcap packet timestamp to ISO 8601 format for Wazuh ingestion
std::string format_timestamp_from_header(const struct pcap_pkthdr *header);
#endif

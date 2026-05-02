#include "utils.h"
#include <pcap.h>
#include <chrono>
#include <sstream>
#include <iomanip>

std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// ISO 8601 format
std::string format_timestamp_from_header(const struct pcap_pkthdr *header) {
    // tv_sec is time_t — transfer to tm struct to format
    struct tm *tm_info = std::gmtime(&header->ts.tv_sec);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm_info);

    // Add microseconds to the end of string
    char full[40];
    snprintf(full, sizeof(full), "%s.%06ldZ", buf, (long)header->ts.tv_usec);
    return std::string(full);
    // Answer: "2025-01-01T13:25:30.123456Z"
}

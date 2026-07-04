#include "utils.h"

std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%S");
    return ss.str();
}

// ISO 8601 format
std::string format_timestamp_from_header(const struct pcap_pkthdr *header) {
	struct tm tm_info;
    // tv_sec is time_t — transfer to tm struct to format
	localtime_r(&header->ts.tv_sec, &tm_info);
    char date_time_buf[32];
    strftime(date_time_buf, sizeof(date_time_buf), "%Y-%m-%dT%H:%M:%S", &tm_info);

	//get timezone in format "+0700"
	char tz_buf[8];
    std::strftime(tz_buf, sizeof(tz_buf), "%z", &tm_info); // tz_buf has format "+0700"

    // Format tz__buf to "+07:00" (add colon)
    char formatted_tz[10] = "Z"; // default timezone is "Z" (UTC 0), if cannot get the timezone
    if (tz_buf[0] != '\0' && (tz_buf[0] == '+' || tz_buf[0] == '-')) {
        std::snprintf(formatted_tz, sizeof(formatted_tz), "%c%.2s:%.2s", tz_buf[0], &tz_buf[1], &tz_buf[3]);
    }

    // reassemble all
    char full_timestamp[64];
    std::snprintf(full_timestamp, sizeof(full_timestamp), "%s.%06ld%s", date_time_buf, (long)header->ts.tv_usec, formatted_tz);
    return std::string(full_timestamp);
}

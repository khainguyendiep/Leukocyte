#ifndef LOG_SCHEMA_H
#define LOG_SCHEMA_H

#include <string>
#include <sys/time.h>
// Standard log schema for all tool
// inline: allows multiple translation units to include this header
// without causing multiple definition errors at link time

struct LogEvent {
	std::string timestamp;
    std::string tool;        // "anti_dos", "port_scan", "brute_force"...
    std::string event_type;  // "attack_detected", "scan_detected"...
    std::string severity;    // "low", "medium", "high", "critical"
    int         threat_id;
    std::string src_ip;
    int         dest_port;
    std::string protocol;
    std::string description;
};

#endif

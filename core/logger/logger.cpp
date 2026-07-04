#include "logger.h"
#include <nlohmann/json.hpp>
#include <fstream>

using json = nlohmann::json;

void write_log(const LogEvent &event, const std::string &LOG_PATH) {
    json j;
    j["event_time"]          = event.event_time;
    j["tool"]               = event.tool;
    j["event_type"]         = event.event_type;
    j["severity"]           = event.severity;
    j["threat_id"]          = event.threat_id;
    j["network"]["src_ip"]  = event.src_ip;
    j["network"]["dest_port"] = event.dest_port;
    j["network"]["protocol"]  = event.protocol;
    j["description"]        = event.description;

    std::ofstream log_file(LOG_PATH, std::ios::app);
	if (log_file.is_open()) {
        // dump() with no arguments ensures the JSON is on one single line
        log_file << j.dump() << std::endl;
        log_file.close();
    }
}

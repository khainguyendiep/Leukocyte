#ifndef LOGGER_H
#define LOGGER_H

#include "log_schema.h"

// Writing log with standard schema, Wazuh will read this file
void write_log(const LogEvent &event, const std::string &log_path);

#endif

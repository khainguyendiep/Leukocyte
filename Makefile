# Compiler
CXX = g++

# Compiler flags
# -Wall -Wextra: Display warnings for safer code
# -std=c++17: Use C++17 standard
# -O2: Performance optimization
CXXFLAGS = -Wall -Wextra -std=c++17 -O2

# Include paths
# -I.: allows #include "core/...", #include "utils/...", #include "tools/..." from project root
INC = -I . -I libs/uthash/src -I libs/json/single_include

# Libraries to link
# -lpcap: Required for pcap library
LIBS = -lpcap

# ─── Shared core object files (reused by every tool) ──────────────────────────
CORE_SRCS = core/logger/logger.cpp \
            core/network/packetParser.cpp \
            core/network/networkUtils.cpp \
            core/utils/utils.cpp
CORE_OBJS = $(CORE_SRCS:.cpp=.o)

# ─── anti_DOS tool ─────────────────────────────────────────────────────────────
ANTIDOS_TARGET = anti_DOS
ANTIDOS_SRCS   = tools/anti_DOS/main.cpp \
                 tools/anti_DOS/anti_DOS.cpp
ANTIDOS_OBJS   = $(ANTIDOS_SRCS:.cpp=.o)

# ─── port_scan_detector tool ───────────────────────────────────────────────────
PORTSCAN_TARGET = port_scan_detector
PORTSCAN_SRCS   = tools/port_scan_detector/main.cpp \
                  tools/port_scan_detector/port_scan_detector.cpp
PORTSCAN_OBJS   = $(PORTSCAN_SRCS:.cpp=.o)

# ─── Default target: build all tools ──────────────────────────────────────────
# Add new tool targets here as the project grows
all: $(ANTIDOS_TARGET) $(PORTSCAN_TARGET)

# Link anti_DOS: its own objects + shared core objects
$(ANTIDOS_TARGET): $(ANTIDOS_OBJS) $(CORE_OBJS)
	$(CXX) $(CXXFLAGS) $(INC) -o $(ANTIDOS_TARGET) $(ANTIDOS_OBJS) $(CORE_OBJS) $(LIBS)

# Link port_scan_detector: its own objects + shared core objects
$(PORTSCAN_TARGET): $(PORTSCAN_OBJS) $(CORE_OBJS)
	$(CXX) $(CXXFLAGS) $(INC) -o $(PORTSCAN_TARGET) $(PORTSCAN_OBJS) $(CORE_OBJS) $(LIBS)

# Rule to compile any .cpp file to a .o file in the same directory
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INC) -c $< -o $@

# Clean command to remove all objects and executables
clean:
	find . -name "*.o" -delete
	rm -f $(ANTIDOS_TARGET) $(PORTSCAN_TARGET)

.PHONY: all clean

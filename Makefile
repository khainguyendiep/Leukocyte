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

# ─── Submodule config ──────────────────────────────────────────────────────────
UTHASH_PATH  := libs/uthash
JSON_PATH    := libs/json

# ─── Shared core object files (reused by every tool) ──────────────────────────
CORE_SRCS = core/logger/logger.cpp \
            core/network/packetParser.cpp \
            core/network/networkUtils.cpp \
            core/utils/utils.cpp
CORE_OBJS = $(CORE_SRCS:.cpp=.o)

# ─── anti-DoS tool ─────────────────────────────────────────────────────────────
ANTIDOS_TARGET = anti-DoS
ANTIDOS_SRCS   = tools/anti-DoS/src/main.cpp \
                 tools/anti-DoS/src/anti-DoS.cpp
ANTIDOS_OBJS   = $(ANTIDOS_SRCS:.cpp=.o)

# ─── port_scan_detector tool ───────────────────────────────────────────────────
PORTSCAN_TARGET = port_scan_detector
PORTSCAN_SRCS   = tools/port_scan_detector/main.cpp \
                  tools/port_scan_detector/port_scan_detector.cpp
PORTSCAN_OBJS   = $(PORTSCAN_SRCS:.cpp=.o)

# ─── All object files (for clean target) ───────────────────────────────────────
ALL_OBJS = $(CORE_OBJS) $(ANTIDOS_OBJS) $(PORTSCAN_OBJS)

# ─── Default target: build all tools ──────────────────────────────────────────
all: setup $(ANTIDOS_TARGET) $(PORTSCAN_TARGET)

# Link anti-DoS: its own objects + shared core objects
$(ANTIDOS_TARGET): $(ANTIDOS_OBJS) $(CORE_OBJS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ $^ $(LIBS)

# Link port_scan_detector: its own objects + shared core objects
$(PORTSCAN_TARGET): $(PORTSCAN_OBJS) $(CORE_OBJS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ $^ $(LIBS)

# Rule to compile any .cpp file to a .o file in the same directory
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INC) -c $< -o $@

# ─── Submodule setup ───────────────────────────────────────────────────────────
setup: .submodule_ready

# Sentinel file: skip setup if already initialized
.submodule_ready:
	@echo "Initializing submodules with sparse-checkout..."
	@git submodule update --init --recursive
	@cd $(UTHASH_PATH) && git sparse-checkout init --cone && git sparse-checkout set src
	@cd $(JSON_PATH) && git sparse-checkout init --cone && git sparse-checkout set single_include
	@git submodule update --checkout
	@touch .submodule_ready
	@echo "Submodules are ready!"

# ─── Cleanup ───────────────────────────────────────────────────────────────────
clean:
	@rm -f $(ALL_OBJS)

# "fclean" will auto call "clean" first to clean up .o file
fclean: clean
	@rm -f $(ANTIDOS_TARGET) $(PORTSCAN_TARGET) .submodule_ready

fclean_libs: fclean
	@git submodule deinit -f $(UTHASH_PATH) $(JSON_PATH)
	@git rm -f $(UTHASH_PATH) $(JSON_PATH)
	@rm -rf .git/modules/$(UTHASH_PATH) .git/modules/$(JSON_PATH)

re: fclean all

.PHONY: all setup clean fclean fclean_libs re

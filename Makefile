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

# ─── anti_dos tool ────────────────────────────────────────────────────────────
ANTIDOS_TARGET = anti_DOS
ANTIDOS_SRCS   = tools/anti_DOS/main.cpp \
                 tools/anti_DOS/anti_DOS.cpp
ANTIDOS_OBJS   = $(ANTIDOS_SRCS:.cpp=.o)

# ─── Default target: build all tools ──────────────────────────────────────────
all: $(ANTIDOS_TARGET)

# Link anti_dos: its own objects + shared core objects
$(ANTIDOS_TARGET): $(ANTIDOS_OBJS) $(CORE_OBJS)
	$(CXX) $(CXXFLAGS) $(INC) -o $(ANTIDOS_TARGET) $(ANTIDOS_OBJS) $(CORE_OBJS) $(LIBS)

# Rule to compile any .cpp file to a .o file in the same directory
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INC) -c $< -o $@

# Clean command to remove all objects and executables
clean:
	find . -name "*.o" -delete
	rm -f $(ANTIDOS_TARGET)

.PHONY: all clean

# 1. Compiler and flags
CC = gcc
CXX = g++
CFLAGS = -std=c11 -Wall -g
CXXFLAGS = -std=c++17 -Wall -g

# 2. Paths and libraries
INC = -I libs/uthash/src
LIBS = -lpcap

# 3. Source detection
SRCS_C = $(wildcard *.c)
SRCS_CXX = $(wildcard *.cpp)

# 4. Generate target names (remove extension .c and .cpp)
TARGETS_C = $(SRCS_C:.c=)
TARGETS_CXX = $(SRCS_CXX:.cpp=)
ALL_TARGETS = $(TARGETS_C) $(TARGETS_CXX)

# 5. Build rules
all: $(ALL_TARGETS)

# Rule for C++ file (from .cpp to execute file)
%: %.cpp
	$(CXX) $(CXXFLAGS) $(INC) $< -o $@ $(LIBS)

# Rule for C file (from .c to execute file)
%: %.c
	$(CC) $(CFLAGS) $(INC) $< -o $@ $(LIBS)

# 6. Clean up
clean:
	rm -f $(ALL_TARGETS) *.o

# 7. Run (run first file found)
run: all
	sudo ./$(firstword $(ALL_TARGETS))

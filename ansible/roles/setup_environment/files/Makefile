# Compiler
CXX = g++

# Paths for OpenSSL
OPENSSL_INCLUDE_DIR = /opt/homebrew/opt/openssl/include
OPENSSL_LIB_DIR = /opt/homebrew/opt/openssl/lib

# Compiler and linker flags
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread -I$(OPENSSL_INCLUDE_DIR) -I/opt/homebrew/include
LDFLAGS = -L$(OPENSSL_LIB_DIR) -lssl -lcrypto

# Common object files (compiled from files that do NOT contain a main)
COMMON_OBJS = acting_protocol/membership.o acting_protocol/acting_utils.o \
              acting_protocol/partnerships.o acting_protocol/audit.o

# Targets (each source file with main becomes its own executable)
TARGETS = dissemination freeRiderNode overloadNode silentNode

all: $(TARGETS)

# Normal node (dissemination.cpp)
dissemination: dissemination.o $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

# Free rider node
freeRiderNode: freeRiderNode.o $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

# Overloaded node
overloadNode: overloadNode.o $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

# Silent node
silentNode: silentNode.o $(COMMON_OBJS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

# Pattern rule to compile any .cpp into a .o
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGETS) *.o $(COMMON_OBJS)

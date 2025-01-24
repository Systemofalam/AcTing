CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread

# Object files
OBJS = dissemination.o acting_protocol/membership.o acting_protocol/acting_utils.o acting_protocol/partnerships.o

# Target binary
TARGET = dissemination

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

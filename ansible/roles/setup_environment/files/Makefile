CXX = g++
CXXFLAGS = -std=c++17 -Wall -pthread 

all: dissemination

dissemination: dissemination.cpp
	$(CXX) $(CXXFLAGS) dissemination.cpp -o dissemination -pthread

clean:
	rm -f dissemination

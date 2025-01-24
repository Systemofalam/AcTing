#ifndef ACTING_UTILS_H
#define ACTING_UTILS_H

#include <string>
#include <vector>
#include <unordered_map>

// Constants
#define CHUNK_SIZE 1024
constexpr int SUSPECT_THRESHOLD = 3;  // Define or include in acting_utils.h
constexpr int MEMBERSHIP_UPDATE_INTERVAL = 30;  // Define or include in acting_utils.h


// Structures
struct NodeInfo {
    std::string nodeId;
    std::string ipAddress;
    int port;
};

struct NodeConfig {
    std::string nodeId;
    int port;
    std::string sourceNode;
    std::string logFile;
    std::string dataFile;
};

// Function Declarations
std::string getCurrentTime();
void logMessage(const std::string& message, const std::string& logFile);
std::vector<std::string> readDataChunks(const std::string& dataFilePath);
int createAndBindSocket(int port, const std::string& logFile);

#endif // ACTING_UTILS_H

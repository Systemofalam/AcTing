#include "acting_utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

// Helper Mutex for Logging
static std::mutex logMutex;

// Get Current Time as String
std::string getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// Log Messages to Console and File
void logMessage(const std::string& message, const std::string& logFile) {
    std::lock_guard<std::mutex> lock(logMutex);

    std::cout << "[" << getCurrentTime() << "] " << message << std::endl;

    std::ofstream logStream(logFile, std::ios::app);
    if (logStream.is_open()) {
        logStream << "[" << getCurrentTime() << "] " << message << std::endl;
    }
}

// Read Data from File and Divide into Chunks
std::vector<std::string> readDataChunks(const std::string& dataFilePath) {
    std::ifstream file(dataFilePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open data file: " + dataFilePath);
    }

    std::vector<std::string> chunks;
    char buffer[CHUNK_SIZE];
    while (file.read(buffer, CHUNK_SIZE)) {
        chunks.emplace_back(buffer, CHUNK_SIZE);
    }
    if (file.gcount() > 0) {
        chunks.emplace_back(buffer, file.gcount());
    }

    return chunks;
}

// Create and Bind a UDP Socket
int createAndBindSocket(int port, const std::string &logFile) {
    int sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0) {
        logMessage("Error: Socket creation failed (Error: " + std::string(strerror(errno)) + ")", logFile);
        exit(EXIT_FAILURE);
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        logMessage("Error: Socket binding failed on port " + std::to_string(port) + " (Error: " + std::string(strerror(errno)) + ")", logFile);
        close(sockFd);
        exit(EXIT_FAILURE);
    }

    logMessage("Socket bound successfully. Node is listening on port " + std::to_string(port), logFile);
    return sockFd;
}

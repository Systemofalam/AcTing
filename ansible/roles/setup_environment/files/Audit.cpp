#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <json/json.h>
#include <openssl/sha.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>

#define PORT 8080
#define BUFFER_SIZE 4096

// Structure for log entries
struct LogEntry {
    int sequenceNumber;
    std::string hash;
    std::string action; // "propose" or "send"
    std::string chunkId;
    std::string recipient;
    std::string content;
};

// Compute SHA256 hash
std::string computeSHA256(const std::string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(data.c_str()), data.size(), hash);

    std::ostringstream oss;
    for (unsigned char c : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}

// Parse JSON log file
std::vector<LogEntry> parseLogFile(const std::string &filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open log file: " + filePath);
    }

    Json::Value root;
    file >> root;

    std::vector<LogEntry> logEntries;

    for (const auto &entry : root) {
        LogEntry logEntry;
        logEntry.sequenceNumber = entry["sequence_number"].asInt();
        logEntry.hash = entry["hash"].asString();
        logEntry.action = entry["action"].asString();
        logEntry.chunkId = entry["chunk_id"].asString();
        logEntry.recipient = entry["recipient"].asString();
        logEntry.content = entry["content"].toStyledString();
        logEntries.push_back(logEntry);
    }

    return logEntries;
}

// Validate log entries
bool validateLogEntries(const std::vector<LogEntry> &logEntries) {
    std::string previousHash = "0";

    // Map to track proposals and sends
    std::unordered_map<std::string, std::set<std::string>> proposedChunks; // chunkId -> recipients
    std::unordered_map<std::string, std::set<std::string>> sentChunks;    // chunkId -> recipients

    for (const auto &entry : logEntries) {
        // Compute and validate hash
        std::string dataToHash = previousHash + std::to_string(entry.sequenceNumber) + entry.content;
        std::string computedHash = computeSHA256(dataToHash);

        if (computedHash != entry.hash) {
            std::cerr << "Validation failed at sequence number: " << entry.sequenceNumber << std::endl;
            return false;
        }

        // Update the hash chain
        previousHash = computedHash;

        // Track proposals and sends
        if (entry.action == "propose") {
            proposedChunks[entry.chunkId].insert(entry.recipient);
        } else if (entry.action == "send") {
            sentChunks[entry.chunkId].insert(entry.recipient);
        }
    }

    // Verify that every proposed chunk was sent to the proposed recipients
    for (const auto &[chunkId, recipients] : proposedChunks) {
        if (sentChunks.find(chunkId) == sentChunks.end()) {
            std::cerr << "Chunk " << chunkId << " was proposed but not sent to any recipients." << std::endl;
            return false;
        }

        for (const auto &recipient : recipients) {
            if (sentChunks[chunkId].find(recipient) == sentChunks[chunkId].end()) {
                std::cerr << "Chunk " << chunkId << " was proposed to " << recipient << " but not sent." << std::endl;
                return false;
            }
        }
    }

    return true;
}

// Send a log request
void sendLogRequest(const std::string &ip, int port, const std::string &request) {
    int sockfd;
    sockaddr_in serverAddr{};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        throw std::runtime_error("Socket creation failed");
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr);

    if (connect(sockfd, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr)) < 0) {
        throw std::runtime_error("Connection to server failed");
    }

    send(sockfd, request.c_str(), request.size(), 0);

    char buffer[BUFFER_SIZE] = {0};
    recv(sockfd, buffer, BUFFER_SIZE, 0);

    std::cout << "Response from " << ip << ":" << port << " - " << buffer << std::endl;

    close(sockfd);
}

// Handle incoming log requests
void handleLogRequest(int serverSocket) {
    sockaddr_in clientAddr{};
    socklen_t clientLen = sizeof(clientAddr);
    char buffer[BUFFER_SIZE];

    while (true) {
        int clientSocket = accept(serverSocket, reinterpret_cast<sockaddr *>(&clientAddr), &clientLen);
        if (clientSocket < 0) {
            std::cerr << "Failed to accept connection" << std::endl;
            continue;
        }

        memset(buffer, 0, BUFFER_SIZE);
        read(clientSocket, buffer, BUFFER_SIZE);

        std::string logResponse = R"({"status": "success", "logs": []})"; // Replace with actual logs
        send(clientSocket, logResponse.c_str(), logResponse.size(), 0);

        close(clientSocket);
    }
}

// Start the audit server
void startAuditServer(int port) {
    int serverSocket;
    sockaddr_in serverAddr{};

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        throw std::runtime_error("Socket creation failed");
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr)) < 0) {
        throw std::runtime_error("Bind failed");
    }

    if (listen(serverSocket, 10) < 0) {
        throw std::runtime_error("Listen failed");
    }

    std::cout << "Audit server listening on port " << port << std::endl;

    handleLogRequest(serverSocket);

    close(serverSocket);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <mode> <port or log_file_path>" << std::endl;
        return EXIT_FAILURE;
    }

    std::string mode = argv[1];

    try {
        if (mode == "server") {
            int port = std::stoi(argv[2]);
            startAuditServer(port);
        } else if (mode == "client") {
            std::string logFilePath = argv[2];
            std::vector<LogEntry> logEntries = parseLogFile(logFilePath);
            if (validateLogEntries(logEntries)) {
                std::cout << "Log validation successful. All entries are consistent and all proposals were sent." << std::endl;
            } else {
                std::cerr << "Log validation failed. Issues found in proposals or sends." << std::endl;
            }
        } else {
            std::cerr << "Invalid mode. Use 'server' or 'client'." << std::endl;
            return EXIT_FAILURE;
        }
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

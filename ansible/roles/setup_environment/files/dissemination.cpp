#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <unordered_set>
#include <unordered_map>
#include <random>
#include <algorithm>
#include <chrono>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <atomic>
#include <condition_variable>
#include <cstring>

#define CHUNK_SIZE 1024
#define MAX_PARTNERS 5
#define GOSSIP_PERIOD 1000 // in milliseconds
#define SIMULATION_TIME 120000 // 2 minutes in milliseconds
#define RETRY_COUNT 3
#define RETRY_DELAY 100 // in milliseconds

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

std::mutex outputMutex;
std::atomic<bool> running{true};
std::condition_variable cv;
std::mutex cvMutex;
std::atomic<bool> ready{false};

// Helper function to log messages to console and file
void logMessage(const std::string &message, const std::string &logFile) {
    std::lock_guard<std::mutex> lock(outputMutex);
    std::cout << message << std::endl;

    std::ofstream logStream(logFile, std::ios::app);
    if (logStream.is_open()) {
        logStream << "[" << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())
                  << "] " << message << std::endl;
    }
}

// Parse the hosts.ini file to create a node database
std::unordered_map<std::string, NodeInfo> parseHostsFile(const std::string &hostsFilePath) {
    std::unordered_map<std::string, NodeInfo> nodeDatabase;
    std::ifstream hostsFile(hostsFilePath);
    if (!hostsFile.is_open()) {
        logMessage("Error: Unable to open hosts.ini file: " + hostsFilePath, "error.log");
        exit(EXIT_FAILURE);
    }

    std::string line;
    while (std::getline(hostsFile, line)) {
        if (line.empty() || line[0] == '[' || line[0] == '#') continue;

        try {
            std::istringstream iss(line);
            std::string nodeName, hostPart, connectionPart, portPart;
            iss >> nodeName >> hostPart >> connectionPart >> portPart;

            NodeInfo nodeInfo;
            nodeInfo.nodeId = nodeName;

            size_t hostPos = hostPart.find('=');
            if (hostPos != std::string::npos) {
                nodeInfo.ipAddress = hostPart.substr(hostPos + 1);
            }

            size_t portPos = portPart.find('=');
            if (portPos != std::string::npos) {
                nodeInfo.port = std::stoi(portPart.substr(portPos + 1));
            }

            nodeDatabase[nodeName] = nodeInfo;
        } catch (const std::exception &e) {
            logMessage("Error parsing node info: " + line + " (" + e.what() + ")", "error.log");
        }
    }

    hostsFile.close();
    return nodeDatabase;
}

// Parse a configuration file for a single node
NodeConfig parseConfigFile(const std::string &configFilePath) {
    NodeConfig config;
    std::ifstream configFile(configFilePath);
    if (!configFile.is_open()) {
        logMessage("Error: Unable to open config file: " + configFilePath, "error.log");
        exit(EXIT_FAILURE);
    }

    std::string line;
    while (std::getline(configFile, line)) {
        if (line.empty() || line[0] == '#') continue;

        try {
            size_t delimPos = line.find(':');
            if (delimPos == std::string::npos) {
                logMessage("Error parsing config line: " + line, "error.log");
                continue;
            }

            std::string key = line.substr(0, delimPos);
            std::string value = line.substr(delimPos + 1);
            key.erase(std::remove_if(key.begin(), key.end(), ::isspace), key.end());
            value.erase(std::remove_if(value.begin(), value.end(), ::isspace), value.end());

            if (key == "node_id") {
                config.nodeId = value;
            } else if (key == "port") {
                config.port = std::stoi(value);
            } else if (key == "source_node") {
                config.sourceNode = value;
            } else if (key == "log_file") {
                config.logFile = value;
            } else if (key == "data_file") {
                config.dataFile = value;
            } else {
                logMessage("Unknown config key: " + key, "error.log");
            }
        } catch (const std::exception &e) {
            logMessage("Error parsing config line: " + line + " (" + e.what() + ")", "error.log");
        }
    }

    configFile.close();
    return config;
}

// Read data from the file and divide it into chunks
std::vector<std::string> readDataChunks(const std::string &dataFilePath) {
    std::ifstream dataFile(dataFilePath, std::ios::binary);
    if (!dataFile.is_open()) {
        logMessage("Error: Unable to open data file: " + dataFilePath, "error.log");
        exit(EXIT_FAILURE);
    }

    std::vector<std::string> chunks;
    char buffer[CHUNK_SIZE];
    while (dataFile.read(buffer, CHUNK_SIZE)) {
        chunks.emplace_back(buffer, CHUNK_SIZE);
    }
    if (dataFile.gcount() > 0) {
        chunks.emplace_back(buffer, dataFile.gcount());
    }

    dataFile.close();
    return chunks;
}

// Create and bind a socket
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

// Wait until all nodes are ready
void waitForReady() {
    std::unique_lock<std::mutex> lock(cvMutex);
    cv.wait(lock, [] { return ready.load(); });
}

// Node logic for disseminating data
void nodeLoop(const NodeConfig &config, const std::unordered_map<std::string, NodeInfo> &nodeDatabase, bool isSourceNode) {
    int sockFd = createAndBindSocket(config.port, config.logFile);

    std::vector<std::string> dataChunks;
    if (isSourceNode) {
        dataChunks = readDataChunks(config.dataFile);
        logMessage("Source node " + config.nodeId + " loaded " + std::to_string(dataChunks.size()) + " data chunks.", config.logFile);
    }

    {
        std::lock_guard<std::mutex> lock(cvMutex);
        ready.store(true);
        cv.notify_all();
    }

    waitForReady();

    std::unordered_set<std::string> receivedChunks;
    auto startTime = std::chrono::steady_clock::now();

    while (running) {
        logMessage("Node " + config.nodeId + " entering Propose Phase.", config.logFile);

        // Select partners
        std::vector<NodeInfo> partners;
        for (const auto &[key, node] : nodeDatabase) {
            if (node.nodeId != config.nodeId) partners.push_back(node);
        }
        std::shuffle(partners.begin(), partners.end(), std::mt19937{std::random_device{}()});
        if (partners.size() > MAX_PARTNERS) partners.resize(MAX_PARTNERS);

        // Propose Phase: Send chunks to partners
        for (const auto &partner : partners) {
            sockaddr_in partnerAddr{};
            partnerAddr.sin_family = AF_INET;
            partnerAddr.sin_port = htons(partner.port);
            inet_pton(AF_INET, partner.ipAddress.c_str(), &partnerAddr.sin_addr);

            for (const auto &chunk : (isSourceNode ? dataChunks : std::vector<std::string>(receivedChunks.begin(), receivedChunks.end()))) {
                if (sendto(sockFd, chunk.c_str(), chunk.size(), 0, (struct sockaddr *)&partnerAddr, sizeof(partnerAddr)) >= 0) {
                    logMessage("Node " + config.nodeId + " sent chunk to " + partner.nodeId, config.logFile);
                } else {
                    logMessage("Error: Failed to send chunk to " + partner.nodeId + " (Error: " + std::string(strerror(errno)) + ")", config.logFile);
                }
            }
        }

        // Pull Phase: Receive chunks
        char buffer[CHUNK_SIZE];
        sockaddr_in senderAddr{};
        socklen_t senderLen = sizeof(senderAddr);

        int bytesReceived = recvfrom(sockFd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT, (struct sockaddr *)&senderAddr, &senderLen);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            std::string chunk(buffer, bytesReceived);
            if (receivedChunks.insert(chunk).second) {
                logMessage("Node " + config.nodeId + " received new chunk.", config.logFile);
            } else {
                logMessage("Node " + config.nodeId + " received duplicate chunk.", config.logFile);
            }
        }

        if (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count() >= SIMULATION_TIME) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(GOSSIP_PERIOD));
    }

    logMessage("Node " + config.nodeId + " shutting down.", config.logFile);
    close(sockFd);
}

// Main function to initialize and run the node
int main(int argc, char *argv[]) {
    if (argc != 3 || std::string(argv[1]) != "--config") {
        std::cerr << "Usage: " << argv[0] << " --config <config_file_path>" << std::endl;
        return EXIT_FAILURE;
    }

    NodeConfig config = parseConfigFile(argv[2]);
    logMessage("Starting node " + config.nodeId + " on port " + std::to_string(config.port), config.logFile);

    auto nodeDatabase = parseHostsFile("/Users/lhassini/Desktop/PHD/Dissemination-System/ansible/inventory/hosts.ini");
    bool isSourceNode = (config.nodeId == config.sourceNode);

    std::thread nodeThread(nodeLoop, config, nodeDatabase, isSourceNode);

    nodeThread.join();

    return 0;
}

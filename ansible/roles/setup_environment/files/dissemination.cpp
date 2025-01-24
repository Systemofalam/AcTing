#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <unordered_set>
#include <unordered_map>
#include <set>
#include <algorithm>
#include <chrono>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <random>

#include "acting_protocol/acting_utils.h"
#include "acting_protocol/membership.h"
#include "acting_protocol/partnerships.h"

#define CHUNK_SIZE 1024 // Size of each UDP chunk
#define GOSSIP_PERIOD 6000 // milliseconds
#define SIMULATION_TIME 120000 // milliseconds
#define MAX_PARTNERS 5 // Maximum nodes to send data in each gossip round
#define PARTNERSHIP_PERIOD 5 // Partnership update period in rounds
enum class State { PROPOSE, PUSH, PULL }; // State Enum


// Global Variables
std::mutex logMutex;
std::atomic<bool> running{true};
std::condition_variable readyCV;
std::mutex readyMutex;
std::atomic<bool> allReady{false};
std::condition_variable cv;      // Condition variable for synchronization
std::mutex cvMutex;              // Mutex for the condition variable
std::atomic<bool> ready{false};  // Atomic boolean for readiness

// Function to generate a unique sequence number
std::string generateSequenceNumber(int chunkIndex) {
    std::ostringstream oss;
    oss << chunkIndex;
    return oss.str();
}

// Helper function to resolve node ID from port
std::string getNodeIdFromPort(int port, const std::unordered_map<std::string, NodeInfo> &nodeDatabase) {
    for (const auto &[nodeId, nodeInfo] : nodeDatabase) {
        if (nodeInfo.port == port) {
            return nodeId;
        }
    }
    return ""; // Return empty string if no match is found
}


//Function to send messages over sockets
void sendMessage(int sockFd, const std::string &message, const sockaddr_in &partnerAddr, const std::string &logFile) {
    if (sendto(sockFd, message.c_str(), message.size(), 0, (struct sockaddr *)&partnerAddr, sizeof(partnerAddr)) >= 0) {
        logMessage("Sent message: " + message + " to partner at " + inet_ntoa(partnerAddr.sin_addr) + ":" + std::to_string(ntohs(partnerAddr.sin_port)), logFile);
    } else {
        logMessage("Error: Failed to send message: " + message + " (" + std::string(strerror(errno)) + ")", logFile);
    }
}

//Function to extract a field from a message
std::string extractField(const std::string &message, const std::string &key) {
    size_t startPos = message.find(key + ":");
    if (startPos == std::string::npos) {
        return "";
    }
    startPos += key.size() + 1; // Skip past "Key:"
    size_t endPos = message.find('|', startPos); // Fields are separated by '|'
    return message.substr(startPos, endPos - startPos);
}

// Send a specific data chunk to a partner
void sendChunk(const std::string &chunk, const std::string &sequenceNumber, const std::string &state, 
               const sockaddr_in &partnerAddr, int sockFd, const std::string &logFile) {
    // Construct the message
    std::string message = "Seq:" + sequenceNumber + "|State:" + state + "|Chunk:" + chunk;

    // Send the message
    ssize_t bytesSent = sendto(sockFd, message.c_str(), message.size(), 0, 
                               (struct sockaddr *)&partnerAddr, sizeof(partnerAddr));
    if (bytesSent >= 0) {
        logMessage("Successfully sent chunk (Seq: " + sequenceNumber + ", Bytes: " + std::to_string(bytesSent) + ")", logFile);
    } else {
        logMessage("Error: Failed to send chunk (Seq: " + sequenceNumber + ", Error: " + std::string(strerror(errno)) + ")", logFile);
    }
}


// Function to parse `hosts.ini` dynamically
std::unordered_map<std::string, NodeInfo> parseHostsFile(const std::string& hostsFilePath) {
    std::unordered_map<std::string, NodeInfo> nodeDatabase;
    std::ifstream hostsFile(hostsFilePath);
    if (!hostsFile.is_open()) {
        throw std::runtime_error("Unable to open hosts file: " + hostsFilePath);
    }

    std::string line;
    while (std::getline(hostsFile, line)) {
        // Skip section headers and comments
        if (line.empty() || line[0] == '[' || line[0] == '#') {
            continue;
        }

        std::istringstream iss(line);
        std::string nodeName;
        NodeInfo node;

        // Extract the node name (first word)
        iss >> nodeName;

        // Find the key-value pairs for `ansible_host` and `ansible_port`
        size_t hostPos = line.find("ansible_host=");
        size_t portPos = line.find("ansible_port=");

        if (hostPos != std::string::npos) {
            size_t hostEnd = line.find(' ', hostPos);
            node.ipAddress = line.substr(hostPos + 13, hostEnd - (hostPos + 13)); // 13 = length of "ansible_host="
        }

        if (portPos != std::string::npos) {
            size_t portEnd = line.find(' ', portPos);
            std::string portStr = line.substr(portPos + 13, portEnd - (portPos + 13)); // 13 = length of "ansible_port="
            try {
                node.port = std::stoi(portStr);
            } catch (const std::exception& e) {
                throw std::runtime_error("Error parsing port for " + nodeName + ": " + e.what());
            }
        }

        // Store the parsed node information
        if (!nodeName.empty() && !node.ipAddress.empty() && node.port > 0) {
            node.nodeId = nodeName;
            nodeDatabase[nodeName] = node;
        }
    }

    hostsFile.close();
    return nodeDatabase;
}

// Function to wait for all nodes to be ready
void waitForReady() {
    const int WAIT_TIME_MS = 5000; // 5 seconds
    std::cout << "Node waiting for " << WAIT_TIME_MS / 1000 << " seconds before starting..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_MS));
    std::cout << "Node is ready to start dissemination." << std::endl;
}

void nodeLoop(const NodeConfig &config, const std::unordered_map<std::string, NodeInfo> &nodeDatabase, bool isSourceNode) {
    logMessage("Node " + config.nodeId + " initializing.", config.logFile);

    int sockFd = createAndBindSocket(config.port, config.logFile);
    if (sockFd < 0) {
        logMessage("Error: Failed to create or bind socket. Exiting.", config.logFile);
        return;
    }
    logMessage("Node " + config.nodeId + " successfully bound to port " + std::to_string(config.port), config.logFile);

    std::vector<std::string> dataChunks = isSourceNode ? readDataChunks(config.dataFile) : std::vector<std::string>();
    std::unordered_set<std::string> ownedChunks;
    std::unordered_set<std::string> receivedChunks;
    std::unordered_map<std::string, std::unordered_set<std::string>> pendingPullRequests;

    if (isSourceNode) {
        logMessage("Node " + config.nodeId + " loaded " + std::to_string(dataChunks.size()) + " data chunks from source file.", config.logFile);
        for (size_t i = 0; i < dataChunks.size(); ++i) {
            ownedChunks.insert(std::to_string(i));
        }
    }

    PartnershipManager partnershipManager(config.nodeId, MAX_PARTNERS, PARTNERSHIP_PERIOD, config.logFile);

    State currentState = State::PROPOSE;
    int round = 0;

    while (running) {
        auto roundStartTime = std::chrono::steady_clock::now();
        logMessage("Node " + config.nodeId + " entering round " + std::to_string(round), config.logFile);

        partnershipManager.updatePartnerships(round, nodeDatabase);
        auto currentPartners = partnershipManager.getCurrentPartners();

        if (currentPartners.empty()) {
            logMessage("Warning: Node " + config.nodeId + " has no partners this round.", config.logFile);
        } else {
            logMessage("Node " + config.nodeId + " has " + std::to_string(currentPartners.size()) + " partners this round.", config.logFile);
        }

        try {
            switch (currentState) {
                case State::PROPOSE: {
                    logMessage("Node " + config.nodeId + " in PROPOSE state.", config.logFile);

                    for (const auto &partnerId : currentPartners) {
                        if (nodeDatabase.find(partnerId) == nodeDatabase.end()) {
                            logMessage("Error: Partner ID not found in database: " + partnerId, config.logFile);
                            continue;
                        }
                        const auto &partner = nodeDatabase.at(partnerId);

                        sockaddr_in partnerAddr{};
                        partnerAddr.sin_family = AF_INET;
                        partnerAddr.sin_port = htons(partner.port);
                        if (inet_pton(AF_INET, partner.ipAddress.c_str(), &partnerAddr.sin_addr) <= 0) {
                            logMessage("Error: Invalid IP address for partner: " + partner.ipAddress, config.logFile);
                            continue;
                        }

                        for (const auto &chunkId : ownedChunks) {
                            std::string message = "Header:Propose|Seq:" + chunkId;
                            sendMessage(sockFd, message, partnerAddr, config.logFile);
                        }
                    }
                    currentState = State::PULL;
                    break;
                }

                case State::PULL: {
                    logMessage("Node " + config.nodeId + " in PULL state.", config.logFile);

                    char buffer[CHUNK_SIZE];
                    sockaddr_in senderAddr{};
                    socklen_t senderLen = sizeof(senderAddr);

                    while (true) {
                        int bytesReceived = recvfrom(sockFd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT, (struct sockaddr *)&senderAddr, &senderLen);
                        if (bytesReceived > 0) {
                            buffer[bytesReceived] = '\0';
                            std::string message(buffer, bytesReceived);
                            logMessage("Node " + config.nodeId + " received message: " + message, config.logFile);

                            if (message.find("Header:Propose") != std::string::npos) {
                                std::string seqNumber = extractField(message, "Seq");
                                if (!seqNumber.empty() && receivedChunks.find(seqNumber) == receivedChunks.end()) {
                                    std::string senderId = getNodeIdFromPort(ntohs(senderAddr.sin_port), nodeDatabase);
                                    pendingPullRequests[senderId].insert(seqNumber);
                                    logMessage("Node " + config.nodeId + " queued pull request for chunk " + seqNumber + " from node " + senderId, config.logFile);
                                }
                            } else if (message.find("Header:Pull") != std::string::npos) {
                                std::string requestedSeq = extractField(message, "Seq");
                                if (!requestedSeq.empty() && ownedChunks.find(requestedSeq) != ownedChunks.end()) {
                                    sendChunk(dataChunks[std::stoi(requestedSeq)], requestedSeq, "Push", senderAddr, sockFd, config.logFile);
                                } else {
                                    logMessage("Warning: Requested chunk not available: " + requestedSeq, config.logFile);
                                }
                            } else if (message.find("Header:Push") != std::string::npos) {
                                std::string seqNumber = extractField(message, "Seq");
                                std::string chunkData = extractField(message, "Chunk");
                                if (receivedChunks.find(seqNumber) == receivedChunks.end()) {
                                    ownedChunks.insert(seqNumber);
                                    receivedChunks.insert(seqNumber);
                                    dataChunks.push_back(chunkData);
                                    logMessage("Node " + config.nodeId + " received and stored chunk " + seqNumber, config.logFile);
                                }
                            }
                        } else {
                            break;
                        }
                    }

                    for (const auto &[partnerId, requests] : pendingPullRequests) {
                        if (nodeDatabase.find(partnerId) == nodeDatabase.end()) {
                            logMessage("Error: Partner ID not found in database: " + partnerId, config.logFile);
                            continue;
                        }
                        const auto &partner = nodeDatabase.at(partnerId);

                        sockaddr_in partnerAddr{};
                        partnerAddr.sin_family = AF_INET;
                        partnerAddr.sin_port = htons(partner.port);
                        inet_pton(AF_INET, partner.ipAddress.c_str(), &partnerAddr.sin_addr);

                        for (const auto &seqNumber : requests) {
                            std::string pullMessage = "Header:Pull|Seq:" + seqNumber;
                            sendMessage(sockFd, pullMessage, partnerAddr, config.logFile);
                        }
                    }

                    pendingPullRequests.clear();
                    currentState = State::PUSH;
                    break;
                }

                case State::PUSH: {
                    logMessage("Node " + config.nodeId + " in PUSH state.", config.logFile);

                    char buffer[CHUNK_SIZE];
                    sockaddr_in senderAddr{};
                    socklen_t senderLen = sizeof(senderAddr);

                    while (true) {
                        int bytesReceived = recvfrom(sockFd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT, (struct sockaddr *)&senderAddr, &senderLen);
                        if (bytesReceived > 0) {
                            buffer[bytesReceived] = '\0';
                            std::string message(buffer, bytesReceived);
                            logMessage("Node " + config.nodeId + " received pull request: " + message, config.logFile);

                            if (message.find("Header:Pull") != std::string::npos) {
                                std::string seqNumber = extractField(message, "Seq");
                                if (!seqNumber.empty() && ownedChunks.find(seqNumber) != ownedChunks.end()) {
                                    sendChunk(dataChunks[std::stoi(seqNumber)], seqNumber, "Push", senderAddr, sockFd, config.logFile);
                                }
                            }
                        } else {
                            break;
                        }
                    }

                    currentState = State::PROPOSE;
                    break;
                }
            }
        } catch (const std::exception &e) {
            logMessage("Error: Exception during state execution: " + std::string(e.what()), config.logFile);
        }

        auto roundEndTime = std::chrono::steady_clock::now();
        auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(roundEndTime - roundStartTime).count();
        if (elapsedTime < 30) {
            std::this_thread::sleep_for(std::chrono::seconds(30 - elapsedTime));
        }

        logMessage("Node " + config.nodeId + " completed round " + std::to_string(round), config.logFile);
        ++round;
    }

    close(sockFd);
    logMessage("Node " + config.nodeId + " shutting down.", config.logFile);
}

NodeConfig parseConfigFile(const std::string& configFilePath) {
    NodeConfig config;
    std::ifstream configFile(configFilePath);

    if (!configFile.is_open()) {
        throw std::runtime_error("Error: Unable to open config file: " + configFilePath);
    }

    std::string line;
    while (std::getline(configFile, line)) {
        // Skip empty lines or comments
        if (line.empty() || line[0] == '#') {
            continue;
        }

        size_t delimPos = line.find(':');
        if (delimPos == std::string::npos) {
            throw std::runtime_error("Error: Malformed line in config file: " + line);
        }

        std::string key = line.substr(0, delimPos);
        std::string value = line.substr(delimPos + 1);

        // Trim spaces from key and value
        key.erase(remove_if(key.begin(), key.end(), isspace), key.end());
        value.erase(remove_if(value.begin(), value.end(), isspace), value.end());

        try {
            if (key == "node_id") {
                config.nodeId = value;
            } else if (key == "port") {
                config.port = std::stoi(value);  // Conversion to integer
            } else if (key == "source_node") {
                config.sourceNode = value;
            } else if (key == "log_file") {
                config.logFile = value;
            } else if (key == "data_file") {
                config.dataFile = value;
            } else {
                throw std::runtime_error("Error: Unknown key in config file: " + key);
            }
        } catch (const std::exception& e) {
            throw std::runtime_error("Error parsing key '" + key + "' with value '" + value + "': " + e.what());
        }
    }

    // Ensure all required fields are set
    if (config.nodeId.empty() || config.port <= 0 || config.logFile.empty()) {
        throw std::runtime_error("Error: Missing required fields in config file.");
    }

    return config;
}


// Main Function
int main(int argc, char* argv[]) {
    if (argc != 3 || std::string(argv[1]) != "--config") {
        std::cerr << "Usage: " << argv[0] << " --config <config_file_path>" << std::endl;
        return EXIT_FAILURE;
    }

    try {
        // Parse the configuration file
        logMessage("Parsing configuration file...", "debug.log");
        NodeConfig config = parseConfigFile(argv[2]);
        logMessage("Configuration parsed successfully: Node ID = " + config.nodeId, "debug.log");

        // Parse the hosts file
        logMessage("Parsing hosts file...", "debug.log");
        auto nodeDatabase = parseHostsFile("/Users/lhassini/Desktop/PHD/Gossip_Protocols/AcTing/ansible/inventory/hosts.ini");
        logMessage("Hosts file parsed successfully.", "debug.log");

        // Log parsed nodes for debugging
        logMessage("Parsed node database:", "debug.log");
        for (const auto& [nodeId, node] : nodeDatabase) {
            logMessage("NodeID: " + nodeId + ", IP: " + node.ipAddress + ", Port: " + std::to_string(node.port), "debug.log");
        }

        // Add current node to membership
        logMessage("Adding current node to membership...", "debug.log");
        if (!addNode({config.nodeId, nodeDatabase[config.nodeId].ipAddress, config.port}, config.logFile)) {
            logMessage("Node already exists in membership: " + config.nodeId, config.logFile);
        } else {
            logMessage("Node added to membership successfully: " + config.nodeId, config.logFile);
        }

        // Start a thread to notify the source node asynchronously
        logMessage("Starting join request thread...", "debug.log");
        std::thread joinRequestThread([&]() {
            try {
                logMessage("Join request thread started.", config.logFile);
                handleJoinRequest(
                    NodeInfo{config.nodeId, nodeDatabase[config.nodeId].ipAddress, config.port},
                    config.sourceNode,
                    config.logFile);
                logMessage("Join request completed.", config.logFile);
            } catch (const std::exception& e) {
                logMessage("Error in join request thread: " + std::string(e.what()), config.logFile);
            }
        });

        // Determine if this node is the source node
        logMessage("Determining if this node is the source node...", "debug.log");
        bool isSourceNode = (config.nodeId == config.sourceNode);

        // Start the node loop in a separate thread
        logMessage("Starting node loop thread...", "debug.log");
        std::thread nodeThread([&]() {
            try {
                logMessage("Node loop thread started.", config.logFile);
                nodeLoop(config, std::ref(nodeDatabase), isSourceNode);
                logMessage("Node loop thread completed.", config.logFile);
            } catch (const std::exception& e) {
                logMessage("Error in node loop thread: " + std::string(e.what()), config.logFile);
            }
        });

        // Wait for threads to complete
        logMessage("Waiting for threads to complete...", "debug.log");
        joinRequestThread.join();
        nodeThread.join();
        logMessage("All threads completed. Shutting down.", "debug.log");
    } catch (const std::exception& e) {
        logMessage("Error: " + std::string(e.what()), "error.log");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

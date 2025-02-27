#include "acting_utils.h"
#include "audit.h"
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
#include <thread> // Required for std::this_thread::sleep_for
#include <chrono> // Required for std::chrono::seconds
#include <algorithm>
#include <cctype>




// Helper Mutex for Logging
static std::mutex logMutex;
std::unordered_map<std::string, Reassembly> reassemblyMap;  
std::mutex reassemblyMutex;

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


// -------------------------------------------------------------------------
// Filter out "Audit" entries from a local JSON log. Return entire JSON as string.
std::string filterOutAuditEntries(const std::string &originalLogFilePath,
                                  const std::string &logFile) 
{
    std::ifstream inFile(originalLogFilePath);
    if (!inFile.is_open()) {
        logMessage("Error: Unable to open local JSON log: " + originalLogFilePath, logFile);
        return "";
    }
    json fullLog;
    try {
        inFile >> fullLog; // parse entire array
    } catch (...) {
        logMessage("Error: JSON parsing failed while filtering logs.", logFile);
        return "";
    }

    // Build new array excluding "Audit" states
    json filtered = json::array();
    for (auto &entry : fullLog) {
        if (!entry.contains("content") || !entry["content"].contains("state")) {
            // Missing content/state -> keep by default
            filtered.push_back(entry);
            continue;
        }
        std::string stateVal = entry["content"]["state"].get<std::string>();
        if (stateVal != "Audit") {
            filtered.push_back(entry);
        }
    }

    // Return as string
    std::ostringstream oss;
    oss << filtered;
    return oss.str();
}

// -------------------------------------------------------------------------
// Send a big JSON in multiple segments: "Header:LogSegment|LogID:...|Index:i|Count:n|Data:<partial>"
void sendLogResponseInChunks(int sockFd,
                             const sockaddr_in &destAddr,
                             const std::string &logId,
                             const std::string &fullJson,
                             const std::string &logFile)
{
    // Split fullJson into segments
    size_t totalLen = fullJson.size();
    size_t totalChunks = (totalLen + LOG_SEGMENT_SIZE - 1) / LOG_SEGMENT_SIZE; // ceiling

    for (size_t i = 0; i < totalChunks; i++) {
        size_t startPos = i * LOG_SEGMENT_SIZE;
        size_t len = std::min(LOG_SEGMENT_SIZE, totalLen - startPos);
        std::string segment = fullJson.substr(startPos, len);

        // Construct the chunk message
        // Example: "Header:LogSegment|LogID:<logId>|Index:<i>|Count:<totalChunks>|Data:<segment>"
        std::ostringstream oss;
        oss << "Header:LogSegment|LogID:" << logId
            << "|Index:" << i
            << "|Count:" << totalChunks
            << "|Data:" << segment;

        std::string chunkMsg = oss.str();
        sendto(sockFd, chunkMsg.c_str(), chunkMsg.size(), 0,
               (struct sockaddr *)&destAddr, sizeof(destAddr));
        logMessage("Sent LogSegment index " + std::to_string(i) + " of "
                   + std::to_string(totalChunks) + " to "
                   + inet_ntoa(destAddr.sin_addr) + ":"
                   + std::to_string(ntohs(destAddr.sin_port)), logFile);
    }
}

// -------------------------------------------------------------------------
// Once all segments are reassembled, parse the full JSON and audit it
void finalizeLogReassembly(const std::string &logId,
                           const NodeConfig &config)
{
    std::string fullJson;
    {
        std::lock_guard<std::mutex> lock(reassemblyMutex);
        auto &r = reassemblyMap[logId];
        // Concatenate
        for (auto &seg : r.segments) {
            fullJson += seg;
        }
        // Remove from reassembly map
        reassemblyMap.erase(logId);
    }

    // Write to a temp file to use existing 'auditLog(...)' function
    std::string tempPartnerLog = "logs/temp_partner_audit_" + config.nodeId + ".json";
    {
        std::ofstream ofs(tempPartnerLog);
        if (!ofs.is_open()) {
            logMessage("Error: Unable to write reassembled log " + logId, config.logFile);
            return;
        }
        ofs << fullJson;
    }

    logMessage("Node " + config.nodeId + " reassembled partner log " + logId
               + " into " + tempPartnerLog, config.logFile);

    // Now we parse & audit
    try {
        auditLog(tempPartnerLog);
    } catch (...) {
        logMessage("Error: Exception occurred while auditing reassembled log " + logId, config.logFile);
    }
   //std::remove(tempPartnerLog.c_str());
}

// -------------------------------------------------------------------------
// Handle a LogSegment chunk: store in reassembly buffer. If complete, finalize.
void handleIncomingLogSegment(const std::string &message,
                              const sockaddr_in &senderAddr,
                              const NodeConfig &config)
{
    // Example chunk: "Header:LogSegment|LogID:xyz|Index:2|Count:5|Data:<data>"
    std::string logId = extractField(message, "LogID");
    std::string indexStr = extractField(message, "Index");
    std::string countStr = extractField(message, "Count");
    std::string dataSegment = extractField(message, "Data");

    if (logId.empty() || indexStr.empty() || countStr.empty()) {
        logMessage("Error: Incomplete LogSegment fields, ignoring message.", config.logFile);
        return;
    }

    size_t idx = std::stoul(indexStr);
    size_t total = std::stoul(countStr);

    std::lock_guard<std::mutex> lock(reassemblyMutex);
    // If new or changed total, init
    if (reassemblyMap.find(logId) == reassemblyMap.end()) {
        Reassembly reasm;
        reasm.totalChunks = total;
        reasm.chunksReceived = 0;
        reasm.segments.resize(total);
        reassemblyMap[logId] = reasm;
        logMessage("Node " + config.nodeId + " started reassembling log " + logId
                   + " (total chunks " + std::to_string(total) + ")", config.logFile);
    }

    auto &r = reassemblyMap[logId];
    // Basic check
    if (idx >= r.totalChunks) {
        logMessage("Error: Incoming segment idx " + std::to_string(idx)
                   + " >= totalChunks " + std::to_string(r.totalChunks)
                   + ", ignoring.", config.logFile);
        return;
    }
    if (r.segments[idx].empty()) {
        // only count it if we haven't set it before
        r.segments[idx] = dataSegment;
        r.chunksReceived++;
        logMessage("Node " + config.nodeId + " received chunk " + std::to_string(idx)
                   + " of " + std::to_string(r.totalChunks)
                   + " for log " + logId, config.logFile);
    }

    finalizeLogReassembly(logId, config);

    // If all chunks arrived
    //if (r.chunksReceived == r.totalChunks) {
        // finalize reassembly
        //finalizeLogReassembly(logId, config);
    //}
}

// -------------------------------------------------------------------------
// Respond to "Header:Audit|Requester:<nodeId>" by chunking a filtered log

void handleIncomingAuditRequest(int sockFd,
                                const sockaddr_in &senderAddr,
                                const NodeConfig &config)
{
    // Node's own JSON log
    std::string localLogFilePath = "/Users/lhassini/Desktop/PHD/Gossip_Protocols/AcTing/ansible/playbooks/logs/"
        "traffic_" + config.nodeId + "_" + std::to_string(config.port) + "_log.json";

    // Filter out "Audit" entries
    std::string filteredLog = filterOutAuditEntries(localLogFilePath, config.logFile);
    if (filteredLog.empty()) {
        // If no data or error, let's still send empty log in chunked form
        filteredLog = "[]";
    }

    // We define a unique LogID for reassembly on the partner side
    // For example: nodeX_<time>
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::string logId = config.nodeId + "_" + std::to_string(now);

    // Send the filtered JSON in multiple segments
    sendLogResponseInChunks(sockFd, senderAddr, logId, filteredLog, config.logFile);

    logMessage("Node " + config.nodeId + " responded to audit request with logId "
               + logId, config.logFile);
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

void appendToSentMessages(const std::string &nodeId, const std::string &msg) {
    std::string filePath = "/home/Project/ansible/logs/" + nodeId + "_sentMessages";
    std::ofstream outFile(filePath, std::ios::app);
    if (outFile) {
        // Remove spaces from the message:
        std::string msgNoSpaces = msg;
        msgNoSpaces.erase(std::remove(msgNoSpaces.begin(), msgNoSpaces.end(), ' '), msgNoSpaces.end());
        outFile << msgNoSpaces;
    }
}

void sendMessageWithLog(int sockFd, const std::string &msg, const sockaddr_in &dest, 
                        const std::string &logFile, const std::string &nodeId) {
    appendToSentMessages(nodeId, msg);
    sendMessage(sockFd, msg, dest, logFile);
}
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
#include <fcntl.h> 
#include <poll.h>
#include <cstdio>   
#include <cstdlib>  
#include <openssl/sha.h>

#include "acting_protocol/acting_utils.h"
#include "acting_protocol/membership.h"
#include "acting_protocol/partnerships.h"
#include "acting_protocol/audit.h"

#define CHUNK_SIZE 1024 // Size of each UDP chunk
#define GOSSIP_PERIOD 6000 // milliseconds
#define SIMULATION_TIME 240000 // milliseconds
#define MAX_PARTNERS 2 // Maximum nodes to send data in each gossip round
#define PARTNERSHIP_PERIOD 5 // Partnership update period in rounds
#define AUDIT_PROBABILITY_PERCENT 30 // Probability of auditing in percentage
enum class State { PROPOSE, PUSH, PULL }; // State Enum
const size_t MAX_UDP_PAYLOAD = 1200; // Maximum safe UDP payload size in bytes
const std::string log_dir = "/home/Project/ansible/logs";


// Global Variables
std::mutex logMutex;
std::atomic<bool> running{true};
std::condition_variable readyCV;
std::mutex readyMutex;
std::atomic<bool> allReady{false};
std::condition_variable cv;      // Condition variable for synchronization
std::mutex cvMutex;              // Mutex for the condition variable
std::atomic<bool> ready{false};  // Atomic boolean for readiness
std::unordered_map<std::string, int> noProposeCounter;
std::unordered_map<std::string, bool> hasProposed;

// -------------------------------------------------------------------------
std::unordered_map<std::string, std::string> chunkStorage; 
std::unordered_set<std::string> ownedChunks;
bool loadedAlready = false;

std::unordered_set<std::string> globalSuspectedNodes;

std::mutex suspectedNodesMutex;

// Define the AuditCounts structure.
struct AuditCounts {
    int proposeCount = 0;
    int ownedCount = 0;
};

std::vector<std::pair<sockaddr_in, std::string>> timedReceiveAll(
    int sockFd,
    const std::unordered_map<std::string, NodeInfo>& nodeDatabase,
    const std::string &logFile,
    int maxMillis = 300)
{
    std::vector<std::pair<sockaddr_in, std::string>> results;
    auto start = std::chrono::steady_clock::now();
    char buffer[CHUNK_SIZE];
    sockaddr_in senderAddr{};
    socklen_t senderLen = sizeof(senderAddr);

    while (true) {
        auto diff = std::chrono::steady_clock::now() - start;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(diff).count() > maxMillis)
            break;
        int n = recvfrom(sockFd, buffer, CHUNK_SIZE - 1, MSG_DONTWAIT,
                         reinterpret_cast<struct sockaddr*>(&senderAddr), &senderLen);
        if (n <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        buffer[n] = '\0';
        results.push_back({senderAddr, std::string(buffer, n)});
    }
    return results;
}



std::string computeHash(const std::unordered_map<std::string, std::string>& chunks) {
    // Get the keys and sort them for deterministic ordering.
    std::vector<std::string> keys;
    for (const auto &pair : chunks) {
        keys.push_back(pair.first);
    }
    std::sort(keys.begin(), keys.end());
    
    // Concatenate the contents in sorted order.
    std::string concatenated;
    for (const auto &key : keys) {
        concatenated += chunks.at(key);
    }
    
    // Compute SHA-256 hash.
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(concatenated.c_str()),
           concatenated.size(), hash);

    // Convert hash to a hex string.
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}


struct pcap_hdr_t {
    uint32_t magic_number;   // 0xa1b2c3d4 for big-endian
    uint16_t version_major;  // usually 2
    uint16_t version_minor;  // usually 4
    int32_t  thiszone;       // GMT to local correction, usually 0
    uint32_t sigfigs;        // accuracy of timestamps, usually 0
    uint32_t snaplen;        // maximum length of captured packets, e.g. 65535
    uint32_t network;        // data link type (e.g., 113 for Linux cooked capture)
};

void reinitializePCAPFile(const std::string &pcapFile, const NodeConfig &config) {
    // Prepare a PCAP header. We force network byte order (big-endian)
    // so that EagleEye correctly interprets the header.
    pcap_hdr_t header;
    header.magic_number   = htonl(0xa1b2c3d4);  // big-endian magic
    header.version_major  = htons(2);
    header.version_minor  = htons(4);
    header.thiszone       = 0;
    header.sigfigs        = 0;
    header.snaplen        = htonl(65535);
    header.network        = htonl(113); // Linux cooked capture (0x71)
    
    std::ofstream ofs(pcapFile, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!ofs) {
        std::cerr << "WARNING: Could not reinitialize PCAP file: " << pcapFile << std::endl;
        return;
    }
    ofs.write(reinterpret_cast<const char*>(&header), sizeof(header));
    ofs.close();
    logMessage("Reinitialized PCAP file (header written in big-endian): " + pcapFile, config.logFile);
}
//--------------------------------
void synchronizeRound(int roundNumber) {
    // Wait a fixed time to allow all nodes to reach this point.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

void overloadNodeLoop(
    int roundNumber,
    const NodeConfig &config,
    const std::unordered_map<std::string, NodeInfo> &nodeDatabase,
    bool isSourceNode,
    const std::vector<std::string> &partners)
{
    // Synchronize round start across all nodes.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Bind our socket (reuse the same port).
    int sockFd = createAndBindSocket(config.port, config.logFile);
    if (sockFd < 0) {
        logMessage("Overload Node: Error binding socket on port " + std::to_string(config.port), config.logFile);
        return;
    }
    logMessage("Overload Node " + config.nodeId + " bound to port " + std::to_string(config.port) +
               " for overload round " + std::to_string(roundNumber), config.logFile);

    // If source, load data if not already loaded.
    if (isSourceNode && !loadedAlready) {
        loadedAlready = true;
        logMessage("Overload Node " + config.nodeId + " is SOURCE. Loading data from " + config.dataFile, config.logFile);
        std::vector<std::string> fileChunks = readDataChunks(config.dataFile);
        for (size_t i = 0; i < fileChunks.size(); i++) {
            std::string cid = std::to_string(i);
            ownedChunks.insert(cid);
            chunkStorage[cid] = fileChunks[i];
        }
        logMessage("Overload Node " + config.nodeId + " loaded " + std::to_string(fileChunks.size()) + " chunks.", config.logFile);
    }

    // Log current owned chunks.
    {
        std::ostringstream oss;
        oss << "Overload Node " << config.nodeId << " owns " << ownedChunks.size()
            << " chunk(s) before overload round " << roundNumber << ": [";
        bool first = true;
        for (const auto &cid : ownedChunks) {
            if (!first) oss << ", ";
            first = false;
            oss << cid;
        }
        oss << "]";
        logMessage(oss.str(), config.logFile);
    }

    // Duration for this overload round.
    auto roundStart = std::chrono::steady_clock::now();
    const auto roundDuration = std::chrono::milliseconds(2000);
    int sentCount = 0;
    int recvCount = 0;

    // Aggressively send messages in a tight loop until the round duration elapses.
    while (std::chrono::steady_clock::now() - roundStart < roundDuration) {
        // For each partner, send several duplicate proposals for each owned chunk.
        for (const auto &pid : partners) {
            auto it = nodeDatabase.find(pid);
            if (it == nodeDatabase.end()) {
                logMessage("Overload Node: Error - partner " + pid + " not found in DB", config.logFile);
                continue;
            }
            const NodeInfo &pinfo = it->second;
            sockaddr_in partnerAddr{};
            partnerAddr.sin_family = AF_INET;
            partnerAddr.sin_port = htons(pinfo.port);
            inet_pton(AF_INET, pinfo.ipAddress.c_str(), &partnerAddr.sin_addr);
            // Send duplicate proposals (e.g., 10 duplicates) per partner per iteration.
            for (int dup = 0; dup < 10; dup++) {
                for (const auto &cid : ownedChunks) {
                    std::string proposeMsg = "Header:Propose|Seq:" + cid;
                    sendMessageWithLog(sockFd, proposeMsg, partnerAddr, config.logFile, config.nodeId);
                    sentCount++;
                }
            }
        }
        // Also, process any incoming messages with a short timeout.
        auto messages = timedReceiveAll(sockFd, nodeDatabase, config.logFile, 20);
        if (!messages.empty()) {
            for (const auto &msgPair : messages) {
                recvCount++;
                const sockaddr_in &senderAddr = msgPair.first;
                const std::string &msg = msgPair.second;
                int senderPort = ntohs(senderAddr.sin_port);
                std::string partnerId = getNodeIdFromPort(senderPort, nodeDatabase);
                logMessage("Overload round " + std::to_string(roundNumber) +
                           " received from " + partnerId + ": " + msg, config.logFile);
                // Respond to PULL requests, for example.
                if (msg.find("Header:Pull") != std::string::npos) {
                    std::string seq = extractField(msg, "Seq");
                    if (!seq.empty() && (ownedChunks.find(seq) != ownedChunks.end())) {
                        std::string pushMsg = "Header:Push|Seq:" + seq + "|Raw:" + chunkStorage[seq];
                        sendMessageWithLog(sockFd, pushMsg, senderAddr, config.logFile, config.nodeId);
                        sentCount++;
                        logMessage("Overload round " + std::to_string(roundNumber) +
                                   ": Sent PUSH for chunk " + seq + " to " + partnerId, config.logFile);
                    }
                }
            }
        }
        // Minimal sleep to yield control (but keep loop tight).
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    logMessage("Overload Node " + config.nodeId + " sent " + std::to_string(sentCount) + " messages, received " +
               std::to_string(recvCount) + " messages in overload round " + std::to_string(roundNumber), config.logFile);

    // Log final owned chunks.
    {
        std::ostringstream oss;
        oss << "Overload Node " << config.nodeId << " final ownership after round " << roundNumber << ": [";
        bool first = true;
        for (const auto &cid : ownedChunks) {
            if (!first) oss << ", ";
            first = false;
            oss << cid;
        }
        oss << "]";
        logMessage(oss.str(), config.logFile);
    }

    // Close the socket.
    close(sockFd);
    logMessage("Overload Node " + config.nodeId + " finished overload round " +
               std::to_string(roundNumber) + " and socket closed.", config.logFile);
}


// Structure for storing partner audit responses.
struct AuditResponseParts {
    int expectedTotal = -1;
    std::unordered_map<int, std::string> parts;
};

// Structure for holding fragments from one sender.
struct FragmentBuffer {
    int total = 0;
    std::unordered_map<int, std::string> fragments;
};

// Helper: Generate a key string from sender's IP and port.
std::string ipPortKey(const sockaddr_in &addr) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN);
    int port = ntohs(addr.sin_port);
    return std::string(ip) + ":" + std::to_string(port);
}

// Helper: Fragment and send a long message.
void sendLongMessage(int sock, const std::string &message, const sockaddr_in &dest, const std::string &logFil, const std::string &nodeId) {
    size_t totalSize = message.size();
    size_t fragmentSize = MAX_UDP_PAYLOAD - 50; // reserve space for a simple fragment header
    size_t numFragments = (totalSize + fragmentSize - 1) / fragmentSize;
    
    for (size_t i = 0; i < numFragments; i++) {
        std::ostringstream oss;
        // Header for each fragment: "FRAG|<fragNum>/<totalFragments>|"
        oss << "FRAG|" << (i + 1) << "/" << numFragments << "|";
        // Append the fragment content.
        oss << message.substr(i * fragmentSize, fragmentSize);
        std::string frag = oss.str();
        // Note: Remove the assignment; sendMessage returns void.
        sendMessageWithLog(sock, frag, dest, logFil, nodeId);
    }
}

//-------------------------------------------------------------------------
std::unordered_map<std::string, AuditCounts> auditLoopOptimized(
    const std::vector<std::string>& auditPartners,
    const NodeConfig &config,
    const std::unordered_map<std::string, NodeInfo> &nodeDatabase,
    const std::string &localAuditFile,
    const std::string &pcapFile)
{
    int auditSock = createAndBindSocket(config.port, config.logFile);
    if (auditSock < 0) {
        logMessage("ERROR: Unable to bind audit socket on port " + std::to_string(config.port), config.logFile);
        return {};
    }
    logMessage("Audit socket bound on port " + std::to_string(config.port), config.logFile);
    logMessage("Audit loop using JSON file: " + localAuditFile, config.logFile);
    logMessage("Using PCAP file: " + pcapFile, config.logFile);

    {
        std::ostringstream cmdStream;
        cmdStream << "cd /home/Project/ansible && python3 AuditLogs/EagleEye.py --input-file " << pcapFile;
        std::string pcapCmd = cmdStream.str();
        logMessage("Converting PCAP to JSON: " + pcapCmd, config.logFile);
        int ret = system(pcapCmd.c_str());
        if (ret != 0)
            logMessage("ERROR: PCAP conversion failed with code " + std::to_string(ret), config.logFile);
    }

    std::ifstream ifs(localAuditFile);
    std::string fileContent((std::istreambuf_iterator<char>(ifs)),
                             std::istreambuf_iterator<char>());
    ifs.close();
    if (fileContent.empty())
        fileContent = "[]";
    nlohmann::json myAuditJson;
    try {
        myAuditJson = nlohmann::json::parse(fileContent);
        if (!myAuditJson.is_array()) {
            logMessage("Local audit log not an array; forcing empty array.", config.logFile);
            myAuditJson = nlohmann::json::array();
        }
    } catch (...) {
        logMessage("Error parsing local audit log; forcing empty array.", config.logFile);
        myAuditJson = nlohmann::json::array();
    }
    int myTotal = myAuditJson.size();
    logMessage("Loaded audit log with " + std::to_string(myTotal) + " entr" +
               (myTotal == 1 ? "y" : "ies") + ".", config.logFile);

    // Broadcast our audit log.
    for (const auto &pid : auditPartners) {
        auto it = nodeDatabase.find(pid);
        if (it != nodeDatabase.end()) {
            sockaddr_in partnerAddr{};
            partnerAddr.sin_family = AF_INET;
            partnerAddr.sin_port = htons(it->second.port);
            inet_pton(AF_INET, it->second.ipAddress.c_str(), &partnerAddr.sin_addr);
            if (myTotal > 0) {
                for (int i = 0; i < myTotal; i++) {
                    std::ostringstream outMsg;
                    outMsg << "Header:AuditLogEntry|" << config.nodeId << "|"
                           << (i + 1) << "/" << myTotal << "|" << myAuditJson[i].dump();
                    std::string msg = outMsg.str();
                    if (msg.size() > MAX_UDP_PAYLOAD)
                        sendLongMessage(auditSock, msg, partnerAddr, config.logFile, config.nodeId);
                    else
                        sendMessageWithLog(auditSock, msg, partnerAddr, config.logFile, config.nodeId);
                }
            } else {
                sendMessageWithLog(auditSock, "Header:AuditLogEmpty|" + config.nodeId, partnerAddr, config.logFile, config.nodeId);
            }
            sendMessageWithLog(auditSock, "Header:AuditLogEnd|" + config.nodeId, partnerAddr, config.logFile, config.nodeId);
            logMessage("Broadcasted audit log to partner " + pid, config.logFile);
        }
    }

    // Set up to collect responses.
    const int passiveTimeMs = 10000, activeTimeMs = 10000, finalDrainMs = 2000, pollTimeoutMs = 20;
    std::unordered_map<std::string, AuditResponseParts> partnerResponses;
    std::unordered_map<std::string, bool> partnerComplete;
    for (const auto &pid : auditPartners) {
        partnerResponses[pid] = AuditResponseParts();
        partnerComplete[pid] = false;
    }
    std::unordered_map<std::string, FragmentBuffer> fragBuffers;
    char recvBuffer[8192];
    struct pollfd pfd;
    pfd.fd = auditSock;
    pfd.events = POLLIN;

    auto processFullMessage = [&](const std::string &msg) {
        if (msg.find("Header:AuditLogEntry|") == 0) {
            size_t pos1 = msg.find("|");
            size_t pos2 = msg.find("|", pos1 + 1);
            size_t pos3 = msg.find("|", pos2 + 1);
            if (pos1 != std::string::npos && pos2 != std::string::npos && pos3 != std::string::npos) {
                std::string partnerId = msg.substr(pos1 + 1, pos2 - pos1 - 1);
                std::string seqInfo = msg.substr(pos2 + 1, pos3 - pos2 - 1);
                std::string entryJsonStr = msg.substr(pos3 + 1);
                size_t slashPos = seqInfo.find("/");
                if (slashPos != std::string::npos) {
                    try {
                        int seq = std::stoi(seqInfo.substr(0, slashPos));
                        int total = std::stoi(seqInfo.substr(slashPos + 1));
                        partnerResponses[partnerId].expectedTotal = total;
                        partnerResponses[partnerId].parts[seq] = entryJsonStr;
                    } catch (...) {
                        logMessage("Error parsing audit log entry: " + msg, config.logFile);
                    }
                }
            }
        }
        else if (msg.find("Header:AuditLogEnd|") == 0) {
            std::string partnerId = msg.substr(msg.find("|") + 1);
            partnerComplete[partnerId] = true;
            logMessage("Received audit log end marker from " + partnerId, config.logFile);
        }
        else if (msg.find("Header:AuditLogEmpty|") == 0) {
            std::string partnerId = msg.substr(msg.find("|") + 1);
            partnerResponses[partnerId].expectedTotal = 0;
            partnerComplete[partnerId] = true;
            logMessage("Received empty audit log marker from " + partnerId, config.logFile);
        }
    };

    auto collectMessages = [&](int durationMs) {
        auto startTime = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - startTime < std::chrono::milliseconds(durationMs)) {
            int ret = poll(&pfd, 1, pollTimeoutMs);
            if (ret > 0 && (pfd.revents & POLLIN)) {
                sockaddr_in sender;
                socklen_t senderLen = sizeof(sender);
                int bytes = recvfrom(auditSock, recvBuffer, sizeof(recvBuffer) - 1, 0,
                                      reinterpret_cast<struct sockaddr*>(&sender), &senderLen);
                if (bytes > 0) {
                    recvBuffer[bytes] = '\0';
                    std::string msg(recvBuffer);
                    if (msg.find("FRAG|") == 0) {
                        size_t p1 = msg.find("|");
                        size_t p2 = msg.find("/", p1 + 1);
                        size_t p3 = msg.find("|", p2 + 1);
                        if (p1 != std::string::npos && p2 != std::string::npos && p3 != std::string::npos) {
                            int fragNum = std::stoi(msg.substr(p1 + 1, p2 - p1 - 1));
                            int fragTotal = std::stoi(msg.substr(p2 + 1, p3 - p2 - 1));
                            std::string fragPayload = msg.substr(p3 + 1);
                            std::string key = ipPortKey(sender);
                            FragmentBuffer &fb = fragBuffers[key];
                            fb.total = fragTotal;
                            fb.fragments[fragNum] = fragPayload;
                            if ((int)fb.fragments.size() == fragTotal) {
                                std::ostringstream oss;
                                bool allPresent = true;
                                for (int i = 1; i <= fragTotal; i++) {
                                    if (fb.fragments.find(i) == fb.fragments.end()) {
                                        allPresent = false;
                                        logMessage("Missing fragment " + std::to_string(i) + " from " + key, config.logFile);
                                        break;
                                    }
                                    oss << fb.fragments[i];
                                }
                                if (allPresent) {
                                    processFullMessage(oss.str());
                                    fragBuffers.erase(key);
                                }
                            }
                        }
                    } else {
                        processFullMessage(msg);
                    }
                }
            }
        }
    };

    // Collection phases.
    collectMessages(passiveTimeMs);
    for (const auto &pid : auditPartners) {
        if (!partnerComplete[pid]) {
            auto it = nodeDatabase.find(pid);
            if (it != nodeDatabase.end()) {
                sockaddr_in partnerAddr{};
                partnerAddr.sin_family = AF_INET;
                partnerAddr.sin_port = htons(it->second.port);
                inet_pton(AF_INET, it->second.ipAddress.c_str(), &partnerAddr.sin_addr);
                sendMessage(auditSock, "Header:AuditRequest", partnerAddr, config.logFile);
                logMessage("Sent active audit request to " + pid, config.logFile);
            }
        }
    }
    collectMessages(activeTimeMs);
    std::this_thread::sleep_for(std::chrono::milliseconds(finalDrainMs));
    collectMessages(500);
    for (const auto &pid : auditPartners) {
        if (!partnerComplete[pid]) {
            partnerComplete[pid] = true;
            logMessage("Force marking " + pid + " as communicative (default empty log).", config.logFile);
        }
    }

    // Phase 8: Reassemble responses and count the number of "Propose" entries and extract the reported ownership.
    std::unordered_map<std::string, AuditCounts> partnerAuditCounts;
    for (const auto &pid : auditPartners) {
        AuditCounts counts;
        int reportedOwned = 0;
        nlohmann::json combinedLog = nlohmann::json::array();
        auto it = partnerResponses.find(pid);
        if (it == partnerResponses.end() || it->second.expectedTotal < 0) {
            logMessage("No expected entry count from partner " + pid + "; using empty log.", config.logFile);
        } else {
            int expected = it->second.expectedTotal;
            for (int seq = 1; seq <= expected; seq++) {
                if (it->second.parts.find(seq) != it->second.parts.end()) {
                    try {
                        nlohmann::json entry = nlohmann::json::parse(it->second.parts.at(seq));
                        combinedLog.push_back(entry);
                        if (entry.contains("content") && entry["content"].contains("state")) {
                            std::string state = entry["content"]["state"];
                            if (state == "Propose")
                                counts.proposeCount++;
                            else if (state == "Ownership") {
                                if (entry["content"].contains("owned"))
                                    reportedOwned = entry["content"]["owned"].get<int>();
                            }
                        }
                    } catch (const std::exception &e) {
                        logMessage("Error parsing entry " + std::to_string(seq) + " from " + pid + ": " + e.what(), config.logFile);
                        combinedLog.push_back({ {"error", "failed to parse entry"} });
                    }
                } else {
                    logMessage("Partner " + pid + " missing entry " + std::to_string(seq) + "; inserting default.", config.logFile);
                    combinedLog.push_back({ {"error", "missing entry"} });
                }
            }
        }
        counts.ownedCount = reportedOwned;
        partnerAuditCounts[pid] = counts;

        std::string tempAuditFile = "/tmp/audit_combined_" + pid + ".json";
        std::ofstream ofs(tempAuditFile);
        if (ofs.is_open()) {
            ofs << combinedLog.dump();
            ofs.close();
            logMessage("Combined audit JSON for " + pid + " written to " + tempAuditFile, config.logFile);
        } else {
            logMessage("ERROR: Unable to write combined audit JSON to " + tempAuditFile, config.logFile);
        }
        int auditResult = auditLog(tempAuditFile, std::unordered_set<std::string>());
        if (auditResult != 0) {
            logMessage("Audit verification FAILED for " + pid, config.logFile);

            // --- Blame functionality ---
            std::string blameFile = log_dir + "/blame_log.txt";
            std::ofstream blameOfs(blameFile, std::ios::app);
            if (blameOfs.is_open()) {
                blameOfs << "[" << getCurrentTime() << "] Blame: Node " << pid
                         << " failed audit verification due to free‑rider behavior." << std::endl;
                blameOfs.close();
            }
            // Broadcast blame message to all audit partners (except the blamed node).
            for (const auto &partner : auditPartners) {
                if (partner != pid) {
                    auto nit = nodeDatabase.find(partner);
                    if (nit != nodeDatabase.end()) {
                        sockaddr_in partnerAddr{};
                        partnerAddr.sin_family = AF_INET;
                        partnerAddr.sin_port = htons(nit->second.port);
                        inet_pton(AF_INET, nit->second.ipAddress.c_str(), &partnerAddr.sin_addr);
                        std::string blameMsg = "Header:Blame|" + pid + "|FreeRider detected";
                        sendMessageWithLog(auditSock, blameMsg, partnerAddr, config.logFile, config.nodeId);
                    }
                }
            }
            // Add the blamed node to the global suspected list.
            //globalSuspectedNodes.insert(pid);
        } else {
            logMessage("Audit verification PASSED for " + pid, config.logFile);
        }
        std::remove(tempAuditFile.c_str());
    }

    close(auditSock);
    logMessage("Audit cycle completed. Exiting audit loop.", config.logFile);
    return partnerAuditCounts;
}

// ---------------------------------------------------------------------------
// Main function.
int main(int argc, char* argv[]) {
    if (argc != 3 || std::string(argv[1]) != "--config") {
        std::cerr << "Usage: " << argv[0] << " --config <config_file_path>" << std::endl;
        return EXIT_FAILURE;
    }
    try {
        logMessage("Parsing configuration file...", "debug.log");
        NodeConfig config = parseConfigFile(argv[2]);
        logMessage("Configuration parsed successfully: Node ID = " + config.nodeId, "debug.log");

        logMessage("Parsing hosts file...", "debug.log");
        auto nodeDatabase = parseHostsFile("/home/Project/ansible/inventory/hosts.ini");
        logMessage("Hosts file parsed successfully.", "debug.log");
        for (const auto &entry : nodeDatabase)
            logMessage("NodeID: " + entry.first + ", IP: " + entry.second.ipAddress +
                       ", Port: " + std::to_string(entry.second.port), "debug.log");

        // Add current node to membership.
        logMessage("Adding current node to membership...", "debug.log");
        if (!addNode({config.nodeId, nodeDatabase[config.nodeId].ipAddress, config.port}, config.logFile))
            logMessage("Node already exists in membership: " + config.nodeId, config.logFile);
        else
            logMessage("Node added to membership successfully: " + config.nodeId, config.logFile);

        // Launch join request thread.
        logMessage("Starting join request thread...", "debug.log");
        std::thread joinRequestThread([&]() {
            try {
                logMessage("Join request thread started.", config.logFile);
                handleJoinRequest(NodeInfo{config.nodeId, nodeDatabase[config.nodeId].ipAddress, config.port},
                                  config.sourceNode, config.logFile);
                logMessage("Join request completed.", config.logFile);
            } catch (const std::exception &e) {
                logMessage("Error in join request thread: " + std::string(e.what()), config.logFile);
            }
        });
        joinRequestThread.join();
        logMessage("Join request thread joined; membership established.", "debug.log");

        bool isSourceNode = (config.nodeId == config.sourceNode);
        logMessage("Node " + config.nodeId + " is " + (isSourceNode ? "SOURCE" : "NON-SOURCE"), config.logFile);

        // Persistent PCAP file.
        std::string pcapFile = log_dir + "/traffic_" + config.nodeId + "_" + std::to_string(config.port) + ".pcap";
        const auto simulationStart = std::chrono::steady_clock::now();
        const std::chrono::minutes simulationDuration(30);
        int roundNumber = 1;

        // Initialize free‑rider detection maps.
        for (const auto &entry : nodeDatabase) {
            noProposeCounter[entry.first] = 0;
            hasProposed[entry.first] = false;
        }

        // Main simulation loop.
        while (std::chrono::steady_clock::now() - simulationStart < simulationDuration) {
            // Every cycle, select partnerships.
            std::unordered_map<std::string, NodeInfo> filteredDatabase;
            {
                std::lock_guard<std::mutex> lock(suspectedNodesMutex);
                for (const auto &entry : nodeDatabase) {
                    if (globalSuspectedNodes.find(entry.first) == globalSuspectedNodes.end())
                        filteredDatabase.insert(entry);
                }
            }
            PartnershipManager pm(config.nodeId, MAX_PARTNERS, PARTNERSHIP_PERIOD, config.logFile);
            pm.updatePartnerships(roundNumber, filteredDatabase);
            auto partnersSet = pm.getCurrentPartners();
            std::vector<std::string> currentPartners(partnersSet.begin(), partnersSet.end());
            {
                std::ostringstream oss;
                oss << "Round " << roundNumber << ": Selected partners: ";
                for (const auto &pid : currentPartners)
                    oss << pid << " ";
                logMessage(oss.str(), config.logFile);
            }

            // If roundNumber mod 11 is not 0, do a dissemination round.
            if (roundNumber % 11 != 0) {
                logMessage("Round " + std::to_string(roundNumber) + ": Starting dissemination round.", config.logFile);
                overloadNodeLoop(roundNumber, config, nodeDatabase, isSourceNode, currentPartners);
                logMessage("Round " + std::to_string(roundNumber) + ": Dissemination round completed.", config.logFile);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            else {
                // On every 11th round, perform an audit cycle.
                std::ostringstream fnameStream;
                fnameStream << config.nodeId << "_" << config.port << "_round" << roundNumber;
                std::string jsonFile = log_dir + "/traffic_" + config.nodeId + "_" + std::to_string(config.port) + "_log.json";
                logMessage("Round " + std::to_string(roundNumber) + ": Starting audit cycle.", config.logFile);
                std::unordered_map<std::string, AuditCounts> roundAuditCounts =
                    auditLoopOptimized(currentPartners, config, nodeDatabase, jsonFile, pcapFile);

                // Update free‑rider counters.
                for (const auto &pid : currentPartners) {
                    auto it = roundAuditCounts.find(pid);
                    int proposeCount = (it != roundAuditCounts.end()) ? it->second.proposeCount : 0;
                    int ownedCount   = (it != roundAuditCounts.end()) ? it->second.ownedCount : 0;
                    if (ownedCount > 0 && proposeCount == 0)
                        noProposeCounter[pid]++;
                    else
                        noProposeCounter[pid] = 0;
                    if (noProposeCounter[pid] >= 10) {
                        logMessage("Free‑rider detected: " + pid + " owns " + std::to_string(ownedCount) +
                                   " chunks but did not propose in 10 consecutive rounds.", config.logFile);
                        globalSuspectedNodes.insert(pid);
                    }
                }
                logMessage("Round " + std::to_string(roundNumber) + ": Audit cycle completed.", config.logFile);

                // Cleanup: remove JSON file, clear and reinitialize PCAP file.
                if (remove(jsonFile.c_str()) != 0)
                    logMessage("WARNING: Failed to remove JSON file: " + jsonFile, config.logFile);
                else
                    logMessage("Removed JSON file: " + jsonFile, config.logFile);
                {
                    std::ofstream ofs(pcapFile, std::ios::trunc);
                    ofs.close();
                    logMessage("Cleared PCAP file: " + pcapFile, config.logFile);
                }
                reinitializePCAPFile(pcapFile, config);
            }

            roundNumber++;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        logMessage("Simulation complete. Shutting down.", "debug.log");
        running = false;
    }
    catch (const std::exception &e) {
        logMessage("Error: " + std::string(e.what()), "error.log");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
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
#include "acting_protocol/audit.h"

#define CHUNK_SIZE 1024 // Size of each UDP chunk
#define GOSSIP_PERIOD 6000 // milliseconds
#define SIMULATION_TIME 240000 // milliseconds
#define MAX_PARTNERS 5 // Maximum nodes to send data in each gossip round
#define PARTNERSHIP_PERIOD 5 // Partnership update period in rounds
#define AUDIT_PROBABILITY_PERCENT 30 // Probability of auditing in percentage
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

// -------------------------------------------------------------------------
std::unordered_map<std::string, std::string> chunkStorage; 
std::unordered_set<std::string> ownedChunks;
bool loadedAlready = false;

std::vector<std::pair<sockaddr_in, std::string>>

timedReceiveAll(int sockFd,
                const std::unordered_map<std::string, NodeInfo> &nodeDatabase,
                const std::string &logFile,
                int maxMillis = 300)
{
    std::vector<std::pair<sockaddr_in, std::string>> results;

    auto start = std::chrono::steady_clock::now();
    char buffer[CHUNK_SIZE];
    sockaddr_in senderAddr{};
    socklen_t senderLen = sizeof(senderAddr);

    while (true) {
        // Check time
        auto now = std::chrono::steady_clock::now();
        auto diffMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
        if (diffMs > maxMillis) {
            break; // done reading after the timeout
        }

        // Non-blocking recv
        int bytes = recvfrom(sockFd, buffer, CHUNK_SIZE - 1, MSG_DONTWAIT,
                             (struct sockaddr*)&senderAddr, &senderLen);
        if (bytes <= 0) {
            // no data right now, sleep a bit
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        buffer[bytes] = '\0';
        std::string msg(buffer, bytes);
        results.push_back({senderAddr, msg});
    }

    return results;
}


void nodeLoopOneRound(
    int roundNumber,
    const NodeConfig &config,
    const std::unordered_map<std::string, NodeInfo> &nodeDatabase,
    bool isSourceNode, const std::vector<std::string>& Partners)
{
    // 0) Create & bind a socket
    int sockFd = createAndBindSocket(config.port, config.logFile);
    if (sockFd < 0) {
        logMessage("Error: Could not bind socket on port " + std::to_string(config.port),
                   config.logFile);
        return;
    }
    logMessage("Node " + config.nodeId + " bound to port "
               + std::to_string(config.port) + " for round "
               + std::to_string(roundNumber),
               config.logFile);

    // 1) If source node & not loaded, load data from file
    if (isSourceNode && !loadedAlready) {
        loadedAlready = true;
        logMessage("Node " + config.nodeId + " is SOURCE. Loading data from "
                   + config.dataFile,
                   config.logFile);

        std::vector<std::string> fileChunks = readDataChunks(config.dataFile);
        for (size_t i = 0; i < fileChunks.size(); i++) {
            std::string cid = std::to_string(i);
            ownedChunks.insert(cid);
            chunkStorage[cid] = fileChunks[i];
        }
        logMessage("Node " + config.nodeId + " loaded "
                   + std::to_string(fileChunks.size()) + " chunks.",
                   config.logFile);
    }

    // 2) Set up Partnerships for this roundm
    //    (max 5 partners, period=3 is just an example)
    std::ostringstream oss;
    oss << "Using external partners: ";
    for (const auto &pid : Partners)
        oss << pid << " ";
    logMessage(oss.str(), config.logFile);

    // 3) Log the chunks we currently own
    {
        std::ostringstream oss;
        oss << "Node " << config.nodeId << " owns "
            << ownedChunks.size() << " chunk(s) before round "
            << roundNumber << ": [";
        bool first = true;
        for (auto &c : ownedChunks) {
            if (!first) oss << ", ";
            first = false;
            oss << c;
        }
        oss << "]";
        logMessage(oss.str(), config.logFile);
    }

    // We'll collect chunkIDs we need to pull in a map: partner -> set of chunkIDs
    std::unordered_map<std::string, std::unordered_set<std::string>> pendingPulls;

    try {
        // --------------- PHASE A: PROPOSE ---------------
        {
            logMessage("Node " + config.nodeId + " [STATE=PROPOSE]", config.logFile);

            // Send propose for each chunk we own to each partner
            for (auto &pid : Partners) {
                auto it = nodeDatabase.find(pid);
                if (it == nodeDatabase.end()) {
                    logMessage("Error: partner " + pid + " not in DB", config.logFile);
                    continue;
                }
                const NodeInfo &pinfo = it->second;
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port   = htons(pinfo.port);
                inet_pton(AF_INET, pinfo.ipAddress.c_str(), &addr.sin_addr);

                for (auto &cid : ownedChunks) {
                    std::string proposeMsg = "Header:Propose|Seq:" + cid
                                             + "|Raw:" + chunkStorage[cid];
                    sendMessage(sockFd, proposeMsg, addr, config.logFile);

                    std::ostringstream oss;
                    oss << "Node " << config.nodeId
                        << " => PROPOSE chunkId=" << cid
                        << " to " << pid;
                    logMessage(oss.str(), config.logFile);
                }
            }

            // Short receive to gather inbound messages after we propose
            // We might see Propose from others, or Pull from them (or Push).
            auto inbound = timedReceiveAll(sockFd, nodeDatabase, config.logFile, 400);
            for (auto &pair : inbound) {
                const sockaddr_in &senderAddr = pair.first;
                const std::string &msg        = pair.second;

                int senderPort = ntohs(senderAddr.sin_port);
                std::string partnerId = getNodeIdFromPort(senderPort, nodeDatabase);

                std::ostringstream oss;
                oss << "Node " << config.nodeId
                    << " (PROPOSE phase) got from " << partnerId
                    << " => " << msg;
                logMessage(oss.str(), config.logFile);

                // parse message
                if (msg.find("Header:Propose") != std::string::npos) {
                    // They propose a chunk => if we don't have it, we'll want to pull it
                    std::string seq = extractField(msg, "Seq");
                    if (!seq.empty() && !ownedChunks.count(seq)) {
                        pendingPulls[partnerId].insert(seq);
                    }
                }
                else if (msg.find("Header:Pull") != std::string::npos) {
                    // They want a chunk from us => we push if we have it
                    std::string seq = extractField(msg, "Seq");
                    if (!seq.empty() && ownedChunks.count(seq)) {
                        std::string pushMsg = "Header:Push|Seq:" + seq
                                              + "|Raw:" + chunkStorage[seq];
                        sendMessage(sockFd, pushMsg, senderAddr, config.logFile);

                        logMessage("Node " + config.nodeId
                                   + " => PUSH chunkId=" + seq
                                   + " to " + partnerId,
                                   config.logFile);
                    }
                }
                else if (msg.find("Header:Push") != std::string::npos) {
                    // We store the chunk if we don't already have it
                    std::string seq = extractField(msg, "Seq");
                    std::string raw = extractField(msg, "Raw");
                    if (!seq.empty() && !ownedChunks.count(seq)) {
                        ownedChunks.insert(seq);
                        chunkStorage[seq] = raw;

                        logMessage("Node " + config.nodeId
                                   + " STORED chunkId=" + seq
                                   + " from " + partnerId,
                                   config.logFile);
                    }
                }
            }
        }

        // --------------- PHASE B: PULL ---------------
        {
            logMessage("Node " + config.nodeId + " [STATE=PULL]", config.logFile);

            // 1) We might do a short read first to catch new Propose from others
            auto inbound = timedReceiveAll(sockFd, nodeDatabase, config.logFile, 400);
            for (auto &pair : inbound) {
                const sockaddr_in &senderAddr = pair.first;
                const std::string &msg        = pair.second;

                int senderPort = ntohs(senderAddr.sin_port);
                std::string partnerId = getNodeIdFromPort(senderPort, nodeDatabase);

                std::ostringstream oss;
                oss << "Node " << config.nodeId
                    << " (PULL phase, pre-pull read) from " << partnerId
                    << " => " << msg;
                logMessage(oss.str(), config.logFile);

                if (msg.find("Header:Propose") != std::string::npos) {
                    std::string seq = extractField(msg, "Seq");
                    if (!seq.empty() && !ownedChunks.count(seq)) {
                        // we want to pull it
                        pendingPulls[partnerId].insert(seq);
                    }
                }
                else if (msg.find("Header:Pull") != std::string::npos) {
                    std::string seq = extractField(msg, "Seq");
                    if (!seq.empty() && ownedChunks.count(seq)) {
                        // push
                        std::string pushMsg = "Header:Push|Seq:" + seq
                                              + "|Raw:" + chunkStorage[seq];
                        sendMessage(sockFd, pushMsg, senderAddr, config.logFile);

                        logMessage("Node " + config.nodeId
                                   + " => PUSH chunkId=" + seq
                                   + " to " + partnerId,
                                   config.logFile);
                    }
                }
                else if (msg.find("Header:Push") != std::string::npos) {
                    std::string seq = extractField(msg, "Seq");
                    std::string raw = extractField(msg, "Raw");
                    if (!seq.empty() && !ownedChunks.count(seq)) {
                        ownedChunks.insert(seq);
                        chunkStorage[seq] = raw;

                        logMessage("Node " + config.nodeId
                                   + " STORED chunkId=" + seq
                                   + " from " + partnerId,
                                   config.logFile);
                    }
                }
            }

            // 2) Now send all our Pull requests
            for (auto &kv : pendingPulls) {
                const std::string &pid = kv.first;
                const auto &seqs       = kv.second;

                auto it = nodeDatabase.find(pid);
                if (it == nodeDatabase.end()) {
                    logMessage("Error: partner " + pid + " not found in DB",
                               config.logFile);
                    continue;
                }
                const NodeInfo &pinfo = it->second;
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port   = htons(pinfo.port);
                inet_pton(AF_INET, pinfo.ipAddress.c_str(), &addr.sin_addr);

                for (auto &seq : seqs) {
                    std::string pullMsg = "Header:Pull|Seq:" + seq;
                    sendMessage(sockFd, pullMsg, addr, config.logFile);

                    std::ostringstream oss;
                    oss << "Node " << config.nodeId
                        << " => PULL chunkId=" << seq
                        << " from " << pid;
                    logMessage(oss.str(), config.logFile);
                }
            }

            // 3) Another short read for the immediate Push responses
            inbound = timedReceiveAll(sockFd, nodeDatabase, config.logFile, 400);
            for (auto &pair : inbound) {
                const sockaddr_in &senderAddr = pair.first;
                const std::string &msg        = pair.second;

                int senderPort = ntohs(senderAddr.sin_port);
                std::string partnerId = getNodeIdFromPort(senderPort, nodeDatabase);

                std::ostringstream oss;
                oss << "Node " << config.nodeId
                    << " (PULL phase, post-pull read) from " << partnerId
                    << " => " << msg;
                logMessage(oss.str(), config.logFile);

                if (msg.find("Header:Pull") != std::string::npos) {
                    std::string seq = extractField(msg, "Seq");
                    if (!seq.empty() && ownedChunks.count(seq)) {
                        // push it
                        std::string pushMsg = "Header:Push|Seq:" + seq
                                              + "|Raw:" + chunkStorage[seq];
                        sendMessage(sockFd, pushMsg, senderAddr, config.logFile);

                        logMessage("Node " + config.nodeId
                                   + " => PUSH chunkId=" + seq
                                   + " to " + partnerId,
                                   config.logFile);
                    }
                }
                else if (msg.find("Header:Push") != std::string::npos) {
                    std::string seq = extractField(msg, "Seq");
                    std::string raw = extractField(msg, "Raw");
                    if (!seq.empty() && !ownedChunks.count(seq)) {
                        ownedChunks.insert(seq);
                        chunkStorage[seq] = raw;

                        logMessage("Node " + config.nodeId
                                   + " STORED chunkId=" + seq
                                   + " from " + partnerId,
                                   config.logFile);
                    }
                }
                else if (msg.find("Header:Propose") != std::string::npos) {
                    // If we get a new propose now, we can decide to pull it
                    std::string seq = extractField(msg, "Seq");
                    if (!seq.empty() && !ownedChunks.count(seq)) {
                        // we can do an immediate pull or store it for next
                        std::string pullMsg = "Header:Pull|Seq:" + seq;
                        sendMessage(sockFd, pullMsg, senderAddr, config.logFile);

                        logMessage("Node " + config.nodeId
                                   + " => PULL chunkId=" + seq
                                   + " from " + partnerId,
                                   config.logFile);
                    }
                }
            }
        }

    } catch (const std::exception &ex) {
        logMessage("Exception in nodeLoopOneRound: " + std::string(ex.what()),
                   config.logFile);
    }

    // 4) Log final ownership
    {
        std::ostringstream oss;
        oss << "Node " << config.nodeId << " final ownership after round "
            << roundNumber << ": [";
        bool first = true;
        for (auto &cid : ownedChunks) {
            if (!first) oss << ", ";
            first = false;
            oss << cid;
        }
        oss << "]";
        logMessage(oss.str(), config.logFile);
    }

    // [Optional] Sleep a short while to let the round finish nicely
    std::this_thread::sleep_for(std::chrono::seconds(10));

    // 5) Close the socket
    close(sockFd);
    logMessage("Node " + config.nodeId + " finished round "
               + std::to_string(roundNumber)
               + ", socket closed.",
               config.logFile);
}


struct AuditResponseParts {
    int expectedTotal = -1; // Set when first received
    std::map<int, std::string> parts; // key: sequence number (1-indexed), ordered
};

void auditLoop(const std::vector<std::string>& auditPartners,
               const NodeConfig &config,
               const std::unordered_map<std::string, NodeInfo> &nodeDatabase)
{
    // 1. Bind a UDP socket for audit communications on port = config.port (adjust offset if needed)
    int auditPort = config.port;  // You may add an offset if desired.
    int auditSock = createAndBindSocket(auditPort, config.logFile);
    if (auditSock < 0) {
        logMessage("ERROR: Unable to bind audit socket on port " + std::to_string(auditPort), config.logFile);
        return;
    }
    logMessage("Audit socket bound on port " + std::to_string(auditPort), config.logFile);

    // 2. Build file paths for PCAP and local audit file.
    std::string pcapFilePath = "/home/Project/ansible/logs/traffic_" 
                               + config.nodeId + "_" + std::to_string(config.port) + ".pcap";
    std::string localAuditFile = "/home/Project/ansible/playbooks/logs/traffic_" 
                               + config.nodeId + "_" + std::to_string(config.port) + "_log.json";

    // 3. Convert PCAP to JSON using EagleEye.
    std::ostringstream cmdStream;
    cmdStream << "python3 /home/Project/ansible/AuditLogs/EagleEye.py "
              << "--input-file " << pcapFilePath;
    std::string pcapToJsonCmd = cmdStream.str();
    logMessage("Converting PCAP to JSON: " + pcapToJsonCmd, config.logFile);
    int retCode = system(pcapToJsonCmd.c_str());
    if (retCode != 0) {
        logMessage("ERROR: EagleEye conversion failed with code: " + std::to_string(retCode), config.logFile);
    }

    // 4. Set audit cycle parameters (one round only).
    const int collectionTimeMs = 10000; // 10 seconds collection period.
    const int sleepIntervalMs = 50;       // Sleep interval while collecting.

    // Map to collect responses from partners.
    std::unordered_map<std::string, AuditResponseParts> partnerResponses;
    char buffer[8192];

    // For blame system.
    std::vector<std::string> suspectedNodes;

    // --- Phase A: Process incoming messages for a short period ---
    auto collStart = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - collStart < std::chrono::milliseconds(collectionTimeMs)) {
        sockaddr_in sender;
        socklen_t senderLen = sizeof(sender);
        int bytes = recvfrom(auditSock, buffer, sizeof(buffer) - 1, MSG_DONTWAIT,
                              (struct sockaddr*)&sender, &senderLen);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::string msg(buffer);
            char senderIp[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &(sender.sin_addr), senderIp, INET_ADDRSTRLEN);
            int senderPort = ntohs(sender.sin_port);
            logMessage("Received audit message from " + std::string(senderIp) + ":" +
                       std::to_string(senderPort) + " -> " + msg, config.logFile);

            // (A1) If this is an audit request, reply with our local audit log entries.
            if (msg.find("Header:AuditRequest") != std::string::npos ||
                msg.find("Header:AuditLogRequest") != std::string::npos)
            {
                std::ifstream ifs(localAuditFile);
                std::string fileContent;
                if (ifs.is_open()) {
                    std::ostringstream oss;
                    oss << ifs.rdbuf();
                    fileContent = oss.str();
                    ifs.close();
                } else {
                    fileContent = "[]"; // Default empty array.
                    logMessage("WARNING: Unable to open local audit JSON file: " + localAuditFile, config.logFile);
                }
                try {
                    nlohmann::json auditJson = nlohmann::json::parse(fileContent);
                    if (!auditJson.is_array()) {
                        logMessage("Local audit JSON is not a JSON array.", config.logFile);
                    } else {
                        int total = auditJson.size();
                        for (int i = 0; i < total; i++) {
                            std::string entry = auditJson[i].dump();
                            std::ostringstream outMsg;
                            // Format: Header:AuditLogEntry|<nodeId>|<seq>/<total>|<entry JSON>
                            outMsg << "Header:AuditLogEntry|" << config.nodeId << "|" << (i+1) << "/" << total << "|" << entry;
                            std::string response = outMsg.str();
                            sendMessage(auditSock, response, sender, config.logFile);
                            logMessage("Sent audit log entry " + std::to_string(i+1) + "/" + std::to_string(total) +
                                       " to " + std::string(senderIp), config.logFile);
                        }
                    }
                } catch (const std::exception &e) {
                    logMessage("Exception parsing local audit JSON: " + std::string(e.what()), config.logFile);
                }
            }
            // (A2) Else if this is an audit log entry from a partner, process it.
            else if (msg.find("Header:AuditLogEntry|") == 0) {
                size_t pos1 = msg.find("|");
                size_t pos2 = msg.find("|", pos1 + 1);
                size_t pos3 = msg.find("|", pos2 + 1);
                if (pos1 == std::string::npos || pos2 == std::string::npos || pos3 == std::string::npos) {
                    logMessage("Malformed audit log entry: " + msg, config.logFile);
                } else {
                    std::string partnerId = msg.substr(pos1 + 1, pos2 - pos1 - 1);
                    std::string seqInfo = msg.substr(pos2 + 1, pos3 - pos2 - 1);
                    std::string entryJson = msg.substr(pos3 + 1);
                    size_t slashPos = seqInfo.find("/");
                    if (slashPos == std::string::npos) {
                        logMessage("Malformed sequence info: " + seqInfo, config.logFile);
                    } else {
                        int seq = std::stoi(seqInfo.substr(0, slashPos));
                        if (partnerResponses[partnerId].expectedTotal < 0) {
                            int total = std::stoi(seqInfo.substr(slashPos + 1));
                            partnerResponses[partnerId].expectedTotal = total;
                        }
                        partnerResponses[partnerId].parts[seq] = entryJson;
                        logMessage("Collected audit log entry " + std::to_string(seq) +
                                   " from partner " + partnerId, config.logFile);
                    }
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepIntervalMs));
    } // End Phase A

    // --- Phase B: Initiate our audit cycle (send audit requests and collect responses) ---
    logMessage("=== Initiating audit cycle (auditor role) ===", config.logFile);
    // Clear any previous responses.
    partnerResponses.clear();
    suspectedNodes.clear();

    {
        std::ostringstream oss;
        oss << "Auditing partners: ";
        for (const auto &pid : auditPartners)
            oss << pid << " ";
        logMessage(oss.str(), config.logFile);
    }
    // Send audit request to each external partner.
    for (const auto &pid : auditPartners) {
        auto it = nodeDatabase.find(pid);
        if (it == nodeDatabase.end()) {
            logMessage("Audit: Partner " + pid + " not found.", config.logFile);
            continue;
        }
        const NodeInfo &partnerInfo = it->second;
        sockaddr_in partnerAddr{};
        partnerAddr.sin_family = AF_INET;
        partnerAddr.sin_port = htons(partnerInfo.port); // using their normal port
        inet_pton(AF_INET, partnerInfo.ipAddress.c_str(), &partnerAddr.sin_addr);
        sendMessage(auditSock, "Header:AuditRequest", partnerAddr, config.logFile);
        logMessage("Sent audit request to partner " + pid, config.logFile);
    }
    // Collect responses for a fixed period.
    auto collEnd = std::chrono::steady_clock::now() + std::chrono::milliseconds(collectionTimeMs);
    while (std::chrono::steady_clock::now() < collEnd) {
        sockaddr_in rSender;
        socklen_t rSenderLen = sizeof(rSender);
        int rBytes = recvfrom(auditSock, buffer, sizeof(buffer) - 1, MSG_DONTWAIT,
                               (struct sockaddr*)&rSender, &rSenderLen);
        if (rBytes > 0) {
            buffer[rBytes] = '\0';
            std::string rMsg(buffer);
            if (rMsg.find("Header:AuditLogEntry|") == 0) {
                size_t p1 = rMsg.find("|");
                size_t p2 = rMsg.find("|", p1 + 1);
                size_t p3 = rMsg.find("|", p2 + 1);
                if (p1 != std::string::npos && p2 != std::string::npos && p3 != std::string::npos) {
                    std::string partnerId = rMsg.substr(p1 + 1, p2 - p1 - 1);
                    std::string seqInfo = rMsg.substr(p2 + 1, p3 - p2 - 1);
                    std::string entryJson = rMsg.substr(p3 + 1);
                    size_t slashPos = seqInfo.find("/");
                    if (slashPos != std::string::npos) {
                        int seq = std::stoi(seqInfo.substr(0, slashPos));
                        if (partnerResponses[partnerId].expectedTotal < 0) {
                            int total = std::stoi(seqInfo.substr(slashPos + 1));
                            partnerResponses[partnerId].expectedTotal = total;
                        }
                        partnerResponses[partnerId].parts[seq] = entryJson;
                        logMessage("Collected (during audit) entry " + std::to_string(seq) +
                                   " from partner " + partnerId, config.logFile);
                    }
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepIntervalMs));
    } // End Phase B

    // --- Phase C: For each partner, reassemble their entries into a JSON array and write to a temp file ---
    for (auto &pr : partnerResponses) {
        const std::string &partnerId = pr.first;
        AuditResponseParts &respParts = pr.second;
        if (respParts.parts.empty()) {
            logMessage("No audit entries received from partner " + partnerId, config.logFile);
            continue;
        }
        if (respParts.expectedTotal > 0 && respParts.parts.size() < static_cast<size_t>(respParts.expectedTotal)) {
            std::ostringstream warn;
            warn << "Incomplete audit log from partner " << partnerId
                 << ". Expected " << respParts.expectedTotal << " entries, got " << respParts.parts.size();
            logMessage(warn.str(), config.logFile);
        }
        nlohmann::json partnerLog = nlohmann::json::array();
        // Insert entries in order (the map is ordered by key).
        for (const auto &entryPair : respParts.parts) {
            try {
                nlohmann::json entry = nlohmann::json::parse(entryPair.second);
                partnerLog.push_back(entry);
            } catch (const std::exception &e) {
                logMessage("Error parsing an entry from partner " + partnerId + ": " + e.what(), config.logFile);
            }
        }
        // Write temp file using the audited partner's id.
        std::string tempAuditFile = "/tmp/audit_combined_" + partnerId + ".json";
        {
            std::ofstream ofs(tempAuditFile);
            if (ofs.is_open()) {
                ofs << partnerLog.dump(4);
                ofs.close();
                logMessage("Combined audit JSON for partner " + partnerId + " written to file: " + tempAuditFile, config.logFile);
                logMessage("Combined audit JSON content for partner " + partnerId + ":\n" + partnerLog.dump(4), config.logFile);
            } else {
                logMessage("ERROR: Unable to write combined audit JSON to file: " + tempAuditFile, config.logFile);
            }
        }
        // --- Phase D: Run audit verification for this partner ---
        int auditResult = auditLog(tempAuditFile);
        if (auditResult != 0) {
            suspectedNodes.push_back(partnerId);
            logMessage("Audit verification FAILED for partner " + partnerId, config.logFile);
        } else {
            logMessage("Audit verification PASSED for partner " + partnerId, config.logFile);
        }
    }

    // --- Phase E: If any suspected nodes, send heavy blame message and write blame file ---
    if (!suspectedNodes.empty()) {
        std::ostringstream blameMsg;
        blameMsg << "Header:Blame|SuspectedNodes:";
        for (const auto &suspect : suspectedNodes)
            blameMsg << suspect << ",";
        std::string blameMessage = blameMsg.str();
        // Send blame message to every node.
        for (const auto &nodePair : nodeDatabase) {
            const NodeInfo &node = nodePair.second;
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(node.port);
            inet_pton(AF_INET, node.ipAddress.c_str(), &addr.sin_addr);
            sendMessage(auditSock, blameMessage, addr, config.logFile);
            logMessage("Sent blame message to node " + nodePair.first, config.logFile);
        }
        // Write blame file.
        std::string blameFile = "/home/Project/ansible/blame/blamed_nodes_" + config.nodeId + "_" + std::to_string(config.port) + ".txt";
        std::ofstream ofsBlame(blameFile);
        if (ofsBlame.is_open()) {
            for (const auto &suspect : suspectedNodes)
                ofsBlame << suspect << "\n";
            ofsBlame.close();
            logMessage("Written blame file: " + blameFile, config.logFile);
        } else {
            logMessage("ERROR: Unable to write blame file: " + blameFile, config.logFile);
        }
    }

    // Close the audit socket and exit the round.
    close(auditSock);
    logMessage("Audit cycle completed. Exiting audit loop.", config.logFile);
}


int main(int argc, char* argv[]) {
    if (argc != 3 || std::string(argv[1]) != "--config") {
        std::cerr << "Usage: " << argv[0] << " --config <config_file_path>" << std::endl;
        return EXIT_FAILURE;
    }

    try {
        // 1) Parse configuration and hosts.
        logMessage("Parsing configuration file...", "debug.log");
        NodeConfig config = parseConfigFile(argv[2]);
        logMessage("Configuration parsed successfully: Node ID = " + config.nodeId, "debug.log");

        logMessage("Parsing hosts file...", "debug.log");
        auto nodeDatabase = parseHostsFile("/home/Project/ansible/inventory/hosts.ini");
        logMessage("Hosts file parsed successfully.", "debug.log");

        logMessage("Parsed node database:", "debug.log");
        for (const auto& [nodeId, node] : nodeDatabase) {
            logMessage("NodeID: " + nodeId + ", IP: " + node.ipAddress +
                       ", Port: " + std::to_string(node.port), "debug.log");
        }

        // 2) Add current node to membership.
        logMessage("Adding current node to membership...", "debug.log");
        if (!addNode({config.nodeId, nodeDatabase[config.nodeId].ipAddress, config.port}, config.logFile)) {
            logMessage("Node already exists in membership: " + config.nodeId, config.logFile);
        } else {
            logMessage("Node added to membership successfully: " + config.nodeId, config.logFile);
        }

        // 3) Start join request thread.
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

        // 4) Determine if this node is the source node.
        logMessage("Determining if this node is the source node...", "debug.log");
        bool isSourceNode = (config.nodeId == config.sourceNode);

        // 5) Simulation loop: alternate between dissemination rounds and audit cycles.
        const auto simulationStart = std::chrono::steady_clock::now();
        const std::chrono::minutes simulationDuration(5); // 15 minutes simulation.
        int roundNumber = 1;
        while (std::chrono::steady_clock::now() - simulationStart < simulationDuration) {
            // Partnership selection in main.
            PartnershipManager pm(config.nodeId, MAX_PARTNERS, PARTNERSHIP_PERIOD, config.logFile);
            pm.updatePartnerships(roundNumber, nodeDatabase);
            auto partnersSet = pm.getCurrentPartners();
            std::vector<std::string> currentPartners(partnersSet.begin(), partnersSet.end());
            {
                std::ostringstream oss;
                oss << "Round " << roundNumber << ": Selected partners: ";
                for (const auto &pid : currentPartners)
                    oss << pid << " ";
                logMessage(oss.str(), config.logFile);
            }

            // Alternate rounds: odd rounds run dissemination, even rounds run audit.
            if (roundNumber % 2 == 1) {
                logMessage("Round " + std::to_string(roundNumber) + ": Starting dissemination round.", config.logFile);
                nodeLoopOneRound(roundNumber, config, nodeDatabase, isSourceNode, currentPartners);
                logMessage("Round " + std::to_string(roundNumber) + ": Dissemination round completed.", config.logFile);
            } else {
                logMessage("Round " + std::to_string(roundNumber) + ": Starting audit cycle.", config.logFile);
                //auditLoop(currentPartners, config, nodeDatabase);
                logMessage("Round " + std::to_string(roundNumber) + ": Audit cycle completed.", config.logFile);
            }

            roundNumber++;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        logMessage("Simulation complete. Shutting down.", "debug.log");
        running = false; // Signal any loops to end.
    }
    catch (const std::exception &e) {
        logMessage("Error: " + std::string(e.what()), "error.log");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

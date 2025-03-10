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

// -------------------------------------------------------------------------
std::unordered_map<std::string, std::string> chunkStorage; 
std::unordered_set<std::string> ownedChunks;
bool loadedAlready = false;

std::unordered_set<std::string> globalSuspectedNodes;
std::mutex suspectedNodesMutex;

std::vector<std::pair<sockaddr_in, std::string>>

timedReceiveAll(int sockFd,
                const std::unordered_map<std::string, NodeInfo> & /*nodeDatabase*/,
                const std::string & /*logFile*/,
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

//--------------------------------

void nodeLoopOneRound(
    int roundNumber,
    const NodeConfig &config,
    const std::unordered_map<std::string, NodeInfo> &nodeDatabase,
    bool isSourceNode,
    const std::vector<std::string> &partners)
{
    // 1) Create and bind our socket.
    int sockFd = createAndBindSocket(config.port, config.logFile);
    if (sockFd < 0) {
        logMessage("Error: Could not bind socket on port " + std::to_string(config.port), config.logFile);
        return;
    }
    logMessage("Node " + config.nodeId + " bound to port " + std::to_string(config.port) +
               " for round " + std::to_string(roundNumber), config.logFile);

    // 2) Load owned chunks if not already loaded.
    if (isSourceNode && !loadedAlready) {
        loadedAlready = true;
        logMessage("Node " + config.nodeId + " is SOURCE. Loading data from " + config.dataFile, config.logFile);
        std::vector<std::string> fileChunks = readDataChunks(config.dataFile);
        for (size_t i = 0; i < fileChunks.size(); i++) {
            std::string cid = std::to_string(i);
            ownedChunks.insert(cid);
            chunkStorage[cid] = fileChunks[i];
        }
        logMessage("Node " + config.nodeId + " loaded " + std::to_string(fileChunks.size()) + " chunks.", config.logFile);
    }

    // 3) Log current owned chunks.
    {
        std::ostringstream oss;
        oss << "Node " << config.nodeId << " owns " << ownedChunks.size()
            << " chunk(s) before round " << roundNumber << ": [";
        bool first = true;
        for (const auto &cid : ownedChunks) {
            if (!first) oss << ", ";
            first = false;
            oss << cid;
        }
        oss << "]";
        logMessage(oss.str(), config.logFile);
    }

    // 4) Propose every owned chunk to each partner (every round).
    for (const auto &pid : partners) {
        auto it = nodeDatabase.find(pid);
        if (it == nodeDatabase.end()) {
            logMessage("Error: partner " + pid + " not found in DB", config.logFile);
            continue;
        }
        const NodeInfo &pinfo = it->second;
        sockaddr_in partnerAddr{};
        partnerAddr.sin_family = AF_INET;
        partnerAddr.sin_port = htons(pinfo.port);
        inet_pton(AF_INET, pinfo.ipAddress.c_str(), &partnerAddr.sin_addr);
        for (const auto &cid : ownedChunks) {
            std::string proposeMsg = "Header:Propose|Seq:" + cid;
            sendMessageWithLog(sockFd, proposeMsg, partnerAddr, config.logFile, config.nodeId);
            logMessage("Round " + std::to_string(roundNumber) +
                       ": Sent PROPOSE for chunk " + cid + " to " + pid, config.logFile);
        }
    }

    // 5) Set up round timing.
    auto roundStart = std::chrono::steady_clock::now();
    auto lastActivity = roundStart;
    const auto roundDuration = std::chrono::milliseconds(600);
    const auto inactivityThreshold = std::chrono::milliseconds(100);

    // 6) Event loop: process incoming messages.
    while (std::chrono::steady_clock::now() - roundStart < roundDuration) {
        auto messages = timedReceiveAll(sockFd, nodeDatabase, config.logFile, 50);
        if (!messages.empty()) {
            lastActivity = std::chrono::steady_clock::now();
            for (const auto &msgPair : messages) {
                const sockaddr_in &senderAddr = msgPair.first;
                const std::string &msg = msgPair.second;
                int senderPort = ntohs(senderAddr.sin_port);
                std::string partnerId = getNodeIdFromPort(senderPort, nodeDatabase);
                logMessage("Round " + std::to_string(roundNumber) +
                           " received from " + partnerId + ": " + msg, config.logFile);

                // If a partner proposes a chunk that we don't have, request it.
                if (msg.find("Header:Propose") != std::string::npos) {
                    std::string seq = extractField(msg, "Seq");
                    if (!seq.empty() && (ownedChunks.find(seq) == ownedChunks.end())) {
                        std::string pullMsg = "Header:Pull|Seq:" + seq;
                        sendMessageWithLog(sockFd, pullMsg, senderAddr, config.logFile, config.nodeId);
                        logMessage("Round " + std::to_string(roundNumber) +
                                   ": Sent PULL for missing chunk " + seq + " to " + partnerId, config.logFile);
                    }
                }
                // If a partner sends a Pull request, respond by pushing if we own the chunk.
                else if (msg.find("Header:Pull") != std::string::npos) {
                    std::string seq = extractField(msg, "Seq");
                    if (!seq.empty() && (ownedChunks.find(seq) != ownedChunks.end())) {
                        std::string pushMsg = "Header:Push|Seq:" + seq + "|Raw:" + chunkStorage[seq];
                        sendMessageWithLog(sockFd, pushMsg, senderAddr, config.logFile, config.nodeId);
                        logMessage("Round " + std::to_string(roundNumber) +
                                   ": Sent PUSH for chunk " + seq + " to " + partnerId, config.logFile);
                    }
                }
                // Process incoming Push messages from others.
                else if (msg.find("Header:Push") != std::string::npos) {
                    std::string seq = extractField(msg, "Seq");
                    std::string raw = extractField(msg, "Raw");
                    if (!seq.empty() && (ownedChunks.find(seq) == ownedChunks.end())) {
                        ownedChunks.insert(seq);
                        chunkStorage[seq] = raw;
                        logMessage("Round " + std::to_string(roundNumber) +
                                   ": Stored chunk " + seq + " from " + partnerId, config.logFile);
                    }
                }
            }
        }
        if (std::chrono::steady_clock::now() - lastActivity > inactivityThreshold)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // 7) Log final owned chunks.
    {
        std::ostringstream oss;
        oss << "Node " << config.nodeId << " final ownership after round " << roundNumber << ": [";
        bool first = true;
        for (const auto &cid : ownedChunks) {
            if (!first) oss << ", ";
            first = false;
            oss << cid;
        }
        oss << "]";
        logMessage(oss.str(), config.logFile);
    }

    static bool convergedLogged = false;
    if (!convergedLogged && ownedChunks.size() >= 20) {
        if (config.nodeId != config.sourceNode) { // Only non-source nodes check the hash
            // Calculate the hash over the stored chunks.
            std::string currentHash = computeHash(chunkStorage);
            std::string expectedHash = "c05c894d6e15f1faef29fb6ba0b3287337cd693f8ea759b2a19fb38765d9c324"; // Placeholder for expected hash
            logMessage("The hash I calculated is: " + currentHash, config.logFile);
            if (currentHash == expectedHash) {
                logMessage("I converged", config.logFile);
                convergedLogged = true;
            } else {
                logMessage("New data received; node state updated (hash mismatch).", config.logFile);
            }
        } else {
            // Source node: Do not check hash.
            logMessage("I converged", config.logFile);
        }
    }


    // 8) Close the socket.
    close(sockFd);
    logMessage("Node " + config.nodeId + " finished honest round " +
               std::to_string(roundNumber) + " and socket closed.", config.logFile);
}


struct AuditResponseParts {
    int expectedTotal = -1;
    std::unordered_map<int, std::string> parts;
};

// Helper: Fragment and send a long message.
void sendLongMessage(int sock, const std::string &message, const sockaddr_in &dest, const std::string &logFile) {
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
        sendMessage(sock, frag, dest, logFile);
    }
}

void auditLoop(const std::vector<std::string>& auditPartners,
               const NodeConfig &config,
               const std::unordered_map<std::string, NodeInfo> &nodeDatabase,
               const std::string &localAuditFile,
               const std::string &pcapFile)
{
    // --- Setup audit socket ---
    int auditSock = createAndBindSocket(config.port, config.logFile);
    if (auditSock < 0) {
        logMessage("ERROR: Unable to bind audit socket on port " + std::to_string(config.port), config.logFile);
        return;
    }
    logMessage("Audit socket bound on port " + std::to_string(config.port), config.logFile);
    logMessage("Audit loop using round-specific JSON file: " + localAuditFile, config.logFile);
    logMessage("Using PCAP file: " + pcapFile, config.logFile);

    // --- PCAP Conversion Phase ---
    {
        std::ostringstream cmdStream;
        cmdStream << "cd /home/Project/ansible && python3 AuditLogs/EagleEye.py --input-file " << pcapFile;
        std::string pcapToJsonCmd = cmdStream.str();
        logMessage("Converting PCAP to JSON: " + pcapToJsonCmd, config.logFile);
        int retCode = system(pcapToJsonCmd.c_str());
        if (retCode != 0) {
            logMessage("ERROR: EagleEye conversion failed with code: " + std::to_string(retCode), config.logFile);
        }
    }

    // --- Setup collection parameters and data structures ---
    // Use shorter windows so the audit loop runs quickly.
    const int passiveTimeMs = 3000;   // 3 seconds passive collection
    const int activeTimeMs  = 1000;    // 1 second active re‑request
    const int pollTimeoutMs = 5;       // 5 ms poll timeout

    // Data structures to store audit responses.
    std::unordered_map<std::string, AuditResponseParts> partnerResponses;
    std::unordered_map<std::string, bool> partnerComplete;
    std::unordered_set<std::string> nonCommPartners;  // Partners that explicitly indicate noncommunication

    // Initialize each partner’s state.
    for (const auto &pid : auditPartners) {
        partnerResponses[pid] = AuditResponseParts();
        partnerComplete[pid] = false;
    }

    char buffer[8192];
    struct pollfd pfd;
    pfd.fd = auditSock;
    pfd.events = POLLIN;

    // --- Phase A: Passive Collection ---
    auto passiveStart = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - passiveStart < std::chrono::milliseconds(passiveTimeMs)) {
        int ret = poll(&pfd, 1, pollTimeoutMs);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            sockaddr_in sender;
            socklen_t senderLen = sizeof(sender);
            int bytes = recvfrom(auditSock, buffer, sizeof(buffer) - 1, 0,
                                 reinterpret_cast<struct sockaddr*>(&sender), &senderLen);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                std::string msg(buffer);

                // Process noncommunication marker.
                if (msg.find("Header:NonComm") == 0) {
                    size_t delim = msg.find("|");
                    if (delim != std::string::npos) {
                        std::string partnerId = msg.substr(delim + 1);
                        partnerComplete[partnerId] = true;
                        nonCommPartners.insert(partnerId);
                        logMessage("Received noncomm marker from partner " + partnerId, config.logFile);
                    }
                }
                // Process end-of-log marker.
                else if (msg.find("Header:AuditLogEnd|") == 0) {
                    size_t delim = msg.find("|");
                    if (delim != std::string::npos) {
                        std::string partnerId = msg.substr(delim + 1);
                        partnerComplete[partnerId] = true;
                        logMessage("Received end-of-log marker from partner " + partnerId, config.logFile);
                    }
                }
                // Process audit request messages (from partners asking for our audit log).
                else if (msg.find("Header:AuditRequest") != std::string::npos ||
                         msg.find("Header:AuditLogRequest") != std::string::npos) {
                    std::ifstream ifs(localAuditFile);
                    std::string fileContent;
                    if (ifs.is_open()) {
                        std::ostringstream oss;
                        oss << ifs.rdbuf();
                        fileContent = oss.str();
                        ifs.close();
                    } else {
                        fileContent = "";
                        logMessage("WARNING: Unable to open local audit JSON file: " + localAuditFile, config.logFile);
                    }
                    if (fileContent.empty() || fileContent == "[]") {
                        std::string nonCommMsg = "Header:NonComm|" + config.nodeId;
                        sendMessage(auditSock, nonCommMsg, sender, config.logFile);
                        logMessage("Sent noncomm marker to requester", config.logFile);
                    } else {
                        try {
                            nlohmann::json auditJson = nlohmann::json::parse(fileContent);
                            if (!auditJson.is_array()) {
                                logMessage("Local audit JSON is not an array.", config.logFile);
                            } else {
                                int total = auditJson.size();
                                for (int i = 0; i < total; i++) {
                                    std::string entry = auditJson[i].dump();
                                    std::ostringstream outMsg;
                                    outMsg << "Header:AuditLogEntry|" << config.nodeId << "|" 
                                           << (i + 1) << "/" << total << "|" << entry;
                                    std::string response = outMsg.str();
                                    if (response.size() > MAX_UDP_PAYLOAD)
                                        sendLongMessage(auditSock, response, sender, config.logFile);
                                    else
                                        sendMessage(auditSock, response, sender, config.logFile);
                                }
                                std::string endMarker = "Header:AuditLogEnd|" + config.nodeId;
                                sendMessage(auditSock, endMarker, sender, config.logFile);
                            }
                        } catch (const std::exception &e) {
                            logMessage("Exception parsing local audit JSON: " + std::string(e.what()), config.logFile);
                        }
                    }
                }
                // Process incoming audit log entry messages.
                else if (msg.find("Header:AuditLogEntry|") == 0) {
                    size_t pos1 = msg.find("|");
                    size_t pos2 = msg.find("|", pos1 + 1);
                    size_t pos3 = msg.find("|", pos2 + 1);
                    if (pos1 != std::string::npos && pos2 != std::string::npos && pos3 != std::string::npos) {
                        std::string partnerId = msg.substr(pos1 + 1, pos2 - pos1 - 1);
                        if (nonCommPartners.count(partnerId) > 0)
                            continue;
                        std::string seqInfo = msg.substr(pos2 + 1, pos3 - pos2 - 1);
                        std::string entryJson = msg.substr(pos3 + 1);
                        size_t slashPos = seqInfo.find("/");
                        if (slashPos != std::string::npos) {
                            int seq = std::stoi(seqInfo.substr(0, slashPos));
                            int total = std::stoi(seqInfo.substr(slashPos + 1));
                            partnerResponses[partnerId].expectedTotal = total;
                            partnerResponses[partnerId].parts[seq] = entryJson;
                        }
                    }
                }
            }
        }
        // Exit early if every partner has signaled completion.
        bool allDone = true;
        for (const auto &p : partnerComplete) {
            if (!p.second) { allDone = false; break; }
        }
        if (allDone)
            break;
    } // End Phase A

    // --- Phase B: Active Re‑request ---
    for (const auto &pid : auditPartners) {
        if (!partnerComplete[pid]) {
            auto it = nodeDatabase.find(pid);
            if (it != nodeDatabase.end()) {
                sockaddr_in partnerAddr;
                partnerAddr.sin_family = AF_INET;
                partnerAddr.sin_port = htons(it->second.port);
                inet_pton(AF_INET, it->second.ipAddress.c_str(), &partnerAddr.sin_addr);
                sendMessage(auditSock, "Header:AuditRequest", partnerAddr, config.logFile);
                logMessage("Sent active audit request to partner " + pid, config.logFile);
            }
        }
    }
    auto activeEnd = std::chrono::steady_clock::now() + std::chrono::milliseconds(activeTimeMs);
    while (std::chrono::steady_clock::now() < activeEnd) {
        int ret = poll(&pfd, 1, pollTimeoutMs);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            sockaddr_in rSender;
            socklen_t rSenderLen = sizeof(rSender);
            int rBytes = recvfrom(auditSock, buffer, sizeof(buffer) - 1, 0,
                                   reinterpret_cast<struct sockaddr*>(&rSender), &rSenderLen);
            if (rBytes > 0) {
                buffer[rBytes] = '\0';
                std::string rMsg(buffer);
                if (rMsg.find("Header:AuditLogEntry|") == 0) {
                    size_t pos1 = rMsg.find("|");
                    size_t pos2 = rMsg.find("|", pos1 + 1);
                    size_t pos3 = rMsg.find("|", pos2 + 1);
                    if (pos1 != std::string::npos && pos2 != std::string::npos && pos3 != std::string::npos) {
                        std::string partnerId = rMsg.substr(pos1 + 1, pos2 - pos1 - 1);
                        if (nonCommPartners.count(partnerId) > 0)
                            continue;
                        std::string seqInfo = rMsg.substr(pos2 + 1, pos3 - pos2 - 1);
                        std::string entryJson = rMsg.substr(pos3 + 1);
                        size_t slashPos = seqInfo.find("/");
                        if (slashPos != std::string::npos) {
                            int seq = std::stoi(seqInfo.substr(0, slashPos));
                            int total = std::stoi(seqInfo.substr(slashPos + 1));
                            partnerResponses[partnerId].expectedTotal = total;
                            partnerResponses[partnerId].parts[seq] = entryJson;
                        }
                    }
                }
                else if (rMsg.find("Header:AuditLogEnd|") == 0) {
                    size_t delim = rMsg.find("|");
                    if (delim != std::string::npos) {
                        std::string partnerId = rMsg.substr(delim + 1);
                        partnerComplete[partnerId] = true;
                        logMessage("Received active end-of-log marker from partner " + partnerId, config.logFile);
                    }
                }
                else if (rMsg.find("Header:NonComm") == 0) {
                    size_t delim = rMsg.find("|");
                    if (delim != std::string::npos) {
                        std::string partnerId = rMsg.substr(delim + 1);
                        partnerComplete[partnerId] = true;
                        nonCommPartners.insert(partnerId);
                        logMessage("Received active noncomm marker from partner " + partnerId, config.logFile);
                    }
                }
            }
        }
    } // End Phase B

    // Mark any partners that still haven’t responded as noncommunicative.
    for (const auto &pid : auditPartners) {
        if (!partnerComplete[pid]) {
            nonCommPartners.insert(pid);
            logMessage("Marking partner " + pid + " as noncommunicative (no response received).", config.logFile);
        }
    }

    // --- Phase C: Check for Missing Entries ---
    std::vector<std::string> faultyPartners;
    for (const auto &pid : auditPartners) {
        // Skip partners that indicated noncommunication.
        if (nonCommPartners.count(pid) > 0) {
            logMessage("Skipping audit for noncommunicative partner " + pid, config.logFile);
            continue;
        }
        auto it = partnerResponses.find(pid);
        if (it != partnerResponses.end() && it->second.expectedTotal > 0) {
            int expected = it->second.expectedTotal;
            bool missing = false;
            std::string missingEntries;
            for (int seq = 1; seq <= expected; seq++) {
                if (it->second.parts.find(seq) == it->second.parts.end()) {
                    missing = true;
                    missingEntries += std::to_string(seq) + " ";
                }
            }
            if (missing) {
                std::ostringstream warn;
                warn << "Incomplete audit log from partner " << pid << ". Missing entries: " << missingEntries;
                logMessage(warn.str(), config.logFile);
                /*
                double ratio = static_cast<double>(it->second.parts.size()) / expected;
                
                if (!partnerComplete[pid] || ratio < 0.8)
                    faultyPartners.push_back(pid);
                */
            }
        } else {
            // If the partner sent an end-of-log marker (i.e. is complete) but no entries were received, treat it as nonfaulty.
            if (partnerComplete[pid]) {
                logMessage("Partner " + pid + " sent end-of-log marker but no audit entries were received. Treating as nonfaulty.", config.logFile);
            } else {
                logMessage("No audit entries received from partner " + pid, config.logFile);
                /*faultyPartners.push_back(pid);*/
            }
        }
    }

    // --- Phase D: Reassemble and Verify Logs ---
    for (auto &pair : partnerResponses) {
        const std::string &partnerId = pair.first;
        if (nonCommPartners.count(partnerId) > 0)
            continue;
        AuditResponseParts &respParts = pair.second;
        if (respParts.parts.empty())
            continue;
        std::vector<int> seqKeys;
        for (const auto &kv : respParts.parts)
            seqKeys.push_back(kv.first);
        std::sort(seqKeys.begin(), seqKeys.end());
        nlohmann::json combinedLog = nlohmann::json::array();
        for (int seq : seqKeys) {
            try {
                combinedLog.push_back(nlohmann::json::parse(respParts.parts.at(seq)));
            } catch (const std::exception &e) {
                logMessage("Error parsing entry " + std::to_string(seq) + " from partner " + partnerId + ": " + e.what(), config.logFile);
            }
        }
        std::string tempAuditFile = "/tmp/audit_combined_" + partnerId + ".json";
        {
            std::ofstream ofs(tempAuditFile);
            if (ofs.is_open()) {
                ofs << combinedLog.dump();
                ofs.close();
                logMessage("Combined audit JSON for partner " + partnerId + " written to " + tempAuditFile, config.logFile);
            } else {
                logMessage("ERROR: Unable to write combined audit JSON to file: " + tempAuditFile, config.logFile);
            }
        }
        int auditResult = auditLog(tempAuditFile, ownedChunks);
        if (auditResult != 0) {
            logMessage("Audit verification FAILED for partner " + partnerId, config.logFile);
            faultyPartners.push_back(partnerId);
        } else {
            logMessage("Audit verification PASSED for partner " + partnerId, config.logFile);
        }
        std::remove(tempAuditFile.c_str());
    }

    // --- Phase E: Blame Faulty Partners ---
    if (!faultyPartners.empty()) {
        std::ostringstream blameMsg;
        blameMsg << "Header:Blame|SuspectedNodes:";
        for (const auto &suspect : faultyPartners)
            blameMsg << suspect << ",";
        std::string blameMessage = blameMsg.str();
        for (const auto &entry : nodeDatabase) {
            if (nonCommPartners.count(entry.first) > 0)
                continue;
            sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(entry.second.port);
            inet_pton(AF_INET, entry.second.ipAddress.c_str(), &addr.sin_addr);
            sendMessage(auditSock, blameMessage, addr, config.logFile);
            logMessage("Sent blame message to node " + entry.first, config.logFile);
        }
        std::string blameFile = "/home/Project/ansible/blame/blamed_nodes_" + config.nodeId +
                                "_" + std::to_string(config.port) + ".txt";
        std::ofstream ofsBlame(blameFile);
        if (ofsBlame.is_open()) {
            for (const auto &suspect : faultyPartners)
                ofsBlame << suspect << "\n";
            ofsBlame.close();
            logMessage("Written blame file: " + blameFile, config.logFile);
        } else {
            logMessage("ERROR: Unable to write blame file: " + blameFile, config.logFile);
        }
    }

    // --- Final: Update global suspected nodes and close socket ---
    {
        std::lock_guard<std::mutex> lock(suspectedNodesMutex);
        for (const auto &pid : faultyPartners)
            globalSuspectedNodes.insert(pid);
    }
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

        // 3) Launch join request thread.
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

        // 4) Determine if this node is the source.
        logMessage("Determining if this node is the source node...", "debug.log");
        bool isSourceNode = (config.nodeId == config.sourceNode);

        // 5) Simulation loop: for each round, capture dissemination traffic, audit it, then delete logs.
        // The persistent PCAP file is managed externally and is located at:
        // log_dir + "/traffic_" + config.nodeId + "_" + config.port + ".pcap"
        std::string pcapFile = log_dir + "/traffic_" + config.nodeId + "_" + std::to_string(config.port) + ".pcap";

        const auto simulationStart = std::chrono::steady_clock::now();
        const std::chrono::minutes simulationDuration(15); // 15-minute simulation.
        int roundNumber = 1;
        while (std::chrono::steady_clock::now() - simulationStart < simulationDuration) {
            // Create a unique JSON file name for this round's audit output.
            std::ostringstream fnameStream;
            fnameStream << config.nodeId << "_" << config.port << "_round" << roundNumber;
            std::string roundTag = fnameStream.str();
            std::string jsonFile = log_dir + "/traffic_" + config.nodeId + "_" + std::to_string(config.port) + "_log.json";

            // Select partnerships.
            std::unordered_map<std::string, NodeInfo> filteredDatabase;
            {
                std::lock_guard<std::mutex> lock(suspectedNodesMutex);
                for (const auto &entry : nodeDatabase) {
                    if (globalSuspectedNodes.find(entry.first) == globalSuspectedNodes.end()) {
                        filteredDatabase.insert(entry);
                    }
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

            // Run dissemination round.
            logMessage("Round " + std::to_string(roundNumber) + ": Starting dissemination round.", config.logFile);
            nodeLoopOneRound(roundNumber, config, nodeDatabase, isSourceNode, currentPartners);
            logMessage("Round " + std::to_string(roundNumber) + ": Dissemination round completed.", config.logFile);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));


            // Run audit on the persistent capture.
            logMessage("Round " + std::to_string(roundNumber) + ": Starting audit cycle.", config.logFile);
            auditLoop(currentPartners, config, nodeDatabase, jsonFile, pcapFile);
            logMessage("Round " + std::to_string(roundNumber) + ": Audit cycle completed.", config.logFile);

            // Delete the JSON file.
            if (remove(jsonFile.c_str()) != 0) {
                logMessage("WARNING: Failed to remove JSON file: " + jsonFile, config.logFile);
            } else {
                logMessage("Removed JSON file: " + jsonFile, config.logFile);
            }
            // Truncate (clear) the persistent PCAP file.
            
            {
                std::ofstream ofs(pcapFile, std::ios::trunc);
                ofs.close();
                logMessage("Cleared PCAP file: " + pcapFile, config.logFile);
            }
            

            reinitializePCAPFile(pcapFile, config);


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
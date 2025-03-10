#ifndef ACTING_UTILS_H
#define ACTING_UTILS_H

#include <string>
#include <vector>
#include <unordered_map>
#include <netinet/in.h> // For sockaddr_in
#include <mutex>


// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------
#define CHUNK_SIZE 1024
constexpr int SUSPECT_THRESHOLD = 3;  
constexpr int MEMBERSHIP_UPDATE_INTERVAL = 30;  
constexpr size_t LOG_SEGMENT_SIZE = 4096; // Used for log segmentation


// For reassembling incoming segmented logs
struct Reassembly {
    size_t totalChunks = 0;
    size_t chunksReceived = 0;
    std::vector<std::string> segments;
};


extern std::unordered_map<std::string, Reassembly> reassemblyMap;
extern std::mutex reassemblyMutex;

// -----------------------------------------------------------------------------
// Structures
// -----------------------------------------------------------------------------
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


// -----------------------------------------------------------------------------
// Externs for any shared global variables (if you choose to keep them global)
// -----------------------------------------------------------------------------
extern std::unordered_map<std::string, Reassembly> reassemblyMap; 
// If you store the map/its mutex in a .cpp file, declare them as 'extern' here
// e.g., extern std::mutex reassemblyMutex; 

// -----------------------------------------------------------------------------
// Function Declarations
// -----------------------------------------------------------------------------

// Basic utilities
std::string getCurrentTime();
void logMessage(const std::string &message, const std::string &logFile);

// Chunk-based reading
std::vector<std::string> readDataChunks(const std::string &dataFilePath);

// Socket utilities
int createAndBindSocket(int port, const std::string &logFile);
void sendMessage(int sockFd, const std::string &message, 
                 const sockaddr_in &partnerAddr, 
                 const std::string &logFile);

// Field extraction
std::string extractField(const std::string &message, const std::string &key);

// Dissemination helpers
std::string generateSequenceNumber(int chunkIndex);
std::string getNodeIdFromPort(int port, 
       const std::unordered_map<std::string, NodeInfo> &nodeDatabase);
void sendChunk(const std::string &chunk, 
               const std::string &sequenceNumber, 
               const std::string &state,
               const sockaddr_in &partnerAddr, 
               int sockFd, 
               const std::string &logFile);

// Hosts/config parsing
std::unordered_map<std::string, NodeInfo> parseHostsFile(
       const std::string &hostsFilePath);
NodeConfig parseConfigFile(const std::string &configFilePath);
void waitForReady();

// Audit/Log handling
std::string filterOutAuditEntries(const std::string &originalLogFilePath,
                                  const std::string &logFile);
void sendLogResponseInChunks(int sockFd, 
                             const sockaddr_in &destAddr,
                             const std::string &logId, 
                             const std::string &fullJson, 
                             const std::string &logFile);
void handleIncomingAuditRequest(int sockFd,
                                const sockaddr_in &senderAddr, 
                                const NodeConfig &config);

// Reassembly functions
void finalizeLogReassembly(const std::string &logId, 
                           const NodeConfig &config);
void handleIncomingLogSegment(const std::string &message,
                              const sockaddr_in &senderAddr, 
                              const NodeConfig &config);
void appendToSentMessages(const std::string &nodeId, const std::string &msg); 
void sendMessageWithLog(int sockFd, const std::string &msg, const sockaddr_in &dest, 
                        const std::string &logFile, const std::string &nodeId); 

#endif // ACTING_UTILS_H

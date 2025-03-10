#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_set>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <string>

using json = nlohmann::json;

// -----------------------------------------------------------------------------
// Computes the SHA256 hash for the provided data string.
std::string computeSHA256(const std::string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(data.c_str()), data.size(), hash);
    std::ostringstream hashStream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        hashStream << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(hash[i]);
    return hashStream.str();
}

// -----------------------------------------------------------------------------
// Computes the log entry hash using the previous hash, sequence number,
// message type, and raw data.
std::string computeLogEntryHash(const std::string &previousHash, int sequenceNumber,
                                const std::string &type, const std::string &rawData) {
    std::ostringstream dataStream;
    dataStream << previousHash << sequenceNumber << type << rawData;
    return computeSHA256(dataStream.str());
}

// -----------------------------------------------------------------------------
// Extracts a string field from a JSON object. Returns "Unknown" if the key
// is missing or not a string.
std::string extractField(const json &content, const std::string &key) {
    if (content.contains(key) && content[key].is_string())
        return content[key];
    return "Unknown";
}

// -----------------------------------------------------------------------------
// Revised auditLog function with additional checks for free‑rider behavior.
// Parameters:
//   logFilePath - path to the JSON audit log file.
//   designatedChunks - (optional) set of chunk IDs that the node is supposed to own.
//                      When provided, the function checks that if any proposals or pushes
//                      occurred during the round, then every owned chunk must appear in at
//                      least one proposal or push. Also, every pushed chunk must be owned.
// Returns 0 if all checks pass; 1 otherwise.
int auditLog(const std::string &logFilePath,
             const std::unordered_set<std::string> &designatedChunks = {}) {
    std::ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        std::cerr << "Error: Unable to open log file: " << logFilePath << std::endl;
        return 1;
    }
    
    json logEntries;
    try {
        logFile >> logEntries;
    } catch (const std::exception &e) {
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
        return 1;
    }
    
    // Counters for summary reporting.
    int totalEntries = 0, totalPropose = 0, totalPull = 0, totalPush = 0;
    int hashPassed = 0, hashFailed = 0;
    
    // Sets to track chunk IDs by state.
    std::unordered_set<std::string> proposedChunks;
    std::unordered_set<std::string> pulledChunks;
    std::unordered_set<std::string> pushedChunks;
    
    // Initialize the hash chain with 64 zeros.
    std::string prevHash(64, '0');
    
    // Process each log entry.
    for (const auto &entry : logEntries) {
        totalEntries++;
        int seqNo = entry["sequence_number"];
        std::string type = entry["type"];
        json content = entry["content"];
        std::string expectedHash = entry["hash"];
        std::string rawData = content["raw_data"];
        std::string state = content["state"];
        std::string chunkId = content["chunk_id"];
        
        // Recompute the hash.
        std::string actualHash = computeLogEntryHash(prevHash, seqNo, type, rawData);
        std::cout << "Verifying entry " << seqNo << ":\n"
                  << "  State: " << state << "\n"
                  << "  Chunk ID: " << chunkId << "\n"
                  << "  Expected Hash: " << expectedHash << "\n"
                  << "  Actual Hash:   " << actualHash << "\n";
        
        if (expectedHash == actualHash) {
            hashPassed++;
        } else {
            hashFailed++;
            std::cerr << "Hash mismatch at sequence number " << seqNo << "\n";
            // Update prevHash with the computed hash to continue the chain.
            prevHash = actualHash;
            continue;
        }
        
        // Record the chunk ID based on message state.
        if (state == "Propose") {
            proposedChunks.insert(chunkId);
            totalPropose++;
        } else if (state == "Pull") {
            pulledChunks.insert(chunkId);
            totalPull++;
        } else if (state == "Push") {
            pushedChunks.insert(chunkId);
            totalPush++;
        } else {
            std::cerr << "Warning: Unknown state '" << state << "' in entry " << seqNo << "\n";
        }
        
        prevHash = actualHash;
    }
    
    bool errorsDetected = false;
    
    // (i) If any proposals or pushes occurred, then each owned chunk must appear
    // in at least one of those sets.
    if (!designatedChunks.empty() && (totalPropose > 0 || totalPush > 0)) {
        for (const auto &chunk : designatedChunks) {
            if (proposedChunks.find(chunk) == proposedChunks.end() &&
                pushedChunks.find(chunk) == pushedChunks.end()) {
                std::cerr << "Error: Owned chunk " << chunk << " was neither proposed nor pushed.\n";
                errorsDetected = true;
            }
        }
    } else {
        std::cout << "No proposals or pushes in this round; skipping ownership check for designated chunks.\n";
    }
    
    // (ii) Ensure every pushed chunk is indeed owned.
    if (!designatedChunks.empty()) {
        for (const auto &chunk : pushedChunks) {
            if (designatedChunks.find(chunk) == designatedChunks.end()) {
                std::cerr << "Error: Pushed chunk " << chunk << " is not owned.\n";
                errorsDetected = true;
            }
        }
    }
    
    // --- Additional Free‑Rider Behavior Checks ---
    // (iii) Check if the node solely sent pull messages.
    if (totalPull > 0 && totalPropose == 0 && totalPush == 0) {
        std::cerr << "Error: Node exhibits free‑rider behavior: only pull messages found without any proposals or pushes.\n";
        errorsDetected = true;
    }
    
    // (iv) If designatedChunks are provided, verify that pull requests target only owned chunks.
    if (!designatedChunks.empty()) {
        for (const auto &chunk : pulledChunks) {
            if (designatedChunks.find(chunk) == designatedChunks.end()) {
                std::cerr << "Error: Node pulled chunk " << chunk << " which is not among the designated owned chunks.\n";
                errorsDetected = true;
            }
        }
    }
    
    // Print summary.
    std::cout << "\n=== Audit Summary ===\n";
    std::cout << "Total Entries: " << totalEntries << "\n";
    std::cout << "Propose Messages: " << totalPropose << "\n";
    std::cout << "Pull Messages:    " << totalPull << "\n";
    std::cout << "Push Messages:    " << totalPush << "\n";
    std::cout << "Unique Proposed Chunks: " << proposedChunks.size() << "\n";
    std::cout << "Unique Pulled Chunks:   " << pulledChunks.size() << "\n";
    std::cout << "Unique Pushed Chunks:   " << pushedChunks.size() << "\n";
    std::cout << "Hashes Passed: " << hashPassed << "\n";
    std::cout << "Hashes Failed: " << hashFailed << "\n";
    
    if (errorsDetected || hashFailed > 0) {
        std::cout << "Log verification encountered errors.\n";
        return 1;
    } else {
        std::cout << "Log consistency and protocol compliance verified successfully.\n";
        return 0;
    }
}

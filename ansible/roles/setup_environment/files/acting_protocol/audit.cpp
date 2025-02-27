#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <unordered_set>
#include <unordered_map>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>

using json = nlohmann::json;
//std::mutex reassemblyMutex; // Define the mutex


// Function to compute SHA256 hash
std::string computeSHA256(const std::string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(data.c_str()), data.size(), hash);

    std::ostringstream hashStream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return hashStream.str();
}

// Function to compute log entry hash
std::string computeLogEntryHash(const std::string &previousHash, int sequenceNumber, const std::string &type, const std::string &rawData) {
    std::ostringstream dataStream;
    dataStream << previousHash << sequenceNumber << type << rawData;
    return computeSHA256(dataStream.str());
}

// Function to extract a field from JSON content
std::string extractField(const json &content, const std::string &key) {
    if (content.contains(key) && content[key].is_string()) {
        return content[key];
    }
    return "Unknown";
}

#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <string>

// Assume computeLogEntryHash and extractField are declared elsewhere.
extern std::string computeLogEntryHash(const std::string &previousHash, int seqNo, const std::string &type, const std::string &rawData);
extern std::string extractField(const nlohmann::json &content, const std::string &key);

// Modified auditLog function that returns 0 if OK and 1 if errors are detected.
int auditLog(const std::string &logFilePath) {
    std::ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        std::cerr << "Error: Unable to open log file: " << logFilePath << std::endl;
        return 1;
    }

    nlohmann::json logEntries;
    try {
        logFile >> logEntries;
    } catch (const std::exception &e) {
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
        return 1;
    }

    // Tracking sets and counters
    std::unordered_set<std::string> proposedChunks;
    std::unordered_set<std::string> pulledChunks;
    std::unordered_set<std::string> pushedChunks;
    int totalEntries = 0, totalPropose = 0, totalPull = 0, totalPush = 0;
    int hashPassed = 0, hashFailed = 0;
    std::string previousHash(64, '0');

    for (const auto &entry : logEntries) {
        totalEntries++;
        int seqNo = entry["sequence_number"];
        std::string type = entry["type"];
        nlohmann::json content = entry["content"];
        std::string expectedHash = entry["hash"];
        std::string rawData = content["raw_data"];
        std::string state = content["state"];
        std::string chunkId = content["chunk_id"];

        std::string actualHash = computeLogEntryHash(previousHash, seqNo, type, rawData);

        std::cout << "Verifying entry:\n"
                  << "  Sequence Number: " << seqNo << "\n"
                  << "  State: " << state << "\n"
                  << "  Chunk ID: " << chunkId << "\n"
                  << "  Raw Data: " << rawData << "\n"
                  << "  Expected Hash: " << expectedHash << "\n"
                  << "  Actual Hash: " << actualHash << "\n";

        if (expectedHash == actualHash) {
            hashPassed++;
        } else {
            hashFailed++;
            std::cerr << "Hash mismatch at sequence number " << seqNo << "\n";
            continue; // Skip further processing for this entry
        }

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

        previousHash = actualHash;
    }

    // Final verifications
    for (const auto &chunkId : pulledChunks) {
        if (pushedChunks.find(chunkId) == pushedChunks.end()) {
            std::cerr << "Error: Pulled chunk " << chunkId << " was not pushed.\n";
        }
    }
    for (const auto &chunkId : pushedChunks) {
        if (proposedChunks.find(chunkId) == proposedChunks.end()) {
            std::cerr << "Error: Pushed chunk " << chunkId << " was not proposed.\n";
        }
    }

    std::cout << "\n=== Audit Summary ===\n";
    std::cout << "Total Entries: " << totalEntries << "\n";
    std::cout << "Total Propose Messages: " << totalPropose << "\n";
    std::cout << "Total Pull Messages: " << totalPull << "\n";
    std::cout << "Total Push Messages: " << totalPush << "\n";
    std::cout << "Unique Proposed Chunks: " << proposedChunks.size() << "\n";
    std::cout << "Unique Pulled Chunks: " << pulledChunks.size() << "\n";
    std::cout << "Unique Pushed Chunks: " << pushedChunks.size() << "\n";
    std::cout << "Hashes Passed: " << hashPassed << "\n";
    std::cout << "Hashes Failed: " << hashFailed << "\n";

    if (hashFailed == 0) {
        std::cout << "Log consistency and protocol compliance verified successfully.\n";
        return 0;
    } else {
        std::cout << "Log verification encountered errors.\n";
        return 1;
    }
}

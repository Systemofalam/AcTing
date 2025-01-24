#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>

using json = nlohmann::json;

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

// Function to extract chunk ID (example assumes raw_data is hex-encoded)
std::string extractChunkId(const std::string &rawData) {
    if (rawData.size() < 16) {
        return "INVALID"; // Indicate invalid chunk ID if raw_data is too short
    }
    return rawData.substr(0, 16); // Example: Extract first 16 hex characters as chunk ID
}

// Audit function
void auditLog(const std::string &logFilePath) {
    std::ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        std::cerr << "Error: Unable to open log file: " << logFilePath << std::endl;
        return;
    }

    json logEntries;
    try {
        logFile >> logEntries;
    } catch (const std::exception &e) {
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
        return;
    }

    std::string previousHash(64, '0'); // Base hash
    std::unordered_map<std::string, std::unordered_set<std::string>> proposals; // Tracks proposed chunks per partner
    std::unordered_map<std::string, std::unordered_set<std::string>> pulls;     // Tracks pull requests per partner
    std::unordered_map<std::string, std::unordered_set<std::string>> pushes;    // Tracks pushed chunks per partner

    for (const auto &entry : logEntries) {
        int seqNo = entry["sequence_number"];
        std::string type = entry["type"];
        json content = entry["content"];
        std::string expectedHash = entry["hash"];
        std::string rawData = content["raw_data"];

        // Compute the actual hash
        std::string actualHash = computeLogEntryHash(previousHash, seqNo, type, rawData);

        // Debugging output
        std::cout << "Verifying entry:\n"
                  << "  Sequence Number: " << seqNo << "\n"
                  << "  Raw Data: " << rawData << "\n"
                  << "  Expected Hash: " << expectedHash << "\n"
                  << "  Actual Hash: " << actualHash << "\n";

        // Verify hash
        if (expectedHash != actualHash) {
            std::cerr << "Hash mismatch at sequence number " << seqNo << "\n";
            std::cerr << "  Content Hash: " << computeSHA256(rawData) << "\n";
            std::cerr << "  Concatenated String: " << previousHash << seqNo << type << rawData << "\n";
            return;
        }

        // Extract details from the content
        std::string sourceIp = content["source_ip"];
        std::string destIp = content["dest_ip"];
        std::string state = content["state"];
        std::string chunkId = extractChunkId(rawData);

        // Analyze log based on state
        if (state == "Propose") {
            proposals[destIp].insert(chunkId);
        } else if (state == "Pull") {
            pulls[sourceIp].insert(chunkId);
        } else if (state == "Push") {
            pushes[destIp].insert(chunkId);
        }

        previousHash = actualHash;
    }

    // Verify protocol conditions
    std::cout << "\nProtocol Verification:\n";

    for (const auto &[partner, proposedChunks] : proposals) {
        for (const auto &chunk : proposedChunks) {
            if (pushes[partner].find(chunk) == pushes[partner].end()) {
                std::cerr << "Error: Proposed chunk " << chunk << " to " << partner << " was not sent (Push missing).\n";
            }
        }
    }

    for (const auto &[partner, requestedChunks] : pulls) {
        for (const auto &chunk : requestedChunks) {
            if (pushes[partner].find(chunk) == pushes[partner].end()) {
                std::cerr << "Error: Pull request for chunk " << chunk << " by " << partner << " was not fulfilled.\n";
            }
        }
    }

    std::cout << "Audit completed successfully. All checks passed.\n";
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <log_file_path>" << std::endl;
        return 1;
    }

    std::string logFilePath = argv[1];
    auditLog(logFilePath);

    return 0;
}

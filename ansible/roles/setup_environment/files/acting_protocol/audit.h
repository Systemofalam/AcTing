#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <string>
#include <unordered_set>
#include <unordered_map>
#include <nlohmann/json.hpp>
#include "acting_utils.h"


// Use the nlohmann::json namespace
using json = nlohmann::json;

// Function to compute SHA256 hash
std::string computeSHA256(const std::string &data);

// Function to compute log entry hash
std::string computeLogEntryHash(const std::string &previousHash, int sequenceNumber, const std::string &type, const std::string &rawData);

// Function to extract a field from JSON content
std::string extractField(const json &content, const std::string &key);

// Audit function
int auditLog(const std::string &logFilePath);

#endif // AUDIT_LOG_H

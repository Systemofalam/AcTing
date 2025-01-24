#include "partnerships.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>

// Constructor
PartnershipManager::PartnershipManager(const std::string &nodeId, int maxPartners, int partnershipPeriod, const std::string &logFile)
    : nodeId(nodeId), maxPartners(maxPartners), partnershipPeriod(partnershipPeriod), logFile(logFile), randomGenerator(std::random_device{}()) {
    logEvent("PartnershipManager initialized for node: " + nodeId);
}

// Initialize partnerships for the first time
void PartnershipManager::initializePartnerships(int roundNumber, const std::unordered_map<std::string, NodeInfo> &membershipList) {
    logEvent("Initializing partnerships for round: " + std::to_string(roundNumber));
    updatePartnerships(roundNumber, membershipList);
}

// Update partnerships based on the round number and membership list
void PartnershipManager::updatePartnerships(int roundNumber, const std::unordered_map<std::string, NodeInfo> &membershipList) {
    logEvent("Updating partnerships for round: " + std::to_string(roundNumber));

    try {
        std::vector<std::string> eligibleNodes;
        for (const auto &[nodeId, _] : membershipList) {
            if (nodeId != this->nodeId && suspicionList.find(nodeId) == suspicionList.end()) {
                eligibleNodes.push_back(nodeId);
            } else {
                logEvent("Excluding node: " + nodeId + " (self or suspicious).");
            }
        }

        logEvent("Eligible nodes count: " + std::to_string(eligibleNodes.size()));

        if (eligibleNodes.empty()) {
            logEvent("Error: No eligible nodes available for partnerships.");
            return;
        }

        // Generate PRNG seed
        std::string seedString = this->nodeId + std::to_string(roundNumber);
        std::hash<std::string> hasher;
        size_t seed = hasher(seedString);

        // Shuffle eligible nodes
        std::mt19937 rng(seed);
        std::shuffle(eligibleNodes.begin(), eligibleNodes.end(), rng);

        int addedPartners = 0;
        {
            std::lock_guard<std::mutex> lock(partnershipMutex);
            for (const auto &nodeId : eligibleNodes) {
                if (static_cast<int>(currentPartners.size()) >= maxPartners) break;

                if (currentPartners.insert(nodeId).second) {
                    logEvent("Added partner: " + nodeId);
                    ++addedPartners;
                }
            }
        }

        logEvent("Total partnerships established: " + std::to_string(addedPartners));
    } catch (const std::exception &e) {
        logEvent("Error during partnership update: " + std::string(e.what()));
    }
}


// Terminate partnerships if they have expired
void PartnershipManager::terminateExpiredPartnerships(int roundNumber) {
    logEvent("Terminating expired partnerships for round: " + std::to_string(roundNumber));

    if ((std::stoi(nodeId) + roundNumber) % partnershipPeriod == 0) {
        std::lock_guard<std::mutex> lock(partnershipMutex);
        currentPartners.clear();
        logEvent("All expired partnerships have been terminated.");
    } else {
        logEvent("No partnerships terminated this round.");
    }
}

// Log current partnerships
void PartnershipManager::logCurrentPartnerships() const {
    std::lock_guard<std::mutex> lock(partnershipMutex);
    logEvent("Current active partnerships:");
    for (const auto &partner : currentPartners) {
        logEvent(" - Partner: " + partner);
    }
}

// Get a copy of the current partners (thread-safe)
std::unordered_set<std::string> PartnershipManager::getCurrentPartners() const {
    std::lock_guard<std::mutex> lock(partnershipMutex);
    return currentPartners;
}

// Select random partners from the membership list
std::vector<std::string> PartnershipManager::selectRandomPartners(int count, const std::unordered_map<std::string, NodeInfo> &membershipList) {
    logEvent("Selecting random partners from membership list.");

    std::vector<std::string> eligibleNodes;
    for (const auto &[nodeId, nodeInfo] : membershipList) {
        if (nodeId != this->nodeId) {
            eligibleNodes.push_back(nodeId);
        }
    }

    logEvent("Eligible nodes for random selection: " + std::to_string(eligibleNodes.size()));

    // Shuffle and limit size
    std::shuffle(eligibleNodes.begin(), eligibleNodes.end(), randomGenerator);
    if (count < static_cast<int>(eligibleNodes.size())) {
        eligibleNodes.resize(count);
    }

    logEvent("Selected partners:");
    for (const auto &partner : eligibleNodes) {
        logEvent(" - " + partner); // Log each selected partner
    }

    return eligibleNodes;
}

// Log events to both a file and console
void PartnershipManager::logEvent(const std::string &message) const {
    std::ofstream logStream(logFile, std::ios::app);
    if (logStream.is_open()) {
        logStream << "[" << getCurrentTime() << "] " << message << std::endl;
    }
    std::cout << "[" << getCurrentTime() << "] " << message << std::endl;
}

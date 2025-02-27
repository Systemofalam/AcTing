#include "partnerships.h"

#include <algorithm>
#include <chrono>
#include <cctype>     // For std::isdigit
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

// Helper function to extract the numeric portion from a node ID (e.g., "node1" returns 1).
static int extractNumericNodeId(const std::string &nodeId) {
    int num = 0;
    for (char c : nodeId) {
        if (std::isdigit(c)) {
            num = num * 10 + (c - '0');
        }
    }
    return num;
}

// Constructor.
PartnershipManager::PartnershipManager(const std::string &nodeId,
                                       int maxPartners,
                                       int partnershipPeriod,
                                       const std::string &logFile)
    : nodeId(nodeId), maxPartners(maxPartners), partnershipPeriod(partnershipPeriod), logFile(logFile)
{
    logEvent("PartnershipManager initialized for node: " + nodeId);
}

// Deterministic score: lower is better.
// Computes a hash-based score using a combination of (from, to, roundNumber).
size_t PartnershipManager::computeScore(const std::string &from, const std::string &to, int roundNumber) const {
    std::hash<std::string> hasher;
    std::string input = from + "_" + to + "_" + std::to_string(roundNumber);
    return hasher(input);
}

// Update our partnerships for the current round using symmetric selection.
// For each candidate, we compute a symmetric score defined as:
//   symmetricScore = min( computeScore(ourNode, candidate, roundNumber),
//                           computeScore(candidate, ourNode, roundNumber) )
// Then we sort all eligible candidates (excluding self and suspected nodes) by the symmetric score
// and select the top maxPartners. This guarantees bidirectionality if all nodes use the same algorithm.
void PartnershipManager::updatePartnerships(int roundNumber, const std::unordered_map<std::string, NodeInfo> &membershipList) {
    logEvent("Updating partnerships for round: " + std::to_string(roundNumber));

    int numericNodeId = extractNumericNodeId(nodeId);
    // Expire current partnerships if needed.
    if ((numericNodeId + roundNumber) % partnershipPeriod == 0) {
        logEvent("Partnership period expired. Clearing current partnerships.");
        currentPartners.clear();
    }

    // Build a vector of candidates: each candidate is paired with its symmetric score.
    std::vector<std::pair<size_t, std::string>> candidates;
    for (const auto &entry : membershipList) {
        const std::string &candidateId = entry.first;
        if (candidateId == nodeId)
            continue; // Exclude self.
        if (suspicionList.find(candidateId) != suspicionList.end()) {
            logEvent("Excluding candidate " + candidateId + " (suspected).");
            continue;
        }
        size_t scoreOurToCandidate = computeScore(nodeId, candidateId, roundNumber);
        size_t scoreCandidateToOur = computeScore(candidateId, nodeId, roundNumber);
        size_t symmetricScore = std::min(scoreOurToCandidate, scoreCandidateToOur);
        candidates.push_back({symmetricScore, candidateId});
    }

    if (candidates.empty()) {
        logEvent("No eligible nodes available for partnerships.");
        return;
    }

    // Sort candidates by their symmetric score (ascending).
    std::sort(candidates.begin(), candidates.end(), [](const auto &a, const auto &b) {
        return a.first < b.first;
    });

    // Select the top maxPartners candidates.
    std::unordered_set<std::string> newPartners;
    for (size_t i = 0; i < candidates.size() && newPartners.size() < static_cast<size_t>(maxPartners); i++) {
        newPartners.insert(candidates[i].second);
    }

    currentPartners = newPartners;

    // Log the final partnerships for this round.
    std::ostringstream oss;
    oss << "Total bidirectional partnerships established: " << currentPartners.size() << ". Partners:";
    for (const auto &partner : currentPartners) {
        oss << " " << partner;
    }
    logEvent(oss.str());
}

// Terminate partnerships if the expiration condition is met.
// In this case, if (numericNodeId + roundNumber) mod partnershipPeriod equals 0, we clear current partnerships.
void PartnershipManager::terminateExpiredPartnerships(int roundNumber) {
    int numericNodeId = extractNumericNodeId(nodeId);
    if ((numericNodeId + roundNumber) % partnershipPeriod == 0) {
        currentPartners.clear();
        logEvent("Partnerships terminated for round: " + std::to_string(roundNumber));
    } else {
        logEvent("No partnerships terminated for round: " + std::to_string(roundNumber));
    }
}

// Return the current set of partners.
std::unordered_set<std::string> PartnershipManager::getCurrentPartners() const {
    return currentPartners;
}

// Log the current active partnerships.
void PartnershipManager::logCurrentPartnerships() const {
    std::ostringstream oss;
    oss << "Current active bidirectional partnerships:";
    for (const auto &partner : currentPartners) {
        oss << " " << partner;
    }
    logEvent(oss.str());
}

// Add a node to the suspicion list.
void PartnershipManager::addToSuspicion(const std::string &suspectNode) {
    suspicionList.insert(suspectNode);
    logEvent("Node " + suspectNode + " added to suspicion list.");
}

// Log an event to the log file and also print it to the console.
void PartnershipManager::logEvent(const std::string &message) const {
    std::ofstream logStream(logFile, std::ios::app);
    if (logStream.is_open()) {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        logStream << "[" << now << "] " << message << std::endl;
    }
    std::cout << "[" << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())
              << "] " << message << std::endl;
}

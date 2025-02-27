#ifndef PARTNERSHIPS_H
#define PARTNERSHIPS_H

#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <string>
#include <random>
#include <mutex>
#include "membership.h" // For NodeInfo
#include "acting_utils.h" // For logging utilities

class PartnershipManager {
public:
    PartnershipManager(const std::string &nodeId, int maxPartners, int partnershipPeriod, const std::string &logFile);
    void updatePartnerships(int roundNumber, const std::unordered_map<std::string, NodeInfo> &membershipList);
    void terminateExpiredPartnerships(int roundNumber);
    std::unordered_set<std::string> getCurrentPartners() const;
    void logCurrentPartnerships() const;
    void addToSuspicion(const std::string &suspectNode);

private:
    std::string nodeId;                // Identifier of this node
    int maxPartners;                   // Maximum number of partnerships
    int partnershipPeriod;             // Number of rounds before partnerships are re-evaluated
    std::string logFile;               // File to log partnership updates

    mutable std::mutex partnershipMutex; // Mutex for thread-safe access
    std::unordered_set<std::string> currentPartners; // Current set of active partners
    std::unordered_set<std::string> suspicionList;
    std::mt19937 randomGenerator;      // Random number generator for selecting partners

    std::vector<std::string> selectRandomPartners(int count, const std::unordered_map<std::string, NodeInfo> &membershipList);
    void logEvent(const std::string &message) const;
    size_t computeScore(const std::string &from, const std::string &to, int roundNumber) const;
    int getRankInCandidateList(const std::string &candidate,
                               const std::unordered_map<std::string, NodeInfo> &membershipList,
                               int roundNumber) const;
};

#endif // PARTNERSHIPS_H

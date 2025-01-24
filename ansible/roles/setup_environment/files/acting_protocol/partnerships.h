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

    void initializePartnerships(int roundNumber, const std::unordered_map<std::string, NodeInfo> &membershipList);
    void updatePartnerships(int roundNumber, const std::unordered_map<std::string, NodeInfo> &membershipList);
    void terminateExpiredPartnerships(int roundNumber);
    void logCurrentPartnerships() const;

    std::unordered_set<std::string> getCurrentPartners() const;

private:
    std::string nodeId;                // Identifier of this node
    int maxPartners;                   // Maximum number of partnerships
    int partnershipPeriod;             // Number of rounds before partnerships are re-evaluated
    std::string logFile;               // File to log partnership updates

    mutable std::mutex partnershipMutex; // Mutex for thread-safe access
    std::unordered_set<std::string> currentPartners; // Current set of active partners
    std::mt19937 randomGenerator;      // Random number generator for selecting partners

    std::vector<std::string> selectRandomPartners(int count, const std::unordered_map<std::string, NodeInfo> &membershipList);
    void logEvent(const std::string &message) const;
};

#endif // PARTNERSHIPS_H

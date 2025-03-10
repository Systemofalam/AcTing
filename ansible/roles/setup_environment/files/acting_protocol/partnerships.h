#ifndef PARTNERSHIPS_H
#define PARTNERSHIPS_H

#include <string>
#include <unordered_set>
#include <unordered_map>
#include <vector>

// Ensure that NodeInfo is defined (e.g., in membership.h).
#include "membership.h"

class PartnershipManager {
public:
    // Constructor.
    // nodeId: This node's identifier.
    // maxPartners: Maximum number of partners to select.
    // partnershipPeriod: Round period after which current partnerships expire.
    // logFile: Path to the log file.
    PartnershipManager(const std::string &nodeId,
                       int maxPartners,
                       int partnershipPeriod,
                       const std::string &logFile);

    // Computes a deterministic score based on two node IDs and roundNumber.
    size_t computeScore(const std::string &from,
                        const std::string &to,
                        int roundNumber) const;

    // Updates the partnerships for the current round using a global greedy matching
    // method that enforces bidirectionality.
    void updatePartnerships(int roundNumber,
                            const std::unordered_map<std::string, NodeInfo> &membershipList);

    // Terminates (clears) partnerships if the expiration condition is met.
    void terminateExpiredPartnerships(int roundNumber);

    // Returns the current set of partners.
    std::unordered_set<std::string> getCurrentPartners() const;

    // Logs the current active partnerships.
    void logCurrentPartnerships() const;

    // Adds a node to the suspicion list.
    void addToSuspicion(const std::string &suspectNode);

    // Logs an event to the log file and to the console.
    void logEvent(const std::string &message) const;

private:
    // Data members.
    std::string nodeId;
    int maxPartners;
    int partnershipPeriod;
    std::string logFile;
    std::unordered_set<std::string> currentPartners;
    std::unordered_set<std::string> suspicionList;
};

#endif // PARTNERSHIPS_H

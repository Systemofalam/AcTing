#ifndef MEMBERSHIP_H
#define MEMBERSHIP_H

#include "acting_utils.h"
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <string>

// Global Variables for Membership Management
extern std::unordered_map<std::string, NodeInfo> membershipList;
extern std::unordered_map<std::string, std::unordered_set<std::string>> suspicionList;
extern std::mutex membershipMutex;

// Function Prototypes
bool addNode(const NodeInfo &newNode, const std::string &logFile);
bool removeNode(const std::string &nodeId, const std::string &logFile);
void handleSuspicion(const std::string &suspectingNode, const std::string &suspectedNode, const std::string &logFile);
void periodicMembershipUpdate(const std::string &logFile);
void startPeriodicMembershipUpdates(const std::string &logFile);
void handleJoinRequest(const NodeInfo &joiningNode, const std::string &sourceNode, const std::string &logFile);

#endif // MEMBERSHIP_H

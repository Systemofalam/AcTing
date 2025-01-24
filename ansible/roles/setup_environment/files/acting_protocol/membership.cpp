#include "membership.h"
#include "acting_utils.h"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>

// Global Variables
std::unordered_map<std::string, NodeInfo> membershipList;
std::unordered_map<std::string, std::unordered_set<std::string>> suspicionList;
std::mutex membershipMutex;

// Log events
void logEvent(const std::string &message, const std::string &logFile) {
    std::ofstream logStream(logFile, std::ios::app);
    if (logStream.is_open()) {
        logStream << "[" << getCurrentTime() << "] " << message << std::endl;
    }
    std::cout << "[" << getCurrentTime() << "] " << message << std::endl;
}

// Add a node to the membership list
bool addNode(const NodeInfo &newNode, const std::string &logFile) {
    logEvent("Attempting to add node: " + newNode.nodeId, logFile);

    {
        std::lock_guard<std::mutex> lock(membershipMutex); // Exclusive lock for modifying the list
        logEvent("Lock acquired for membership list (write).", logFile);

        if (membershipList.find(newNode.nodeId) != membershipList.end()) {
            logEvent("Node already in membership list: " + newNode.nodeId, logFile);
            return false;
        }
        membershipList[newNode.nodeId] = newNode;
        logEvent("Node added to membership list: " + newNode.nodeId, logFile);
    }

    logEvent("Lock released for membership list (write).", logFile);
    return true;
}

// Remove a node from the membership list
bool removeNode(const std::string &nodeId, const std::string &logFile) {
    logEvent("Attempting to remove node: " + nodeId, logFile);

    std::lock_guard<std::mutex> lock(membershipMutex); // Exclusive lock for modifying the list
    if (membershipList.erase(nodeId)) {
        logEvent("Node removed from membership list: " + nodeId, logFile);
        return true;
    }
    logEvent("Node not found in membership list: " + nodeId, logFile);
    return false;
}

// Handle suspicion
void handleSuspicion(const std::string &suspectingNode, const std::string &suspectedNode, const std::string &logFile) {
    logEvent("Handling suspicion for node: " + suspectedNode, logFile);

    std::lock_guard<std::mutex> lock(membershipMutex); // Exclusive lock for modifying suspicion list
    suspicionList[suspectedNode].insert(suspectingNode);

    if (suspicionList[suspectedNode].size() >= SUSPECT_THRESHOLD) {
        logEvent("Suspected node reached threshold: " + suspectedNode, logFile);
        removeNode(suspectedNode, logFile);
        suspicionList.erase(suspectedNode);
    }
}

// Periodic membership updates
void periodicMembershipUpdate(const std::string &logFile) {
    logEvent("Updating membership list...", logFile);

    std::lock_guard<std::mutex> lock(membershipMutex); // Shared lock for reading the list
    for (const auto &[nodeId, info] : membershipList) {
        logEvent(" - " + nodeId + " (" + info.ipAddress + ":" + std::to_string(info.port) + ")", logFile);
    }
}

// Start periodic membership updates in a separate thread
void startPeriodicMembershipUpdates(const std::string &logFile) {
    std::thread([logFile]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(MEMBERSHIP_UPDATE_INTERVAL));
            periodicMembershipUpdate(logFile);
        }
    }).detach();
}

// Handle a join request
void handleJoinRequest(const NodeInfo &joiningNode, const std::string &sourceNode, const std::string &logFile) {
    logEvent("Handling join request for node: " + joiningNode.nodeId, logFile);

    if (addNode(joiningNode, logFile)) {
        logEvent("Source node " + sourceNode + " informed of the new node: " + joiningNode.nodeId, logFile);
    } else {
        logEvent("Node already exists in membership list: " + joiningNode.nodeId, logFile);
    }
}

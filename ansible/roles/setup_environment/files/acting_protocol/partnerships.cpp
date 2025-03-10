// partnerships.cpp
#include "partnerships.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>

// Helper: extract numeric portion from a node ID (e.g., "node12" returns 12).
static int extractNumericNodeId(const std::string &nodeId) {
    int num = 0;
    for (char c : nodeId) {
        if (std::isdigit(c)) {
            num = num * 10 + (c - '0');
        }
    }
    return num;
}

// Structure representing an unordered edge between two nodes.
struct Edge {
    std::string u;
    std::string v;
    size_t weight;  // Lower weight indicates a stronger (better) pairing.
};

// Compare edges by weight (ascending). Tie-break using u then v.
static bool compareEdges(const Edge &e1, const Edge &e2) {
    if (e1.weight == e2.weight) {
        if (e1.u == e2.u)
            return e1.v < e2.v;
        return e1.u < e2.u;
    }
    return e1.weight < e2.weight;
}

//////////////////////
// PartnershipManager
//////////////////////

// Constructor.
PartnershipManager::PartnershipManager(const std::string &nodeId,
                                       int maxPartners,
                                       int partnershipPeriod,
                                       const std::string &logFile)
    : nodeId(nodeId), maxPartners(maxPartners), partnershipPeriod(partnershipPeriod), logFile(logFile)
{
    logEvent("PartnershipManager initialized for node: " + nodeId);
}

// Computes a deterministic (one-way) score.
size_t PartnershipManager::computeScore(const std::string &from,
                                        const std::string &to,
                                        int roundNumber) const {
    std::hash<std::string> hasher;
    std::string input = from + "_" + to + "_" + std::to_string(roundNumber);
    return hasher(input);
}

// Update partnerships using a global greedy b-matching algorithm.
// This algorithm computes all unordered edges (u,v) among eligible nodes (excluding self and suspicious nodes).
// Each edge’s weight is the minimum of computeScore(u,v) and computeScore(v,u). Then, edges are sorted
// in ascending order. Iterating through the sorted edges, an edge is accepted if both endpoints have not
// yet reached maxPartners. Because an edge is added only when both endpoints are available, the matching
// is bidirectional.
// To reduce bias, the list of nodes is sorted using a deterministic randomized order (seeded with roundNumber).
void PartnershipManager::updatePartnerships(int roundNumber,
                                            const std::unordered_map<std::string, NodeInfo> &membershipList) {
    logEvent("Updating partnerships for round: " + std::to_string(roundNumber));

    int numericNodeId = extractNumericNodeId(nodeId);
    // Optional: clear partnerships on expiration.
    if ((numericNodeId + roundNumber) % partnershipPeriod == 0) {
        logEvent("Partnership period expired. Clearing current partnerships.");
        currentPartners.clear();
    }
    
    // Build a list of eligible nodes (exclude self and suspicious nodes).
    std::vector<std::string> nodes;
    for (const auto &entry : membershipList) {
        if (entry.first == nodeId)
            continue;
        if (suspicionList.find(entry.first) != suspicionList.end())
            continue;
        nodes.push_back(entry.first);
    }
    // Sort nodes by a deterministic randomized order (using roundNumber as seed).
    std::sort(nodes.begin(), nodes.end(), [&](const std::string &a, const std::string &b) {
        size_t ha = std::hash<std::string>{}(a + "_" + std::to_string(roundNumber));
        size_t hb = std::hash<std::string>{}(b + "_" + std::to_string(roundNumber));
        return ha < hb;
    });
    
    // Build all unordered edges among these nodes.
    std::vector<Edge> edges;
    for (size_t i = 0; i < nodes.size(); i++) {
        for (size_t j = i + 1; j < nodes.size(); j++) {
            Edge e;
            e.u = nodes[i];
            e.v = nodes[j];
            e.weight = std::min(computeScore(e.u, e.v, roundNumber),
                                computeScore(e.v, e.u, roundNumber));
            edges.push_back(e);
        }
    }
    std::sort(edges.begin(), edges.end(), compareEdges);
    
    // Initialize degree counts for every eligible node (including self).
    std::unordered_map<std::string, int> degree;
    degree[nodeId] = 0;
    for (const auto &entry : membershipList) {
        if (entry.first == nodeId)
            continue;
        if (suspicionList.find(entry.first) == suspicionList.end())
            degree[entry.first] = 0;
    }
    
    // Greedy matching: iterate through edges and add an edge if both endpoints have not reached maxPartners.
    std::unordered_set<std::string> myPartners;
    for (const auto &e : edges) {
        if (degree[e.u] < maxPartners && degree[e.v] < maxPartners) {
            degree[e.u]++;
            degree[e.v]++;
            // Record the partner for our node.
            if (e.u == nodeId)
                myPartners.insert(e.v);
            if (e.v == nodeId)
                myPartners.insert(e.u);
        }
    }
    
    // Fallback: if we have fewer than maxPartners, fill in from our own candidate ranking.
    if (myPartners.size() < static_cast<size_t>(maxPartners)) {
        std::vector<std::pair<size_t, std::string>> desired;
        for (const auto &entry : membershipList) {
            if (entry.first == nodeId)
                continue;
            if (suspicionList.find(entry.first) != suspicionList.end())
                continue;
            size_t symScore = std::min(computeScore(nodeId, entry.first, roundNumber),
                                        computeScore(entry.first, nodeId, roundNumber));
            desired.push_back({symScore, entry.first});
        }
        std::sort(desired.begin(), desired.end(), [](const auto &a, const auto &b) {
            return (a.first == b.first) ? (a.second < b.second) : (a.first < b.first);
        });
        for (size_t i = 0; i < desired.size() && myPartners.size() < static_cast<size_t>(maxPartners); i++) {
            myPartners.insert(desired[i].second);
        }
    }
    
    currentPartners = myPartners;
    
    std::ostringstream oss;
    oss << "Total bidirectional partnerships established: " << currentPartners.size() << ". Partners:";
    for (const auto &partner : currentPartners)
        oss << " " << partner;
    logEvent(oss.str());
}

// Terminates partnerships if the expiration condition is met.
void PartnershipManager::terminateExpiredPartnerships(int roundNumber) {
    int numericNodeId = extractNumericNodeId(nodeId);
    if ((numericNodeId + roundNumber) % partnershipPeriod == 0) {
        currentPartners.clear();
        logEvent("Partnerships terminated for round: " + std::to_string(roundNumber));
    } else {
        logEvent("No partnerships terminated for round: " + std::to_string(roundNumber));
    }
}

// Returns the current set of partners.
std::unordered_set<std::string> PartnershipManager::getCurrentPartners() const {
    return currentPartners;
}

// Logs the current active partnerships.
void PartnershipManager::logCurrentPartnerships() const {
    std::ostringstream oss;
    oss << "Current active bidirectional partnerships:";
    for (const auto &partner : currentPartners) {
        oss << " " << partner;
    }
    logEvent(oss.str());
}

// Adds a node to the suspicion list.
void PartnershipManager::addToSuspicion(const std::string &suspectNode) {
    suspicionList.insert(suspectNode);
    logEvent("Node " + suspectNode + " added to suspicion list.");
}

// Logs an event to the log file and prints it to the console.
void PartnershipManager::logEvent(const std::string &message) const {
    std::ofstream logStream(logFile, std::ios::app);
    if (logStream.is_open()) {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        logStream << "[" << now << "] " << message << std::endl;
    }
    std::cout << "[" << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())
              << "] " << message << std::endl;
}

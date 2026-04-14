#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace proxy_core {

// Action taken by the policy engine for a given flow.
enum class PolicyVerdict { Allow, Deny, Log };

struct FlowDescriptor {
    std::string src_ip;
    uint16_t    src_port = 0;
    std::string dst_host;
    uint16_t    dst_port = 0;
    std::string protocol;   // "tcp" | "udp"
    std::string user_id;    // authenticated user (may be empty)
};

struct PolicyRule {
    std::string     id;
    std::string     description;
    // Match criteria (empty = wildcard).
    std::string     src_ip_prefix;  // CIDR notation, e.g. "10.0.0.0/8"
    std::string     dst_host_glob;  // glob, e.g. "*.example.com"
    std::vector<uint16_t> dst_ports; // empty = all
    PolicyVerdict   verdict = PolicyVerdict::Deny;
    int             priority = 100; // lower = evaluated first
};

// Evaluates traffic flows against an ordered set of rules.
// Default verdict when no rule matches: Allow.
class PolicyEngine {
public:
    PolicyEngine() = default;

    // Load rules from a JSON file.
    void load_rules(const std::string& path);

    // Add / replace a single rule.
    void add_rule(PolicyRule rule);

    // Remove a rule by id.
    void remove_rule(const std::string& id);

    // Evaluate a flow; returns first matching rule's verdict (or Allow if none).
    PolicyVerdict evaluate(const FlowDescriptor& flow) const;

    // Return a copy of all rules sorted by priority.
    std::vector<PolicyRule> rules() const;

private:
    mutable std::mutex mu_;
    std::vector<PolicyRule> rules_;  // maintained sorted by priority

    static bool matches_cidr(const std::string& ip, const std::string& cidr);
    static bool matches_glob(const std::string& str, const std::string& pattern);
};

} // namespace proxy_core

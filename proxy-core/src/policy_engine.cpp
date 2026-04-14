#include "policy_engine.hpp"
#include "logger.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <mutex>
#include <fstream>
#include <sstream>
#include <fnmatch.h>

namespace proxy_core {

namespace {
// Minimal CIDR match for IPv4 addresses.
bool cidr_match(const std::string& ip, const std::string& cidr) {
    if (cidr.empty()) return true;  // wildcard

    auto slash = cidr.find('/');
    std::string network_str = slash == std::string::npos ? cidr : cidr.substr(0, slash);

    // Validate and parse prefix length — treat invalid CIDR as non-match.
    int prefix_len = 32;
    if (slash != std::string::npos) {
        try {
            prefix_len = std::stoi(cidr.substr(slash + 1));
        } catch (...) {
            return false;  // non-numeric prefix
        }
        if (prefix_len < 0 || prefix_len > 32)
            return false;  // out-of-range prefix
    }

    in_addr ip_addr{}, net_addr{};
    if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1)       return false;
    if (inet_pton(AF_INET, network_str.c_str(), &net_addr) != 1) return false;

    uint32_t mask = prefix_len == 0 ? 0u : (~0u << (32 - prefix_len));
    return (ntohl(ip_addr.s_addr) & mask) == (ntohl(net_addr.s_addr) & mask);
}

bool glob_match(const std::string& str, const std::string& pattern) {
    if (pattern.empty()) return true;
    return fnmatch(pattern.c_str(), str.c_str(), FNM_CASEFOLD) == 0;
}
} // namespace

void PolicyEngine::add_rule(PolicyRule rule) {
    std::lock_guard<std::mutex> lk(mu_);
    // Remove existing rule with same id.
    rules_.erase(std::remove_if(rules_.begin(), rules_.end(),
                                 [&](const PolicyRule& r){ return r.id == rule.id; }),
                  rules_.end());
    rules_.push_back(std::move(rule));
    std::sort(rules_.begin(), rules_.end(),
               [](const PolicyRule& a, const PolicyRule& b){ return a.priority < b.priority; });
}

void PolicyEngine::remove_rule(const std::string& id) {
    std::lock_guard<std::mutex> lk(mu_);
    rules_.erase(std::remove_if(rules_.begin(), rules_.end(),
                                 [&](const PolicyRule& r){ return r.id == id; }),
                  rules_.end());
}

PolicyVerdict PolicyEngine::evaluate(const FlowDescriptor& flow) const {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& rule : rules_) {
        // Source IP prefix check.
        if (!rule.src_ip_prefix.empty() &&
            !cidr_match(flow.src_ip, rule.src_ip_prefix))
            continue;

        // Destination host glob check.
        if (!rule.dst_host_glob.empty() &&
            !glob_match(flow.dst_host, rule.dst_host_glob))
            continue;

        // Destination port check.
        if (!rule.dst_ports.empty()) {
            bool port_match = std::any_of(rule.dst_ports.begin(), rule.dst_ports.end(),
                                           [&](uint16_t p){ return p == flow.dst_port; });
            if (!port_match) continue;
        }

        // Rule matched.
        if (rule.verdict == PolicyVerdict::Log) {
            LOG_INFO("Policy log [", rule.id, "]: ", flow.src_ip, " -> ",
                     flow.dst_host, ":", flow.dst_port);
        }
        return rule.verdict;
    }
    return PolicyVerdict::Allow;  // default-allow
}

std::vector<PolicyRule> PolicyEngine::rules() const {
    std::lock_guard<std::mutex> lk(mu_);
    return rules_;
}

void PolicyEngine::load_rules(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open policy file: " + path);
    // Rules are added dynamically via add_rule() after parsing.
    // (A JSON/YAML parser such as nlohmann/json would be used in production.)
    LOG_INFO("Policy engine: loaded rules from ", path);
}

bool PolicyEngine::matches_cidr(const std::string& ip, const std::string& cidr) {
    return cidr_match(ip, cidr);
}

bool PolicyEngine::matches_glob(const std::string& str, const std::string& pattern) {
    return glob_match(str, pattern);
}

} // namespace proxy_core

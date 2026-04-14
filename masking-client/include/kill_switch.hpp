#pragma once
#include <string>
#include <atomic>

namespace masking_client {

// Kill-switch: blocks all non-proxy traffic by inserting iptables rules.
// When enabled, only connections to the configured proxy ingress are allowed.
// Requires root / CAP_NET_ADMIN.
class KillSwitch {
public:
    explicit KillSwitch(const std::string& proxy_host, uint16_t proxy_port);
    ~KillSwitch();

    // Install iptables rules to block non-proxy egress.
    // Returns true on success.
    bool enable();

    // Remove the installed rules.
    bool disable();

    bool is_enabled() const { return enabled_.load(); }

    // Update allowed proxy endpoint (re-applies rules if enabled).
    void update_endpoint(const std::string& host, uint16_t port);

private:
    std::string        proxy_host_;
    uint16_t           proxy_port_;
    std::atomic<bool>  enabled_{false};

    bool run_iptables(const std::string& args) const;
    bool apply_rules() const;
    bool remove_rules() const;

    // iptables chain name used for kill-switch rules.
    static constexpr const char* CHAIN = "PROXY_KILL_SWITCH";
};

} // namespace masking_client

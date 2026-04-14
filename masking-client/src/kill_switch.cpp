#include "kill_switch.hpp"
#include <cstdlib>
#include <cstdio>
#include <sstream>
#include <stdexcept>

namespace masking_client {

KillSwitch::KillSwitch(const std::string& proxy_host, uint16_t proxy_port)
    : proxy_host_(proxy_host), proxy_port_(proxy_port) {}

KillSwitch::~KillSwitch() {
    if (enabled_) {
        try { disable(); } catch (...) {}
    }
}

bool KillSwitch::run_iptables(const std::string& args) const {
    std::string cmd = "iptables " + args + " 2>/dev/null";
    return std::system(cmd.c_str()) == 0;
}

bool KillSwitch::apply_rules() const {
    // Make rule application idempotent in case of a previous crash:
    // 1. Create the custom chain (ignore error if it already exists).
    run_iptables("-N " + std::string(CHAIN));
    // 2. Flush the chain to remove any stale/duplicate rules.
    run_iptables("-F " + std::string(CHAIN));

    // Allow established / related.
    run_iptables("-A " + std::string(CHAIN) +
                  " -m state --state ESTABLISHED,RELATED -j ACCEPT");

    // Allow loopback.
    run_iptables("-A " + std::string(CHAIN) + " -o lo -j ACCEPT");

    // Allow DNS (UDP/TCP port 53).
    run_iptables("-A " + std::string(CHAIN) + " -p udp --dport 53 -j ACCEPT");
    run_iptables("-A " + std::string(CHAIN) + " -p tcp --dport 53 -j ACCEPT");

    // Allow outbound to proxy ingress.
    std::ostringstream allow_proxy;
    allow_proxy << "-A " << CHAIN
                << " -d " << proxy_host_
                << " -p tcp --dport " << proxy_port_
                << " -j ACCEPT";
    run_iptables(allow_proxy.str());

    // Block everything else.
    run_iptables("-A " + std::string(CHAIN) + " -j DROP");

    // Attach chain to OUTPUT only if not already attached (-C checks for the rule).
    bool jump_exists = run_iptables("-C OUTPUT -j " + std::string(CHAIN));
    if (!jump_exists) {
        bool ok = run_iptables("-I OUTPUT 1 -j " + std::string(CHAIN));
        return ok;
    }
    return true;
}

bool KillSwitch::remove_rules() const {
    // Remove all OUTPUT jumps to the chain (in case of duplicate insertions).
    while (run_iptables("-D OUTPUT -j " + std::string(CHAIN))) {
        // keep deleting until no more references exist
    }
    run_iptables("-F " + std::string(CHAIN));
    run_iptables("-X " + std::string(CHAIN));
    return true;
}

bool KillSwitch::enable() {
    if (enabled_) return true;
    bool ok = apply_rules();
    if (ok) enabled_ = true;
    return ok;
}

bool KillSwitch::disable() {
    if (!enabled_) return true;
    bool ok = remove_rules();
    if (ok) enabled_ = false;
    return ok;
}

void KillSwitch::update_endpoint(const std::string& host, uint16_t port) {
    bool was_enabled = enabled_.load();
    if (was_enabled) disable();
    proxy_host_ = host;
    proxy_port_ = port;
    if (was_enabled) enable();
}

} // namespace masking_client

#pragma once
#include <string>
#include <cstdint>

namespace proxy_core {

// Top-level configuration loaded from proxy.conf.
struct ProxyConfig {
    // Listening interface / port for inbound client connections.
    std::string listen_host   = "0.0.0.0";
    uint16_t    listen_port   = 1080;   // SOCKS5 default

    // HTTP CONNECT proxy port (0 = disabled).
    uint16_t    http_port     = 8080;

    // Internal control / metrics endpoint.
    std::string control_host  = "127.0.0.1";
    uint16_t    control_port  = 9090;

    // TLS material for inter-node links.
    std::string tls_cert_file;
    std::string tls_key_file;
    std::string tls_ca_file;
    bool        mutual_tls    = true;

    // Connection management.
    size_t max_connections    = 10000;
    size_t thread_pool_size   = 0;  // 0 = hardware_concurrency

    // Timeouts (seconds).
    uint32_t connect_timeout  = 10;
    uint32_t idle_timeout     = 300;
    uint32_t handshake_timeout = 15;

    // Rate limiting: maximum new connections per second per source IP.
    uint32_t rate_limit_cps   = 50;

    // Node role: "ingress", "relay", or "egress".
    std::string node_role     = "ingress";

    // Next hop node (relay/egress) address.
    std::string next_hop_host;
    uint16_t    next_hop_port = 0;

    // Logging.
    std::string log_level     = "info";   // debug|info|warn|error
    std::string log_file;                 // empty = stderr

    // Load from file; throws std::runtime_error on parse error.
    static ProxyConfig from_file(const std::string& path);
};

} // namespace proxy_core

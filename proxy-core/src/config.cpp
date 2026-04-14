#include "config.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace proxy_core {

ProxyConfig ProxyConfig::from_file(const std::string& path) {
    ProxyConfig cfg;
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open config file: " + path);

    std::string line;
    while (std::getline(f, line)) {
        // Strip comments and whitespace.
        auto comment = line.find('#');
        if (comment != std::string::npos) line = line.substr(0, comment);
        if (line.empty()) continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        // Trim whitespace.
        auto trim = [](std::string& s) {
            s.erase(0, s.find_first_not_of(" \t\r\n"));
            s.erase(s.find_last_not_of(" \t\r\n") + 1);
        };
        trim(key); trim(val);

        if (key == "listen_host")      cfg.listen_host   = val;
        else if (key == "listen_port") cfg.listen_port   = static_cast<uint16_t>(std::stoi(val));
        else if (key == "http_port")   cfg.http_port     = static_cast<uint16_t>(std::stoi(val));
        else if (key == "control_host") cfg.control_host = val;
        else if (key == "control_port") cfg.control_port = static_cast<uint16_t>(std::stoi(val));
        else if (key == "tls_cert_file") cfg.tls_cert_file = val;
        else if (key == "tls_key_file")  cfg.tls_key_file  = val;
        else if (key == "tls_ca_file")   cfg.tls_ca_file   = val;
        else if (key == "mutual_tls")    cfg.mutual_tls    = (val == "true" || val == "1");
        else if (key == "max_connections")  cfg.max_connections  = static_cast<size_t>(std::stoul(val));
        else if (key == "thread_pool_size") cfg.thread_pool_size = static_cast<size_t>(std::stoul(val));
        else if (key == "connect_timeout")  cfg.connect_timeout  = static_cast<uint32_t>(std::stoul(val));
        else if (key == "idle_timeout")     cfg.idle_timeout     = static_cast<uint32_t>(std::stoul(val));
        else if (key == "handshake_timeout") cfg.handshake_timeout = static_cast<uint32_t>(std::stoul(val));
        else if (key == "rate_limit_cps") cfg.rate_limit_cps = static_cast<uint32_t>(std::stoul(val));
        else if (key == "node_role")     cfg.node_role     = val;
        else if (key == "next_hop_host") cfg.next_hop_host = val;
        else if (key == "next_hop_port") cfg.next_hop_port = static_cast<uint16_t>(std::stoi(val));
        else if (key == "log_level")     cfg.log_level     = val;
        else if (key == "log_file")      cfg.log_file      = val;
    }
    return cfg;
}

} // namespace proxy_core

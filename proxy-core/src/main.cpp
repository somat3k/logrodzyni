#include "proxy_server.hpp"
#include "config.hpp"
#include <filesystem>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    std::string config_path = "/etc/proxy-core/proxy.conf";
    if (argc == 2) {
        // Normalize the caller-supplied path to remove traversal sequences.
        config_path = std::filesystem::weakly_canonical(argv[1]).string();
    } else if (argc > 2) {
        std::cerr << "Usage: proxy-core [config-file]\n";
        return 1;
    }

    proxy_core::ProxyConfig cfg;
    try {
        cfg = proxy_core::ProxyConfig::from_file(config_path);
    } catch (const std::exception& e) {
        std::cerr << "Config error: " << e.what() << "\n";
        // Use defaults if config not found.
    }

    proxy_core::ProxyServer server(cfg);
    server.run();
    return 0;
}

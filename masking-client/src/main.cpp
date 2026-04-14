#include "masking_client.hpp"
#include "profile_manager.hpp"
#include <iostream>
#include <thread>
#include <csignal>
#include <atomic>

static std::atomic<bool> g_stop{false};
static masking_client::MaskingClient* g_client = nullptr;

static void signal_handler(int) {
    g_stop = true;
    if (g_client) g_client->stop();
}

int main(int argc, char* argv[]) {
    std::string config = std::string(getenv("HOME") ? getenv("HOME") : ".") +
                         "/.config/masking-client/client.conf";
    if (argc == 2) config = argv[1];

    masking_client::ProfileManager profiles(config);
    profiles.load();

    // Ensure at least a default profile exists.
    if (profiles.names().empty()) {
        masking_client::Profile def;
        def.name       = "standard";
        def.proxy_host = "127.0.0.1";
        def.proxy_port = 1080;
        def.use_tls    = false;
        profiles.set(def);
        profiles.set_active("standard");
        std::cout << "Created default profile: standard (127.0.0.1:1080)\n";
    }

    masking_client::MaskingClient client(profiles);
    g_client = &client;

    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    client.on_state_change([](masking_client::ConnectionState s, const std::string& msg) {
        const char* names[] = {"Disconnected", "Connecting", "Connected", "Error"};
        std::cout << "[State] " << names[int(s)];
        if (!msg.empty()) std::cout << " - " << msg;
        std::cout << "\n";
    });

    // Start io thread.
    std::thread io_thread([&client]() { client.run(); });

    client.connect();

    std::cout << "Masking client running. Press Ctrl+C to stop.\n";
    std::cout << "Active profile : " << profiles.active() << "\n";
    std::cout << "Kill-switch    : " << (client.kill_switch_enabled() ? "ON" : "OFF") << "\n";

    io_thread.join();
    g_client = nullptr;
    return 0;
}

#pragma once
#include "profile_manager.hpp"
#include "kill_switch.hpp"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <atomic>
#include <string>
#include <functional>

namespace masking_client {

enum class ConnectionState { Disconnected, Connecting, Connected, Error };

// Lightweight masking client: routes traffic through a proxy circuit.
// Exposes a local SOCKS5 server that tunnels through the upstream circuit.
class MaskingClient {
public:
    using StateCallback = std::function<void(ConnectionState, const std::string&)>;

    explicit MaskingClient(ProfileManager& profiles);
    ~MaskingClient();

    // Connect using the currently active profile.
    void connect();

    // Disconnect from the current circuit.
    void disconnect();

    // Switch to a named profile; reconnects automatically if already connected.
    void switch_profile(const std::string& profile_name);

    // Toggle kill-switch.
    void set_kill_switch(bool enabled);
    bool kill_switch_enabled() const;

    ConnectionState state() const { return state_.load(); }

    // Register a callback for state changes (called from io thread).
    void on_state_change(StateCallback cb) { state_cb_ = std::move(cb); }

    // Start background io event loop (blocks until stop()).
    void run();
    void stop();

    // Local SOCKS5 listening port (for apps to configure).
    uint16_t local_port() const { return local_port_; }

private:
    void do_reconnect();
    void schedule_reconnect(int delay_sec);
    void set_state(ConnectionState s, const std::string& msg = {});

    ProfileManager&           profiles_;
    boost::asio::io_context   ioc_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    std::unique_ptr<KillSwitch> kill_switch_;
    boost::asio::steady_timer   reconnect_timer_;

    std::atomic<ConnectionState> state_{ConnectionState::Disconnected};
    StateCallback                state_cb_;
    uint16_t                     local_port_ = 1081;
    int                          reconnect_attempts_ = 0;
    bool                         stopped_ = false;
};

} // namespace masking_client

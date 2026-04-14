#include "masking_client.hpp"
#include <iostream>
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <thread>

namespace masking_client {

static constexpr int MAX_RECONNECT_DELAY_SEC = 60;

MaskingClient::MaskingClient(ProfileManager& profiles)
    : profiles_(profiles),
      work_guard_(boost::asio::make_work_guard(ioc_)),
      reconnect_timer_(ioc_) {}

MaskingClient::~MaskingClient() { stop(); }

void MaskingClient::set_state(ConnectionState s, const std::string& msg) {
    state_.store(s);
    if (state_cb_) state_cb_(s, msg);

    const char* names[] = {"Disconnected", "Connecting", "Connected", "Error"};
    std::cout << "[MaskingClient] " << names[int(s)];
    if (!msg.empty()) std::cout << ": " << msg;
    std::cout << std::endl;
}

void MaskingClient::connect() {
    if (state_ == ConnectionState::Connecting ||
        state_ == ConnectionState::Connected) return;
    reconnect_attempts_ = 0;
    do_reconnect();
}

void MaskingClient::do_reconnect() {
    if (stopped_) return;
    set_state(ConnectionState::Connecting);

    try {
        const Profile& prof = profiles_.get(profiles_.active());

        // Update kill switch endpoint before connecting.
        if (kill_switch_ && kill_switch_->is_enabled())
            kill_switch_->update_endpoint(prof.proxy_host, prof.proxy_port);

        // In a full implementation: establish SOCKS5 tunnel to ingress node
        // and start a local SOCKS5 listener that relays through the circuit.
        // For now, validate that the profile is properly configured.
        if (prof.proxy_host.empty())
            throw std::runtime_error("Profile has no proxy_host configured");

        set_state(ConnectionState::Connected,
                  prof.proxy_host + ":" + std::to_string(prof.proxy_port));
        reconnect_attempts_ = 0;
    } catch (const std::exception& e) {
        set_state(ConnectionState::Error, e.what());
        int delay = std::min(static_cast<int>(std::pow(2, reconnect_attempts_)),
                             MAX_RECONNECT_DELAY_SEC);
        ++reconnect_attempts_;
        schedule_reconnect(delay);
    }
}

void MaskingClient::schedule_reconnect(int delay_sec) {
    if (stopped_) return;
    std::cout << "[MaskingClient] Reconnecting in " << delay_sec << "s...\n";
    reconnect_timer_.expires_after(std::chrono::seconds(delay_sec));
    reconnect_timer_.async_wait([this](boost::system::error_code ec) {
        if (!ec && !stopped_) do_reconnect();
    });
}

void MaskingClient::disconnect() {
    reconnect_timer_.cancel();
    if (kill_switch_ && kill_switch_->is_enabled())
        kill_switch_->disable();
    set_state(ConnectionState::Disconnected);
}

void MaskingClient::switch_profile(const std::string& profile_name) {
    profiles_.set_active(profile_name);
    if (state_ == ConnectionState::Connected ||
        state_ == ConnectionState::Connecting) {
        disconnect();
        reconnect_attempts_ = 0;
        do_reconnect();
    }
}

void MaskingClient::set_kill_switch(bool enabled) {
    if (!kill_switch_) {
        try {
            const Profile& p = profiles_.get(profiles_.active());
            kill_switch_ = std::make_unique<KillSwitch>(p.proxy_host, p.proxy_port);
        } catch (const std::exception&) {
            kill_switch_ = std::make_unique<KillSwitch>("", 0);
        }
    }
    if (enabled)
        kill_switch_->enable();
    else
        kill_switch_->disable();
}

bool MaskingClient::kill_switch_enabled() const {
    return kill_switch_ && kill_switch_->is_enabled();
}

void MaskingClient::run() {
    ioc_.run();
}

void MaskingClient::stop() {
    if (stopped_) return;
    stopped_ = true;
    disconnect();
    work_guard_.reset();
    ioc_.stop();
}

} // namespace masking_client

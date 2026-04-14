#pragma once
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <string>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace proxy_core {

struct ProxyConfig;
class  PolicyEngine;
class  RateLimiter;
class  Session;

// Owns the acceptor(s) and produces Session objects.
class ConnectionManager {
public:
    explicit ConnectionManager(boost::asio::io_context& ioc,
                               const ProxyConfig& cfg,
                               PolicyEngine& policy,
                               RateLimiter& rate_limiter);

    // Start accepting on configured ports.
    void start();

    // Stop accepting and close all sessions gracefully.
    void stop();

    // Active session count.
    size_t session_count() const;

private:
    void do_accept_tcp(boost::asio::ip::tcp::acceptor& acceptor);
    void register_session(std::shared_ptr<Session> sess);
    void unregister_session(uint64_t id);

    boost::asio::io_context&          ioc_;
    const ProxyConfig&                cfg_;
    PolicyEngine&                     policy_;
    RateLimiter&                      rate_limiter_;

    boost::asio::ip::tcp::acceptor    socks_acceptor_;
    boost::asio::ip::tcp::acceptor    http_acceptor_;

    mutable std::mutex                sessions_mu_;
    std::unordered_map<uint64_t, std::weak_ptr<Session>> sessions_;

    std::atomic<bool> stopped_{false};
};

} // namespace proxy_core

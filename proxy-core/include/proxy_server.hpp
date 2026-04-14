#pragma once
#include "config.hpp"
#include "connection_manager.hpp"
#include "policy_engine.hpp"
#include "rate_limiter.hpp"
#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <thread>

namespace proxy_core {

// Top-level server object; owns io_context, thread pool, and subsystems.
class ProxyServer {
public:
    explicit ProxyServer(ProxyConfig cfg);
    ~ProxyServer();

    // Block until stop() is called.
    void run();

    // Signal a clean shutdown (thread-safe).
    void stop();

private:
    void setup_signals();

    ProxyConfig                          cfg_;
    boost::asio::io_context              ioc_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    std::unique_ptr<PolicyEngine>        policy_;
    std::unique_ptr<RateLimiter>         rate_limiter_;
    std::unique_ptr<ConnectionManager>   conn_mgr_;
    std::vector<std::thread>             threads_;
    boost::asio::signal_set              signals_;
};

} // namespace proxy_core

#include "proxy_server.hpp"
#include "logger.hpp"
#include <thread>

namespace proxy_core {

ProxyServer::ProxyServer(ProxyConfig cfg)
    : cfg_(std::move(cfg)),
      work_guard_(net::make_work_guard(ioc_)),
      policy_(std::make_unique<PolicyEngine>()),
      rate_limiter_(std::make_unique<RateLimiter>(cfg_.rate_limit_cps)),
      conn_mgr_(std::make_unique<ConnectionManager>(ioc_, cfg_, *policy_, *rate_limiter_)),
      signals_(ioc_, SIGINT, SIGTERM) {
    Logger::instance().set_level(cfg_.log_level);
    if (!cfg_.log_file.empty())
        Logger::instance().open_file(cfg_.log_file);
}

ProxyServer::~ProxyServer() {
    stop();
    for (auto& t : threads_)
        if (t.joinable()) t.join();
}

void ProxyServer::run() {
    setup_signals();
    conn_mgr_->start();

    size_t nthreads = cfg_.thread_pool_size > 0
                          ? cfg_.thread_pool_size
                          : std::max(1u, std::thread::hardware_concurrency());
    LOG_INFO("Starting thread pool with ", nthreads, " thread(s)");

    for (size_t i = 0; i < nthreads; ++i)
        threads_.emplace_back([this] { ioc_.run(); });

    for (auto& t : threads_)
        if (t.joinable()) t.join();

    LOG_INFO("ProxyServer shutdown complete.");
}

void ProxyServer::stop() {
    if (conn_mgr_) conn_mgr_->stop();
    work_guard_.reset();
    ioc_.stop();
}

void ProxyServer::setup_signals() {
    signals_.async_wait([this](boost::system::error_code, int signo) {
        LOG_INFO("Received signal ", signo, " - initiating graceful shutdown");
        stop();
    });
}

} // namespace proxy_core

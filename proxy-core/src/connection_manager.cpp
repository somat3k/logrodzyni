#include "connection_manager.hpp"
#include "session.hpp"
#include "config.hpp"
#include "logger.hpp"
#include <boost/asio.hpp>

using boost::asio::ip::tcp;
namespace net = boost::asio;

namespace proxy_core {

ConnectionManager::ConnectionManager(net::io_context& ioc,
                                     const ProxyConfig& cfg,
                                     PolicyEngine& policy,
                                     RateLimiter& rate_limiter)
    : ioc_(ioc),
      cfg_(cfg),
      policy_(policy),
      rate_limiter_(rate_limiter),
      socks_acceptor_(ioc),
      http_acceptor_(ioc) {}

void ConnectionManager::start() {
    // Set up SOCKS5 acceptor.
    auto socks_ep = tcp::endpoint(net::ip::make_address(cfg_.listen_host),
                                  cfg_.listen_port);
    socks_acceptor_.open(socks_ep.protocol());
    socks_acceptor_.set_option(tcp::acceptor::reuse_address(true));
    socks_acceptor_.bind(socks_ep);
    socks_acceptor_.listen(net::socket_base::max_listen_connections);
    LOG_INFO("SOCKS5 listening on ", cfg_.listen_host, ":", cfg_.listen_port);
    do_accept_tcp(socks_acceptor_);

    // Optional HTTP CONNECT acceptor.
    if (cfg_.http_port != 0) {
        auto http_ep = tcp::endpoint(net::ip::make_address(cfg_.listen_host),
                                     cfg_.http_port);
        http_acceptor_.open(http_ep.protocol());
        http_acceptor_.set_option(tcp::acceptor::reuse_address(true));
        http_acceptor_.bind(http_ep);
        http_acceptor_.listen(net::socket_base::max_listen_connections);
        LOG_INFO("HTTP CONNECT listening on ", cfg_.listen_host, ":", cfg_.http_port);
        do_accept_tcp(http_acceptor_);
    }
}

void ConnectionManager::stop() {
    stopped_ = true;
    boost::system::error_code ec;
    socks_acceptor_.close(ec);
    http_acceptor_.close(ec);

    std::lock_guard<std::mutex> lk(sessions_mu_);
    for (auto& [id, weak_sess] : sessions_) {
        if (auto sess = weak_sess.lock())
            sess->stop();
    }
    sessions_.clear();
    LOG_INFO("ConnectionManager stopped, all sessions terminated.");
}

size_t ConnectionManager::session_count() const {
    std::lock_guard<std::mutex> lk(sessions_mu_);
    // Evict expired weak_ptrs and return live count.
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (it->second.expired())
            it = sessions_.erase(it);
        else
            ++it;
    }
    return sessions_.size();
}

void ConnectionManager::do_accept_tcp(tcp::acceptor& acceptor) {
    if (stopped_) return;
    acceptor.async_accept(
        [this, &acceptor](boost::system::error_code ec, tcp::socket sock) {
            if (ec) {
                if (!stopped_) {
                    LOG_WARN("Accept error: ", ec.message(), " — retrying");
                    // Re-issue accept so transient errors don't stop the loop.
                    do_accept_tcp(acceptor);
                }
                return;
            }
            // Enforce max connection limit.
            if (session_count() >= cfg_.max_connections) {
                LOG_WARN("Max connections reached (", cfg_.max_connections, "), dropping connection");
                boost::system::error_code ec2;
                sock.close(ec2);
            } else {
                // Disable Nagle for lower latency.
                boost::system::error_code ec2;
                sock.set_option(tcp::no_delay(true), ec2);

                std::string src_ip = sock.remote_endpoint(ec2).address().to_string();
                auto sess = std::make_shared<Session>(
                    std::move(sock), ioc_, cfg_, policy_, rate_limiter_, src_ip);

                register_session(sess);
                sess->start();
            }
            do_accept_tcp(acceptor);
        });
}

void ConnectionManager::register_session(std::shared_ptr<Session> sess) {
    std::lock_guard<std::mutex> lk(sessions_mu_);
    sessions_[sess->id()] = sess;  // stored as weak_ptr; auto-expires when session ends
}

void ConnectionManager::unregister_session(uint64_t id) {
    std::lock_guard<std::mutex> lk(sessions_mu_);
    sessions_.erase(id);
}

} // namespace proxy_core

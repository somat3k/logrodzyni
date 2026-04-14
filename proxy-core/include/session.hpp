#pragma once
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <string>
#include <memory>
#include <functional>

namespace proxy_core {

struct ProxyConfig;
class  PolicyEngine;
class  RateLimiter;

// Represents a single client session handling either SOCKS5 or HTTP CONNECT.
class Session : public std::enable_shared_from_this<Session> {
public:
    using TcpSocket  = boost::asio::ip::tcp::socket;
    using SslSocket  = boost::asio::ssl::stream<TcpSocket>;
    using Resolver   = boost::asio::ip::tcp::resolver;
    using Callback   = std::function<void()>;

    Session(TcpSocket client_socket,
            boost::asio::io_context& ioc,
            const ProxyConfig& cfg,
            PolicyEngine& policy,
            RateLimiter& rate_limiter,
            std::string src_ip);

    // Start protocol detection and negotiation.
    void start();

    // Request graceful shutdown.
    void stop();

    uint64_t id()             const { return id_; }
    uint64_t bytes_sent()     const { return bytes_sent_; }
    uint64_t bytes_received() const { return bytes_received_; }

private:
    // ---- protocol detection ----
    void detect_protocol();

    // ---- SOCKS5 ----
    void socks5_handshake();
    void socks5_auth();
    void socks5_request();

    // ---- HTTP CONNECT ----
    void http_connect_read();
    void http_connect_parse(size_t n);

    // ---- common relay ----
    void resolve_and_connect(const std::string& host, uint16_t port);
    void relay_loop();
    void half_close();

    TcpSocket                 client_sock_;
    TcpSocket                 remote_sock_;
    boost::asio::io_context&  ioc_;
    const ProxyConfig&        cfg_;
    PolicyEngine&             policy_;
    RateLimiter&              rate_limiter_;
    Resolver                  resolver_;

    std::string src_ip_;
    std::string dst_host_;
    uint16_t    dst_port_ = 0;

    // 64KB I/O buffers.
    static constexpr size_t BUF_SIZE = 65536;
    std::array<uint8_t, BUF_SIZE> client_buf_{};
    std::array<uint8_t, BUF_SIZE> remote_buf_{};

    uint64_t bytes_sent_     = 0;
    uint64_t bytes_received_ = 0;

    static std::atomic<uint64_t> next_id_;
    uint64_t id_;

    bool stopped_ = false;
};

} // namespace proxy_core

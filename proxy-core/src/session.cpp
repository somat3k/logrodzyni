#include "session.hpp"
#include "config.hpp"
#include "policy_engine.hpp"
#include "rate_limiter.hpp"
#include "logger.hpp"
#include <boost/asio.hpp>
#include <cstring>
#include <string>

using boost::asio::ip::tcp;
namespace net = boost::asio;

namespace proxy_core {

std::atomic<uint64_t> Session::next_id_{1};

Session::Session(TcpSocket client_socket,
                 net::io_context& ioc,
                 const ProxyConfig& cfg,
                 PolicyEngine& policy,
                 RateLimiter& rate_limiter,
                 std::string src_ip)
    : client_sock_(std::move(client_socket)),
      remote_sock_(ioc),
      ioc_(ioc),
      cfg_(cfg),
      policy_(policy),
      rate_limiter_(rate_limiter),
      resolver_(ioc),
      src_ip_(std::move(src_ip)),
      id_(next_id_.fetch_add(1, std::memory_order_relaxed)) {}

void Session::start() {
    // Rate-limit check.
    if (!rate_limiter_.allow(src_ip_)) {
        LOG_WARN("Rate limit exceeded for ", src_ip_, " - dropping session ", id_);
        stop();
        return;
    }
    LOG_DEBUG("Session ", id_, " started from ", src_ip_);
    detect_protocol();
}

void Session::stop() {
    if (stopped_) return;
    stopped_ = true;
    boost::system::error_code ec;
    client_sock_.shutdown(tcp::socket::shutdown_both, ec);
    client_sock_.close(ec);
    remote_sock_.shutdown(tcp::socket::shutdown_both, ec);
    remote_sock_.close(ec);
    LOG_DEBUG("Session ", id_, " stopped. tx=", bytes_sent_, " rx=", bytes_received_);
}

// ─── Protocol detection ───────────────────────────────────────────────────────

void Session::detect_protocol() {
    auto self = shared_from_this();
    // Read one byte to distinguish SOCKS5 (0x05) from HTTP.
    net::async_read(client_sock_,
                    net::buffer(client_buf_.data(), 1),
                    [self](boost::system::error_code ec, size_t) {
        if (ec) { self->stop(); return; }
        uint8_t first = self->client_buf_[0];
        if (first == 0x05) {
            self->socks5_handshake();
        } else {
            // Treat as HTTP CONNECT; push the byte back into the buffer.
            self->http_connect_read();
        }
    });
}

// ─── SOCKS5 ──────────────────────────────────────────────────────────────────
// RFC 1928

void Session::socks5_handshake() {
    auto self = shared_from_this();
    // Read the greeting: VER(1) NMETHODS(1) METHODS(1..255)
    net::async_read(client_sock_,
                    net::buffer(client_buf_.data() + 1, 1),   // already have [0]=0x05
                    [self](boost::system::error_code ec, size_t) {
        if (ec) { self->stop(); return; }
        uint8_t nmethods = self->client_buf_[1];
        net::async_read(self->client_sock_,
                        net::buffer(self->client_buf_.data() + 2, nmethods),
                        [self, nmethods](boost::system::error_code ec2, size_t) {
            if (ec2) { self->stop(); return; }
            // Accept "no authentication" (0x00).
            uint8_t reply[2] = {0x05, 0x00};
            net::async_write(self->client_sock_,
                             net::buffer(reply, 2),
                             [self](boost::system::error_code ec3, size_t) {
                if (ec3) { self->stop(); return; }
                self->socks5_request();
            });
        });
    });
}

void Session::socks5_request() {
    auto self = shared_from_this();
    // VER CMD RSV ATYP [DST.ADDR] DST.PORT
    net::async_read(client_sock_,
                    net::buffer(client_buf_.data(), 4),
                    [self](boost::system::error_code ec, size_t) {
        if (ec) { self->stop(); return; }
        // cmd must be 0x01 (CONNECT).
        if (self->client_buf_[1] != 0x01) {
            uint8_t err[10] = {0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0}; // cmd not supported
            net::async_write(self->client_sock_, net::buffer(err, 10),
                             [self](auto...) { self->stop(); });
            return;
        }
        uint8_t atyp = self->client_buf_[3];
        if (atyp == 0x01) {
            // IPv4 (4 bytes + 2 port).
            net::async_read(self->client_sock_,
                            net::buffer(self->client_buf_.data() + 4, 6),
                            [self](boost::system::error_code ec2, size_t) {
                if (ec2) { self->stop(); return; }
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, self->client_buf_.data() + 4, ip, sizeof(ip));
                self->dst_host_ = ip;
                self->dst_port_ = (uint16_t(self->client_buf_[8]) << 8) |
                                   self->client_buf_[9];
                self->resolve_and_connect(self->dst_host_, self->dst_port_);
            });
        } else if (atyp == 0x03) {
            // Domain name: 1 len byte + name + 2 port.
            net::async_read(self->client_sock_,
                            net::buffer(self->client_buf_.data() + 4, 1),
                            [self](boost::system::error_code ec2, size_t) {
                if (ec2) { self->stop(); return; }
                uint8_t len = self->client_buf_[4];
                net::async_read(self->client_sock_,
                                net::buffer(self->client_buf_.data() + 5, len + 2),
                                [self, len](boost::system::error_code ec3, size_t) {
                    if (ec3) { self->stop(); return; }
                    self->dst_host_ = std::string(
                        reinterpret_cast<char*>(self->client_buf_.data() + 5), len);
                    self->dst_port_ = (uint16_t(self->client_buf_[5 + len]) << 8) |
                                       self->client_buf_[6 + len];
                    self->resolve_and_connect(self->dst_host_, self->dst_port_);
                });
            });
        } else {
            // IPv6 or unsupported.
            uint8_t err[10] = {0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0};
            net::async_write(self->client_sock_, net::buffer(err, 10),
                             [self](auto...) { self->stop(); });
        }
    });
}

// ─── HTTP CONNECT ─────────────────────────────────────────────────────────────

void Session::http_connect_read() {
    // Read up to BUF_SIZE bytes to capture the full request line + headers.
    auto self = shared_from_this();
    // Note: first byte already in client_buf_[0] from detect_protocol.
    client_sock_.async_read_some(
        net::buffer(client_buf_.data() + 1, BUF_SIZE - 1),
        [self](boost::system::error_code ec, size_t n) {
            if (ec) { self->stop(); return; }
            self->http_connect_parse(n + 1);
        });
}

void Session::http_connect_parse(size_t n) {
    std::string req(reinterpret_cast<char*>(client_buf_.data()), n);
    // Parse "CONNECT host:port HTTP/1.x\r\n..."
    auto pos = req.find("CONNECT ");
    if (pos == std::string::npos) { stop(); return; }

    auto host_start = pos + 8;
    auto space      = req.find(' ', host_start);
    if (space == std::string::npos) { stop(); return; }

    std::string host_port = req.substr(host_start, space - host_start);
    auto colon = host_port.rfind(':');
    if (colon == std::string::npos) { stop(); return; }

    dst_host_ = host_port.substr(0, colon);
    try { dst_port_ = static_cast<uint16_t>(std::stoi(host_port.substr(colon + 1))); }
    catch (...) { stop(); return; }

    resolve_and_connect(dst_host_, dst_port_);
}

// ─── Common relay logic ───────────────────────────────────────────────────────

void Session::resolve_and_connect(const std::string& host, uint16_t port) {
    // Policy check.
    FlowDescriptor flow;
    flow.src_ip   = src_ip_;
    flow.dst_host = host;
    flow.dst_port = port;
    flow.protocol = "tcp";

    if (policy_.evaluate(flow) == PolicyVerdict::Deny) {
        LOG_WARN("Session ", id_, " denied by policy: ", host, ":", port);
        stop();
        return;
    }

    auto self = shared_from_this();
    LOG_INFO("Session ", id_, " connecting to ", host, ":", port);

    resolver_.async_resolve(host, std::to_string(port),
        [self](boost::system::error_code ec, tcp::resolver::results_type results) {
            if (ec) {
                LOG_WARN("Session ", self->id_, " resolve failed: ", ec.message());
                self->stop();
                return;
            }
            net::async_connect(self->remote_sock_, results,
                [self](boost::system::error_code ec2, const tcp::endpoint&) {
                    if (ec2) {
                        LOG_WARN("Session ", self->id_, " connect failed: ", ec2.message());
                        self->stop();
                        return;
                    }
                    LOG_DEBUG("Session ", self->id_, " connected to remote");

                    // For SOCKS5: send success reply.
                    if (self->client_buf_[0] == 0x05) {
                        uint8_t reply[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
                        net::async_write(self->client_sock_, net::buffer(reply, 10),
                            [self](boost::system::error_code ec3, size_t) {
                                if (ec3) { self->stop(); return; }
                                self->relay_loop();
                            });
                    } else {
                        // HTTP CONNECT: send 200.
                        const char ok[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
                        net::async_write(self->client_sock_,
                            net::buffer(ok, strlen(ok)),
                            [self](boost::system::error_code ec3, size_t) {
                                if (ec3) { self->stop(); return; }
                                self->relay_loop();
                            });
                    }
                });
        });
}

void Session::relay_loop() {
    auto self = shared_from_this();

    // Client -> Remote.
    client_sock_.async_read_some(
        net::buffer(client_buf_),
        [self](boost::system::error_code ec, size_t n) {
            if (ec || n == 0) { self->half_close(); return; }
            self->bytes_received_ += n;
            net::async_write(self->remote_sock_,
                net::buffer(self->client_buf_.data(), n),
                [self](boost::system::error_code ec2, size_t) {
                    if (ec2) { self->half_close(); return; }
                    self->relay_loop();
                });
        });

    // Remote -> Client.
    remote_sock_.async_read_some(
        net::buffer(remote_buf_),
        [self](boost::system::error_code ec, size_t n) {
            if (ec || n == 0) { self->half_close(); return; }
            self->bytes_sent_ += n;
            net::async_write(self->client_sock_,
                net::buffer(self->remote_buf_.data(), n),
                [self](boost::system::error_code ec2, size_t) {
                    if (ec2) { self->half_close(); return; }
                    // Remote -> Client path will restart via the outer relay_loop call.
                });
        });
}

void Session::half_close() {
    stop();
}

} // namespace proxy_core

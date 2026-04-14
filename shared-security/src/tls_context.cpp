#include "tls_context.hpp"
#include <boost/asio/ssl.hpp>
#include <stdexcept>

namespace ssl = boost::asio::ssl;

namespace shared_security {

namespace {
const char* DEFAULT_CIPHERS =
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_128_GCM_SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384";

void apply_hardening_impl(ssl::context& ctx,
                          const std::string& min_version,
                          const std::string& cipher_list) {
    // Disable obsolete protocols.
    ctx.set_options(ssl::context::no_sslv2 |
                    ssl::context::no_sslv3 |
                    ssl::context::no_tlsv1 |
                    ssl::context::no_tlsv1_1 |
                    ssl::context::single_dh_use);

    // TLS 1.3-only unless caller relaxed to TLS 1.2.
    if (min_version != "TLSv1.2") {
        ctx.set_options(ssl::context::no_tlsv1_2);
    }

    // Set cipher suite — throw on invalid cipher string so misconfiguration is detected early.
    const std::string& ciphers = cipher_list.empty() ? DEFAULT_CIPHERS : cipher_list;
    if (SSL_CTX_set_cipher_list(ctx.native_handle(), ciphers.c_str()) != 1)
        throw std::runtime_error("SSL_CTX_set_cipher_list failed: invalid cipher string");
    if (SSL_CTX_set_ciphersuites(ctx.native_handle(),
                                  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") != 1)
        throw std::runtime_error("SSL_CTX_set_ciphersuites failed: invalid TLS 1.3 cipher string");
}
} // namespace

ssl::context TlsContextFactory::create(const TlsConfig& cfg) {
    ssl::context ctx(cfg.role == TlsRole::Server
                         ? ssl::context::tls_server
                         : ssl::context::tls_client);

    apply_hardening_impl(ctx, cfg.min_tls_version, cfg.cipher_list);

    if (!cfg.cert_file.empty())
        ctx.use_certificate_chain_file(cfg.cert_file);

    if (!cfg.key_file.empty()) {
        if (!cfg.key_passphrase.empty())
            ctx.set_password_callback([pass = cfg.key_passphrase]
                                       (size_t, ssl::context::password_purpose) {
                return pass;
            });
        ctx.use_private_key_file(cfg.key_file, ssl::context::pem);
    }

    if (!cfg.ca_file.empty())
        ctx.load_verify_file(cfg.ca_file);

    if (cfg.mutual_tls) {
        ctx.set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
    } else if (cfg.role == TlsRole::Client) {
        ctx.set_verify_mode(ssl::verify_peer);
    }

    return ctx;
}

ssl::context TlsContextFactory::client_context(const std::string& ca_file,
                                                 bool mutual_tls,
                                                 const std::string& cert_file,
                                                 const std::string& key_file) {
    TlsConfig cfg;
    cfg.role       = TlsRole::Client;
    cfg.ca_file    = ca_file;
    cfg.mutual_tls = mutual_tls;
    cfg.cert_file  = cert_file;
    cfg.key_file   = key_file;
    return create(cfg);
}

ssl::context TlsContextFactory::server_context(const std::string& cert_file,
                                                 const std::string& key_file,
                                                 const std::string& ca_file,
                                                 bool mutual_tls) {
    TlsConfig cfg;
    cfg.role       = TlsRole::Server;
    cfg.cert_file  = cert_file;
    cfg.key_file   = key_file;
    cfg.ca_file    = ca_file;
    cfg.mutual_tls = mutual_tls;
    return create(cfg);
}

void TlsContextFactory::apply_hardening(ssl::context& ctx,
                                          const std::string& min_version,
                                          const std::string& cipher_list) {
    apply_hardening_impl(ctx, min_version, cipher_list);
}

} // namespace shared_security

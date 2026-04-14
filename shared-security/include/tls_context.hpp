#pragma once
#include <string>
#include <memory>
#include <boost/asio/ssl.hpp>

namespace shared_security {

// Role of the TLS endpoint.
enum class TlsRole { Server, Client };

// Configuration used to create a TLS context.
struct TlsConfig {
    TlsRole role = TlsRole::Client;

    // Paths to PEM files.
    std::string cert_file;
    std::string key_file;
    std::string ca_file;            // CA bundle for peer verification
    std::string key_passphrase;

    // Mutual TLS: require and verify the peer certificate.
    bool mutual_tls = true;

    // Accepted cipher string (OpenSSL format).
    // Defaults to a strong modern set if empty.
    std::string cipher_list;

    // Minimum TLS version (1.2 or 1.3). Defaults to TLS 1.3.
    std::string min_tls_version = "TLSv1.3";
};

// Factory that produces Boost.Asio SSL contexts configured according to
// the security policy defined in TlsConfig.
class TlsContextFactory {
public:
    // Build and return a configured ssl::context.
    static boost::asio::ssl::context create(const TlsConfig& cfg);

    // Quick helper: create a client context that trusts the given CA.
    static boost::asio::ssl::context client_context(const std::string& ca_file,
                                                     bool mutual_tls = false,
                                                     const std::string& cert_file = "",
                                                     const std::string& key_file = "");

    // Quick helper: create a server context.
    static boost::asio::ssl::context server_context(const std::string& cert_file,
                                                     const std::string& key_file,
                                                     const std::string& ca_file = "",
                                                     bool mutual_tls = false);

private:
    static void apply_hardening(boost::asio::ssl::context& ctx,
                                 const std::string& min_version,
                                 const std::string& cipher_list);
};

} // namespace shared_security

#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <openssl/x509.h>

namespace shared_security {

struct CertInfo {
    std::string subject;
    std::string issuer;
    std::string serial;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    std::vector<std::string> san_dns;   // Subject Alternative Names
    std::vector<std::string> san_ips;
};

// Manages X.509 certificates and private keys for nodes.
class CertManager {
public:
    // Load a CA certificate + key from PEM files for signing.
    static std::shared_ptr<CertManager> from_ca_pem(const std::string& ca_cert_path,
                                                     const std::string& ca_key_path,
                                                     const std::string& key_passphrase = "");

    // Load a leaf certificate + key pair from PEM files.
    static std::shared_ptr<CertManager> from_leaf_pem(const std::string& cert_path,
                                                       const std::string& key_path,
                                                       const std::string& key_passphrase = "");

    // Generate a new RSA-4096 private key.
    static std::vector<uint8_t> generate_rsa_key(int bits = 4096);

    // Generate a new EC key (prime256v1 curve).
    static std::vector<uint8_t> generate_ec_key();

    // Issue a leaf certificate signed by this CA.
    // Returns PEM-encoded certificate.
    std::string issue_certificate(const std::vector<uint8_t>& key_pem,
                                  const std::string& common_name,
                                  const std::vector<std::string>& san_dns = {},
                                  const std::vector<std::string>& san_ips = {},
                                  int validity_days = 365) const;

    // Verify that cert_pem chains up to this CA.
    bool verify_certificate(const std::string& cert_pem) const;

    // Parse information from a PEM certificate.
    static CertInfo parse_cert(const std::string& cert_pem);

    // Check whether a certificate will expire within `warning_days`.
    static bool is_expiring_soon(const std::string& cert_pem, int warning_days = 30);

    // Return PEM-encoded CA certificate (public only).
    std::string ca_cert_pem() const;

    ~CertManager();

private:
    CertManager();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class CertError : public std::runtime_error {
public:
    explicit CertError(const std::string& msg) : std::runtime_error(msg) {}
};

} // namespace shared_security

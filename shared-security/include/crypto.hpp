#pragma once
#include <string>
#include <vector>
#include <stdexcept>

namespace shared_security {

// AES-256-GCM authenticated encryption / decryption.
// The key must be exactly 32 bytes; the nonce/IV 12 bytes.
class Crypto {
public:
    static constexpr size_t KEY_LEN  = 32; // AES-256
    static constexpr size_t NONCE_LEN = 12; // GCM standard
    static constexpr size_t TAG_LEN   = 16;

    // Returns ciphertext || tag  (nonce is prepended automatically).
    // Output layout: [12-byte nonce][ciphertext][16-byte tag]
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& aad = {});

    // Expects the layout produced by encrypt().
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& ciphertext_with_nonce,
                                        const std::vector<uint8_t>& aad = {});

    // Generate cryptographically random bytes.
    static std::vector<uint8_t> random_bytes(size_t n);

    // Derive a 256-bit key from a passphrase using PBKDF2-SHA256.
    static std::vector<uint8_t> derive_key(const std::string& passphrase,
                                           const std::vector<uint8_t>& salt,
                                           int iterations = 200000);

    // Constant-time comparison to prevent timing attacks.
    static bool secure_compare(const std::vector<uint8_t>& a,
                               const std::vector<uint8_t>& b);

    // Base64 encode / decode helpers.
    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& encoded);
};

class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& msg) : std::runtime_error(msg) {}
};

} // namespace shared_security

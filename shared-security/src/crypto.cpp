#include "crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <cstring>
#include <stdexcept>

namespace shared_security {

namespace {
void openssl_check(int rc, const char* ctx) {
    if (rc != 1)
        throw CryptoError(std::string(ctx) + " failed");
}
} // namespace

std::vector<uint8_t> Crypto::random_bytes(size_t n) {
    std::vector<uint8_t> buf(n);
    if (RAND_bytes(buf.data(), static_cast<int>(n)) != 1)
        throw CryptoError("RAND_bytes failed");
    return buf;
}

std::vector<uint8_t> Crypto::encrypt(const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& plaintext,
                                      const std::vector<uint8_t>& aad) {
    if (key.size() != KEY_LEN)
        throw CryptoError("Key must be 32 bytes for AES-256-GCM");

    auto nonce = random_bytes(NONCE_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw CryptoError("EVP_CIPHER_CTX_new failed");

    try {
        openssl_check(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
                      "EVP_EncryptInit_ex(cipher)");
        openssl_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr),
                      "EVP_CTRL_GCM_SET_IVLEN");
        openssl_check(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()),
                      "EVP_EncryptInit_ex(key+iv)");

        if (!aad.empty()) {
            int len = 0;
            openssl_check(EVP_EncryptUpdate(ctx, nullptr, &len,
                                             aad.data(), static_cast<int>(aad.size())),
                          "EVP_EncryptUpdate(aad)");
        }

        std::vector<uint8_t> ciphertext(plaintext.size());
        int len = 0;
        openssl_check(EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                                         plaintext.data(), static_cast<int>(plaintext.size())),
                      "EVP_EncryptUpdate");
        int ciphertext_len = len;

        openssl_check(EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len),
                      "EVP_EncryptFinal_ex");
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        std::vector<uint8_t> tag(TAG_LEN);
        openssl_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()),
                      "EVP_CTRL_GCM_GET_TAG");

        EVP_CIPHER_CTX_free(ctx);

        // Layout: [nonce(12)] [ciphertext] [tag(16)]
        std::vector<uint8_t> result;
        result.reserve(NONCE_LEN + ciphertext_len + TAG_LEN);
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        result.insert(result.end(), tag.begin(), tag.end());
        return result;

    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

std::vector<uint8_t> Crypto::decrypt(const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& blob,
                                      const std::vector<uint8_t>& aad) {
    if (key.size() != KEY_LEN)
        throw CryptoError("Key must be 32 bytes for AES-256-GCM");
    if (blob.size() < NONCE_LEN + TAG_LEN)
        throw CryptoError("Ciphertext blob too short");

    const uint8_t* nonce     = blob.data();
    const uint8_t* ciphertext = blob.data() + NONCE_LEN;
    size_t ciphertext_len     = blob.size() - NONCE_LEN - TAG_LEN;
    const uint8_t* tag        = blob.data() + NONCE_LEN + ciphertext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw CryptoError("EVP_CIPHER_CTX_new failed");

    try {
        openssl_check(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
                      "EVP_DecryptInit_ex(cipher)");
        openssl_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr),
                      "EVP_CTRL_GCM_SET_IVLEN");
        openssl_check(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce),
                      "EVP_DecryptInit_ex(key+iv)");

        if (!aad.empty()) {
            int len = 0;
            openssl_check(EVP_DecryptUpdate(ctx, nullptr, &len,
                                             aad.data(), static_cast<int>(aad.size())),
                          "EVP_DecryptUpdate(aad)");
        }

        std::vector<uint8_t> plaintext(ciphertext_len);
        int len = 0;
        openssl_check(EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                                         ciphertext, static_cast<int>(ciphertext_len)),
                      "EVP_DecryptUpdate");
        int plaintext_len = len;

        // Set expected tag before finalising.
        openssl_check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                                           const_cast<uint8_t*>(tag)),
                      "EVP_CTRL_GCM_SET_TAG");

        int rc = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        EVP_CIPHER_CTX_free(ctx);

        if (rc != 1)
            throw CryptoError("GCM authentication tag mismatch - data tampered");

        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return plaintext;

    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

std::vector<uint8_t> Crypto::derive_key(const std::string& passphrase,
                                          const std::vector<uint8_t>& salt,
                                          int iterations) {
    std::vector<uint8_t> key(KEY_LEN);
    int rc = PKCS5_PBKDF2_HMAC(passphrase.c_str(),
                                  static_cast<int>(passphrase.size()),
                                  salt.data(),
                                  static_cast<int>(salt.size()),
                                  iterations,
                                  EVP_sha256(),
                                  static_cast<int>(key.size()),
                                  key.data());
    if (rc != 1)
        throw CryptoError("PKCS5_PBKDF2_HMAC failed");
    return key;
}

bool Crypto::secure_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string Crypto::base64_encode(const std::vector<uint8_t>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    return result;
}

std::vector<uint8_t> Crypto::base64_decode(const std::string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    std::vector<uint8_t> buf(encoded.size());
    int decoded_len = BIO_read(b64, buf.data(), static_cast<int>(buf.size()));
    BIO_free_all(b64);
    if (decoded_len < 0)
        throw CryptoError("base64_decode failed");
    buf.resize(decoded_len);
    return buf;
}

} // namespace shared_security

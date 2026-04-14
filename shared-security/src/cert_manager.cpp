#include "cert_manager.hpp"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <ctime>

namespace shared_security {

namespace {
std::string openssl_error_str() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return buf;
}

X509* pem_to_x509(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}

EVP_PKEY* pem_to_pkey(const std::string& pem, const std::string& pass) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr,
                                             pass.empty() ? nullptr : (void*)pass.c_str());
    BIO_free(bio);
    return key;
}

std::string pem_from_x509(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::string result(bptr->data, bptr->length);
    BIO_free(bio);
    return result;
}

std::chrono::system_clock::time_point asn1_time_to_tp(const ASN1_TIME* t) {
    struct tm tm_result = {};
    ASN1_TIME_to_tm(t, &tm_result);
    return std::chrono::system_clock::from_time_t(timegm(&tm_result));
}
} // namespace

struct CertManager::Impl {
    X509*    ca_cert = nullptr;
    EVP_PKEY* ca_key  = nullptr;
    X509*    leaf_cert = nullptr;
    EVP_PKEY* leaf_key  = nullptr;

    ~Impl() {
        if (ca_cert)   X509_free(ca_cert);
        if (ca_key)    EVP_PKEY_free(ca_key);
        if (leaf_cert) X509_free(leaf_cert);
        if (leaf_key)  EVP_PKEY_free(leaf_key);
    }
};

CertManager::CertManager() : impl_(std::make_unique<Impl>()) {}
CertManager::~CertManager() = default;

std::shared_ptr<CertManager> CertManager::from_ca_pem(const std::string& ca_cert_path,
                                                        const std::string& ca_key_path,
                                                        const std::string& pass) {
    // Read files into strings.
    auto read_file = [](const std::string& path) {
        FILE* f = fopen(path.c_str(), "r");
        if (!f) throw CertError("Cannot open file: " + path);
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        rewind(f);
        std::string s(sz, '\0');
        fread(s.data(), 1, sz, f);
        fclose(f);
        return s;
    };

    auto mgr = std::shared_ptr<CertManager>(new CertManager());
    std::string cert_pem = read_file(ca_cert_path);
    std::string key_pem  = read_file(ca_key_path);

    mgr->impl_->ca_cert = pem_to_x509(cert_pem);
    if (!mgr->impl_->ca_cert)
        throw CertError("Failed to parse CA cert: " + openssl_error_str());

    mgr->impl_->ca_key = pem_to_pkey(key_pem, pass);
    if (!mgr->impl_->ca_key)
        throw CertError("Failed to parse CA key: " + openssl_error_str());

    return mgr;
}

std::shared_ptr<CertManager> CertManager::from_leaf_pem(const std::string& cert_path,
                                                          const std::string& key_path,
                                                          const std::string& pass) {
    auto read_file = [](const std::string& path) {
        FILE* f = fopen(path.c_str(), "r");
        if (!f) throw CertError("Cannot open file: " + path);
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        rewind(f);
        std::string s(sz, '\0');
        fread(s.data(), 1, sz, f);
        fclose(f);
        return s;
    };

    auto mgr = std::shared_ptr<CertManager>(new CertManager());
    std::string cert_pem = read_file(cert_path);
    std::string key_pem  = read_file(key_path);

    mgr->impl_->leaf_cert = pem_to_x509(cert_pem);
    mgr->impl_->leaf_key  = pem_to_pkey(key_pem, pass);
    return mgr;
}

std::vector<uint8_t> CertManager::generate_rsa_key(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) throw CertError("EVP_PKEY_CTX_new_id failed");

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    EVP_PKEY_free(pkey);

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::vector<uint8_t> result(bptr->data, bptr->data + bptr->length);
    BIO_free(bio);
    return result;
}

std::vector<uint8_t> CertManager::generate_ec_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    EVP_PKEY_free(pkey);

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::vector<uint8_t> result(bptr->data, bptr->data + bptr->length);
    BIO_free(bio);
    return result;
}

std::string CertManager::issue_certificate(const std::vector<uint8_t>& key_pem,
                                             const std::string& common_name,
                                             const std::vector<std::string>& san_dns,
                                             const std::vector<std::string>& san_ips,
                                             int validity_days) const {
    if (!impl_->ca_cert || !impl_->ca_key)
        throw CertError("CertManager has no CA loaded");

    std::string key_str(key_pem.begin(), key_pem.end());
    EVP_PKEY* pkey = pem_to_pkey(key_str, "");
    if (!pkey) throw CertError("Failed to parse subject key");

    X509* cert = X509_new();
    X509_set_version(cert, 2); // v3

    // Random serial.
    BIGNUM* serial_bn = BN_new();
    BN_rand(serial_bn, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    ASN1_INTEGER* serial = BN_to_ASN1_INTEGER(serial_bn, nullptr);
    X509_set_serialNumber(cert, serial);
    ASN1_INTEGER_free(serial);
    BN_free(serial_bn);

    // Validity.
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60 * 24 * validity_days);

    // Subject.
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                (unsigned char*)common_name.c_str(), -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, X509_get_subject_name(impl_->ca_cert));

    X509_set_pubkey(cert, pkey);

    // SANs.
    if (!san_dns.empty() || !san_ips.empty()) {
        std::string san_str;
        for (const auto& dns : san_dns) {
            if (!san_str.empty()) san_str += ",";
            san_str += "DNS:" + dns;
        }
        for (const auto& ip : san_ips) {
            if (!san_str.empty()) san_str += ",";
            san_str += "IP:" + ip;
        }
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr,
                                                    NID_subject_alt_name,
                                                    san_str.c_str());
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    // Sign with CA key.
    X509_sign(cert, impl_->ca_key, EVP_sha256());

    std::string result = pem_from_x509(cert);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return result;
}

bool CertManager::verify_certificate(const std::string& cert_pem) const {
    if (!impl_->ca_cert) return false;
    X509* cert = pem_to_x509(cert_pem);
    if (!cert) return false;

    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, impl_->ca_cert);
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, nullptr);
    int ok = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    return ok == 1;
}

CertInfo CertManager::parse_cert(const std::string& cert_pem) {
    X509* cert = pem_to_x509(cert_pem);
    if (!cert) throw CertError("Failed to parse certificate");

    CertInfo info;
    char buf[256];
    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
    info.subject = buf;
    X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
    info.issuer = buf;

    BIGNUM* serial_bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), nullptr);
    char* serial_str = BN_bn2hex(serial_bn);
    info.serial = serial_str;
    OPENSSL_free(serial_str);
    BN_free(serial_bn);

    info.not_before = asn1_time_to_tp(X509_get0_notBefore(cert));
    info.not_after  = asn1_time_to_tp(X509_get0_notAfter(cert));

    // SANs.
    GENERAL_NAMES* sans = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
    if (sans) {
        for (int i = 0; i < sk_GENERAL_NAME_num(sans); ++i) {
            GENERAL_NAME* gn = sk_GENERAL_NAME_value(sans, i);
            if (gn->type == GEN_DNS) {
                info.san_dns.emplace_back((char*)ASN1_STRING_get0_data(gn->d.dNSName));
            } else if (gn->type == GEN_IPADD) {
                // IPv4/IPv6 raw bytes.
                const uint8_t* data = ASN1_STRING_get0_data(gn->d.iPAddress);
                int len = ASN1_STRING_length(gn->d.iPAddress);
                if (len == 4) {
                    char ip_buf[16];
                    snprintf(ip_buf, sizeof(ip_buf), "%d.%d.%d.%d",
                             data[0], data[1], data[2], data[3]);
                    info.san_ips.emplace_back(ip_buf);
                }
            }
        }
        GENERAL_NAMES_free(sans);
    }

    X509_free(cert);
    return info;
}

bool CertManager::is_expiring_soon(const std::string& cert_pem, int warning_days) {
    auto info = parse_cert(cert_pem);
    auto threshold = std::chrono::system_clock::now() +
                     std::chrono::hours(24 * warning_days);
    return info.not_after < threshold;
}

std::string CertManager::ca_cert_pem() const {
    if (!impl_->ca_cert) throw CertError("No CA cert loaded");
    return pem_from_x509(impl_->ca_cert);
}

} // namespace shared_security

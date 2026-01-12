#pragma once

// Undefine OpenSSL ERROR macro if it exists to avoid conflicts
#ifdef ERROR
#undef ERROR
#endif

#include "common.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <memory>
#include <unordered_map>
#include <utility>

namespace SecureComm {

// Forward declarations
class CryptoManager;
class KeyManager;
class SessionManager;

// RAII wrapper for OpenSSL contexts
class EVPContext {
public:
    EVPContext();
    ~EVPContext();
    EVP_CIPHER_CTX* get() { return ctx_; }
    const EVP_CIPHER_CTX* get() const { return ctx_; }
private:
    EVP_CIPHER_CTX* ctx_;
};

class EVPMDContext {
public:
    EVPMDContext();
    ~EVPMDContext();
    EVP_MD_CTX* get() { return ctx_; }
    const EVP_MD_CTX* get() const { return ctx_; }
private:
    EVP_MD_CTX* ctx_;
};

// Main cryptographic manager class
class CryptoManager {
public:
    CryptoManager();
    ~CryptoManager();

    // Key generation
    KeyPair generate_rsa_keypair(size_t bits = 2048);
    KeyPair generate_dh_keypair();
    std::vector<uint8_t> generate_symmetric_key(size_t size = KEY_SIZE);
    
    // Encryption/Decryption
    // Encryption/Decryption
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encrypt_aes_gcm(
                                        const std::vector<uint8_t>& data, 
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv);
    std::vector<uint8_t> decrypt_aes_gcm(const std::vector<uint8_t>& encrypted_data,
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv,
                                        const std::vector<uint8_t>& tag);
    
    // Key exchange
    std::vector<uint8_t> perform_dh_key_exchange(const std::vector<uint8_t>& private_key,
                                                const std::vector<uint8_t>& peer_public_key);
    std::vector<uint8_t> derive_shared_secret(const std::vector<uint8_t>& dh_result,
                                             const std::vector<uint8_t>& salt);
    
    // Hashing and HMAC
    std::vector<uint8_t> sha256_hash(const std::vector<uint8_t>& data);
    std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& data,
                                    const std::vector<uint8_t>& key);
    
    // Digital signatures
    std::vector<uint8_t> sign_data(const std::vector<uint8_t>& data,
                                  const std::vector<uint8_t>& private_key);
    bool verify_signature(const std::vector<uint8_t>& data,
                         const std::vector<uint8_t>& signature,
                         const std::vector<uint8_t>& public_key);
    
    // Random number generation
    std::vector<uint8_t> generate_random_bytes(size_t size);
    uint32_t generate_random_uint32();
    
    // Key derivation
    std::vector<uint8_t> derive_key(const std::vector<uint8_t>& master_key,
                                   const std::vector<uint8_t>& salt,
                                   size_t key_size = KEY_SIZE);
    
    // Forward secrecy
    std::vector<uint8_t> rotate_session_key(const std::vector<uint8_t>& current_key,
                                           const std::vector<uint8_t>& session_id);

private:
    void initialize_openssl();
    void cleanup_openssl();
    // Private helper methods
    std::vector<uint8_t> rsa_private_key_to_bytes(EVP_PKEY* pkey);
    std::vector<uint8_t> rsa_public_key_to_bytes(EVP_PKEY* pkey);
    EVP_PKEY* bytes_to_rsa_private_key(const std::vector<uint8_t>& data);
    EVP_PKEY* bytes_to_rsa_public_key(const std::vector<uint8_t>& data);
};

// Key management class
class KeyManager {
public:
    KeyManager();
    ~KeyManager();

    // Key storage and retrieval
    void store_key(const std::string& key_id, const std::vector<uint8_t>& key);
    std::vector<uint8_t> get_key(const std::string& key_id);
    void remove_key(const std::string& key_id);
    bool key_exists(const std::string& key_id);
    
    // Key rotation
    void rotate_key(const std::string& key_id);
    std::vector<uint8_t> generate_new_key(const std::string& key_id);
    
    // Key expiration
    void set_key_expiration(const std::string& key_id, 
                           std::chrono::system_clock::time_point expires_at);
    bool is_key_expired(const std::string& key_id);
    
    // Key backup and recovery
    void backup_keys(const std::string& backup_path);
    void restore_keys(const std::string& backup_path);

private:
    std::unordered_map<std::string, std::vector<uint8_t>> keys_;
    std::unordered_map<std::string, std::chrono::system_clock::time_point> key_expirations_;
    std::mutex keys_mutex_;
};

// Session management class
class SessionManager {
public:
    SessionManager();
    ~SessionManager();

    // Session creation and management
    SessionInfo create_session(uint32_t client_id);
    SessionInfo get_session(uint32_t session_id);
    void update_session_activity(uint32_t session_id);
    void remove_session(uint32_t session_id);
    bool session_exists(uint32_t session_id);
    
    // Session authentication
    bool authenticate_session(uint32_t session_id, const std::vector<uint8_t>& auth_data);
    AuthResult verify_session_auth(uint32_t session_id, const std::vector<uint8_t>& signature);
    
    // Session key management
    void set_session_key(uint32_t session_id, const std::vector<uint8_t>& key);
    std::vector<uint8_t> get_session_key(uint32_t session_id);
    void rotate_session_key(uint32_t session_id);
    
    // Session cleanup
    void cleanup_expired_sessions(std::chrono::seconds max_age = std::chrono::hours(24));
    std::vector<uint32_t> get_expired_sessions(std::chrono::seconds max_age = std::chrono::hours(24));

private:
    std::unordered_map<uint32_t, SessionInfo> sessions_;
    std::mutex sessions_mutex_;
    CryptoManager crypto_manager_;
};

// Utility functions
std::string bytes_to_hex(const std::vector<uint8_t>& data);
std::vector<uint8_t> hex_to_bytes(const std::string& hex);
std::string base64_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64_decode(const std::string& encoded);
bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

// Error handling
class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& message) : std::runtime_error(message) {}
    explicit CryptoException(const char* message) : std::runtime_error(message) {}
};

void log_crypto_error(const std::string& operation);
std::string get_openssl_error_string();

} // namespace SecureComm 
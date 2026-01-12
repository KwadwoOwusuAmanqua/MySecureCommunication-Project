#include "crypto_utils.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <random>
#include <algorithm>
#include <cstring>

namespace SecureComm {

// EVPContext implementation
EVPContext::EVPContext() : ctx_(EVP_CIPHER_CTX_new()) {
    if (!ctx_) {
        throw CryptoException("Failed to create EVP_CIPHER_CTX");
    }
}

EVPContext::~EVPContext() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
    }
}

EVPMDContext::EVPMDContext() : ctx_(EVP_MD_CTX_new()) {
    if (!ctx_) {
        throw CryptoException("Failed to create EVP_MD_CTX");
    }
}

EVPMDContext::~EVPMDContext() {
    if (ctx_) {
        EVP_MD_CTX_free(ctx_);
    }
}

// CryptoManager implementation
CryptoManager::CryptoManager() {
    initialize_openssl();
}

CryptoManager::~CryptoManager() {
    cleanup_openssl();
}

void CryptoManager::initialize_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    if (!RAND_poll()) {
        throw CryptoException("Failed to initialize random number generator");
    }
}

void CryptoManager::cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

KeyPair CryptoManager::generate_rsa_keypair(size_t bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        throw CryptoException("Failed to create RSA key generation context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw CryptoException("Failed to initialize RSA key generation");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw CryptoException("Failed to set RSA key size");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw CryptoException("Failed to generate RSA key pair");
    }

    EVP_PKEY_CTX_free(ctx);

    KeyPair keypair;
    keypair.private_key = rsa_private_key_to_bytes(pkey);
    keypair.public_key = rsa_public_key_to_bytes(pkey);
    keypair.created_at = get_current_timestamp();
    keypair.expires_at = keypair.created_at + std::chrono::hours(24);

    EVP_PKEY_free(pkey);
    return keypair;
}

KeyPair CryptoManager::generate_dh_keypair() {
    // Use predefined DH parameters for faster and more reliable operation
    DH* dh = DH_get_2048_256();
    if (!dh) {
        // Fallback to generating parameters if predefined ones aren't available
        dh = DH_new();
        if (!dh) {
            throw CryptoException("Failed to create DH structure");
        }
        
        // Use smaller parameters for faster generation
        if (DH_generate_parameters_ex(dh, 1024, DH_GENERATOR_2, nullptr) != 1) {
            DH_free(dh);
            throw CryptoException("Failed to generate DH parameters");
        }
    }

    // Generate the DH key pair
    if (DH_generate_key(dh) != 1) {
        DH_free(dh);
        throw CryptoException("Failed to generate DH key pair");
    }

    // Extract raw DH key data
    const BIGNUM* pub_key = DH_get0_pub_key(dh);
    const BIGNUM* priv_key = DH_get0_priv_key(dh);
    
    if (!pub_key || !priv_key) {
        DH_free(dh);
        throw CryptoException("Failed to get DH key components");
    }

    // Convert BIGNUM to raw bytes
    int pub_len = BN_num_bytes(pub_key);
    int priv_len = BN_num_bytes(priv_key);
    
    std::vector<uint8_t> pub_bytes(pub_len);
    std::vector<uint8_t> priv_bytes(priv_len);
    
    if (BN_bn2bin(pub_key, pub_bytes.data()) != pub_len) {
        DH_free(dh);
        throw CryptoException("Failed to convert DH public key to bytes");
    }
    
    if (BN_bn2bin(priv_key, priv_bytes.data()) != priv_len) {
        DH_free(dh);
        throw CryptoException("Failed to convert DH private key to bytes");
    }

    // Create KeyPair with raw key data (no length prefix)
    KeyPair keypair;
    
    // Use full DH key size
    keypair.public_key.resize(SecureComm::DH_KEY_SIZE);
    size_t copy_size = std::min<size_t>(pub_len, SecureComm::DH_KEY_SIZE);
    std::copy(pub_bytes.begin(), pub_bytes.begin() + copy_size, keypair.public_key.begin());
    // Zero-pad if needed
    if (copy_size < SecureComm::DH_KEY_SIZE) {
        std::fill(keypair.public_key.begin() + copy_size, keypair.public_key.end(), 0);
    }
    
    // Store the full private key for key exchange
    keypair.private_key = priv_bytes;
    
    keypair.created_at = get_current_timestamp();
    keypair.expires_at = keypair.created_at + std::chrono::hours(1);

    DH_free(dh);
    return keypair;
}

std::vector<uint8_t> CryptoManager::generate_symmetric_key(size_t size) {
    return generate_random_bytes(size);
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> CryptoManager::encrypt_aes_gcm(
                                                   const std::vector<uint8_t>& data,
                                                   const std::vector<uint8_t>& key,
                                                   const std::vector<uint8_t>& iv) {
    EVPContext ctx;
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();

    if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key.data(), iv.data()) != 1) {
        throw CryptoException("Failed to initialize AES-GCM encryption");
    }

    std::vector<uint8_t> encrypted(data.size() + EVP_MAX_BLOCK_LENGTH);
    int len;
    
    if (EVP_EncryptUpdate(ctx.get(), encrypted.data(), &len, data.data(), static_cast<int>(data.size())) != 1) {
        throw CryptoException("Failed to encrypt data");
    }

    int final_len;
    if (EVP_EncryptFinal_ex(ctx.get(), encrypted.data() + len, &final_len) != 1) {
        throw CryptoException("Failed to finalize encryption");
    }

    encrypted.resize(len + final_len);

    std::vector<uint8_t> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        throw CryptoException("Failed to get GCM tag");
    }

    return {encrypted, tag};
}

std::vector<uint8_t> CryptoManager::decrypt_aes_gcm(const std::vector<uint8_t>& encrypted_data,
                                                   const std::vector<uint8_t>& key,
                                                   const std::vector<uint8_t>& iv,
                                                   const std::vector<uint8_t>& tag) {
    EVPContext ctx;
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();

    if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key.data(), iv.data()) != 1) {
        throw CryptoException("Failed to initialize AES-GCM decryption");
    }

    std::vector<uint8_t> decrypted(encrypted_data.size());
    int len;
    
    if (EVP_DecryptUpdate(ctx.get(), decrypted.data(), &len, encrypted_data.data(), static_cast<int>(encrypted_data.size())) != 1) {
        throw CryptoException("Failed to decrypt data");
    }

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data())) != 1) {
        throw CryptoException("Failed to set GCM tag");
    }

    int final_len;
    if (EVP_DecryptFinal_ex(ctx.get(), decrypted.data() + len, &final_len) != 1) {
        throw CryptoException("Failed to finalize decryption");
    }

    decrypted.resize(len + final_len);
    return decrypted;
}

std::vector<uint8_t> CryptoManager::perform_dh_key_exchange(const std::vector<uint8_t>& private_key,
                                                           const std::vector<uint8_t>& peer_public_key) {
    // Create DH structure with predefined parameters
    DH* dh = DH_get_2048_256();
    if (!dh) {
        // Fallback to generating parameters
        dh = DH_new();
        if (!dh) {
            throw CryptoException("Failed to create DH structure");
        }
        if (DH_generate_parameters_ex(dh, 1024, DH_GENERATOR_2, nullptr) != 1) {
            DH_free(dh);
            throw CryptoException("Failed to generate DH parameters");
        }
    }
    
    // Convert raw bytes back to BIGNUM
    BIGNUM* priv_bn = BN_bin2bn(private_key.data(), private_key.size(), nullptr);
    BIGNUM* pub_bn = BN_bin2bn(peer_public_key.data(), peer_public_key.size(), nullptr);
    
    if (!priv_bn || !pub_bn) {
        if (priv_bn) BN_free(priv_bn);
        if (pub_bn) BN_free(pub_bn);
        DH_free(dh);
        throw CryptoException("Failed to convert key bytes to BIGNUM");
    }
    
    // Set the private key in DH structure
    if (DH_set0_key(dh, nullptr, priv_bn) != 1) {
        BN_free(priv_bn);
        BN_free(pub_bn);
        DH_free(dh);
        throw CryptoException("Failed to set DH private key");
    }
    
    // Compute shared secret
    std::vector<uint8_t> secret(DH_size(dh));
    int secret_len = DH_compute_key(secret.data(), pub_bn, dh);
    
    if (secret_len <= 0) {
        BN_free(pub_bn);
        DH_free(dh);
        throw CryptoException("Failed to compute DH shared secret");
    }
    
    secret.resize(secret_len);
    
    // Cleanup
    BN_free(pub_bn);
    DH_free(dh);
    
    return secret;
}

std::vector<uint8_t> CryptoManager::derive_shared_secret(const std::vector<uint8_t>& dh_result,
                                                        const std::vector<uint8_t>& salt) {
    return derive_key(dh_result, salt, KEY_SIZE);
}

std::vector<uint8_t> CryptoManager::sha256_hash(const std::vector<uint8_t>& data) {
    EVPMDContext ctx;
    unsigned int hash_len = EVP_MD_size(EVP_sha256());
    std::vector<uint8_t> hash(hash_len);

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw CryptoException("Failed to initialize SHA256");
    }

    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) {
        throw CryptoException("Failed to update SHA256");
    }

    if (EVP_DigestFinal_ex(ctx.get(), hash.data(), &hash_len) != 1) {
        throw CryptoException("Failed to finalize SHA256");
    }

    return hash;
}

std::vector<uint8_t> CryptoManager::hmac_sha256(const std::vector<uint8_t>& data,
                                               const std::vector<uint8_t>& key) {
    unsigned int hmac_len = EVP_MD_size(EVP_sha256());
    std::vector<uint8_t> hmac(hmac_len);

    if (HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), 
             hmac.data(), &hmac_len) == nullptr) {
        throw CryptoException("Failed to compute HMAC-SHA256");
    }

    return hmac;
}

std::vector<uint8_t> CryptoManager::sign_data(const std::vector<uint8_t>& data,
                                             const std::vector<uint8_t>& private_key) {
    EVP_PKEY* pkey = bytes_to_rsa_private_key(private_key);
    EVPMDContext ctx;

    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey) != 1) {
        EVP_PKEY_free(pkey);
        throw CryptoException("Failed to initialize signature");
    }

    size_t sig_len;
    if (EVP_DigestSign(ctx.get(), nullptr, &sig_len, data.data(), data.size()) != 1) {
        EVP_PKEY_free(pkey);
        throw CryptoException("Failed to get signature length");
    }

    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSign(ctx.get(), signature.data(), &sig_len, data.data(), data.size()) != 1) {
        EVP_PKEY_free(pkey);
        throw CryptoException("Failed to create signature");
    }

    EVP_PKEY_free(pkey);
    return signature;
}

bool CryptoManager::verify_signature(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& signature,
                                   const std::vector<uint8_t>& public_key) {
    EVP_PKEY* pkey = bytes_to_rsa_public_key(public_key);
    EVPMDContext ctx;

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey) != 1) {
        EVP_PKEY_free(pkey);
        return false;
    }

    int result = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), 
                                 data.data(), data.size());
    EVP_PKEY_free(pkey);
    
    return result == 1;
}

std::vector<uint8_t> CryptoManager::generate_random_bytes(size_t size) {
    std::vector<uint8_t> random_bytes(size);
    if (RAND_bytes(random_bytes.data(), size) != 1) {
        throw CryptoException("Failed to generate random bytes");
    }
    return random_bytes;
}

uint32_t CryptoManager::generate_random_uint32() {
    uint32_t value;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
        throw CryptoException("Failed to generate random uint32");
    }
    return value;
}

std::vector<uint8_t> CryptoManager::derive_key(const std::vector<uint8_t>& master_key,
                                              const std::vector<uint8_t>& salt,
                                              size_t key_size) {
    std::vector<uint8_t> derived_key(key_size);
    
    if (PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(master_key.data()), master_key.size(),
                          salt.data(), salt.size(), 10000, EVP_sha256(), key_size, 
                          derived_key.data()) != 1) {
        throw CryptoException("Failed to derive key");
    }
    
    return derived_key;
}

std::vector<uint8_t> CryptoManager::rotate_session_key(const std::vector<uint8_t>& current_key,
                                                      const std::vector<uint8_t>& session_id) {
    std::vector<uint8_t> salt = sha256_hash(session_id);
    return derive_key(current_key, salt, KEY_SIZE);
}

// Private helper methods
std::vector<uint8_t> CryptoManager::rsa_private_key_to_bytes(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw CryptoException("Failed to create BIO for private key");
    }

    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        throw CryptoException("Failed to write private key to BIO");
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::vector<uint8_t> key_data(bptr->data, bptr->data + bptr->length);
    BIO_free(bio);

    return key_data;
}

std::vector<uint8_t> CryptoManager::rsa_public_key_to_bytes(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw CryptoException("Failed to create BIO for public key");
    }

    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        BIO_free(bio);
        throw CryptoException("Failed to write public key to BIO");
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::vector<uint8_t> key_data(bptr->data, bptr->data + bptr->length);
    BIO_free(bio);

    return key_data;
}

EVP_PKEY* CryptoManager::bytes_to_rsa_private_key(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new_mem_buf(data.data(), data.size());
    if (!bio) {
        throw CryptoException("Failed to create BIO from private key data");
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        throw CryptoException("Failed to read private key from BIO");
    }

    return pkey;
}

EVP_PKEY* CryptoManager::bytes_to_rsa_public_key(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new_mem_buf(data.data(), data.size());
    if (!bio) {
        throw CryptoException("Failed to create BIO from public key data");
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        throw CryptoException("Failed to read public key from BIO");
    }

    return pkey;
}

// KeyManager implementation
KeyManager::KeyManager() = default;
KeyManager::~KeyManager() = default;

void KeyManager::store_key(const std::string& key_id, const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    keys_[key_id] = key;
}

std::vector<uint8_t> KeyManager::get_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        throw CryptoException("Key not found: " + key_id);
    }
    return it->second;
}

void KeyManager::remove_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    keys_.erase(key_id);
    key_expirations_.erase(key_id);
}

bool KeyManager::key_exists(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    return keys_.find(key_id) != keys_.end();
}

void KeyManager::rotate_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    auto it = keys_.find(key_id);
    if (it != keys_.end()) {
        // Generate new key based on current key
        CryptoManager crypto;
        std::vector<uint8_t> salt = crypto.generate_random_bytes(32);
        it->second = crypto.derive_key(it->second, salt, KEY_SIZE);
    }
}

std::vector<uint8_t> KeyManager::generate_new_key(const std::string& key_id) {
    CryptoManager crypto;
    std::vector<uint8_t> new_key = crypto.generate_symmetric_key(KEY_SIZE);
    store_key(key_id, new_key);
    return new_key;
}

void KeyManager::set_key_expiration(const std::string& key_id, 
                                   std::chrono::system_clock::time_point expires_at) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    key_expirations_[key_id] = expires_at;
}

bool KeyManager::is_key_expired(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(keys_mutex_);
    auto it = key_expirations_.find(key_id);
    if (it == key_expirations_.end()) {
        return false; // No expiration set
    }
    return std::chrono::system_clock::now() > it->second;
}

void KeyManager::backup_keys(const std::string& backup_path) {
    // Implementation for key backup
    // This would typically encrypt and store keys to a secure location
}

void KeyManager::restore_keys(const std::string& backup_path) {
    // Implementation for key restoration
    // This would typically decrypt and load keys from a secure location
}

// SessionManager implementation
SessionManager::SessionManager() = default;
SessionManager::~SessionManager() = default;

SessionInfo SessionManager::create_session(uint32_t client_id) {
    SessionInfo session;
    session.session_id = generate_session_id();
    session.client_id = client_id;
    session.created_at = get_current_timestamp();
    session.last_activity = session.created_at;
    session.message_counter = 0;
    session.authenticated = false;
    session.key_rotated = false;

    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_[session.session_id] = session;
    return session;
}

SessionInfo SessionManager::get_session(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        throw CryptoException("Session not found: " + std::to_string(session_id));
    }
    return it->second;
}

void SessionManager::update_session_activity(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second.last_activity = get_current_timestamp();
        it->second.message_counter++;
    }
}

void SessionManager::remove_session(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_.erase(session_id);
}

bool SessionManager::session_exists(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return sessions_.find(session_id) != sessions_.end();
}

bool SessionManager::authenticate_session(uint32_t session_id, const std::vector<uint8_t>& auth_data) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        // Simple authentication - in real implementation, this would verify credentials
        it->second.authenticated = true;
        return true;
    }
    return false;
}

AuthResult SessionManager::verify_session_auth(uint32_t session_id, const std::vector<uint8_t>& signature) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return AuthResult::UNKNOWN_CLIENT;
    }

    if (!it->second.authenticated) {
        return AuthResult::INVALID_SIGNATURE;
    }

    // Check if session is expired (24 hours)
    auto now = get_current_timestamp();
    if (now - it->second.created_at > std::chrono::hours(24)) {
        return AuthResult::EXPIRED_SESSION;
    }

    return AuthResult::SUCCESS;
}

void SessionManager::set_session_key(uint32_t session_id, const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second.current_key = key;
    }
}

std::vector<uint8_t> SessionManager::get_session_key(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        throw CryptoException("Session not found: " + std::to_string(session_id));
    }
    return it->second.current_key;
}

void SessionManager::rotate_session_key(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second.current_key = crypto_manager_.rotate_session_key(it->second.current_key, 
                                                                   std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&session_id), 
                                                                                       reinterpret_cast<const uint8_t*>(&session_id) + sizeof(session_id)));
        it->second.key_rotated = true;
    }
}

void SessionManager::cleanup_expired_sessions(std::chrono::seconds max_age) {
    auto now = get_current_timestamp();
    std::vector<uint32_t> expired_sessions;

    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (const auto& pair : sessions_) {
            if (now - pair.second.created_at > max_age) {
                expired_sessions.push_back(pair.first);
            }
        }
    }

    for (uint32_t session_id : expired_sessions) {
        remove_session(session_id);
    }
}

std::vector<uint32_t> SessionManager::get_expired_sessions(std::chrono::seconds max_age) {
    auto now = get_current_timestamp();
    std::vector<uint32_t> expired_sessions;

    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (const auto& pair : sessions_) {
        if (now - pair.second.created_at > max_age) {
            expired_sessions.push_back(pair.first);
        }
    }

    return expired_sessions;
}

// Utility functions

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string base64_encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return result;
}

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.c_str(), encoded.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<uint8_t> decoded(encoded.length());
    int decoded_len = BIO_read(bio, decoded.data(), decoded.size());
    BIO_free_all(bio);

    if (decoded_len < 0) {
        throw CryptoException("Failed to decode base64");
    }

    decoded.resize(decoded_len);
    return decoded;
}

bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    
    int result = 0;
    for (size_t i = 0; i < a.size(); i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

void log_crypto_error(const std::string& operation) {
    std::cerr << "Crypto error in " << operation << ": " << get_openssl_error_string() << std::endl;
}

std::string get_openssl_error_string() {
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string error_string(buffer_ptr->data, buffer_ptr->length);
    BIO_free(bio);
    return error_string;
}

} // namespace SecureComm 
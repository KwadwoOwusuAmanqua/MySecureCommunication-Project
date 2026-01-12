#pragma once

// Undefine OpenSSL ERROR macro if it exists to avoid conflicts
#ifdef ERROR
#undef ERROR
#endif

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <chrono>
#include <random>
#include <mutex>
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/aes.h>

// MSVC compatibility - use pragma pack
#ifdef _MSC_VER
    #pragma pack(push, 1)
#endif

namespace SecureComm {

// Protocol constants
constexpr uint16_t DEFAULT_PORT = 8080;
constexpr size_t MAX_MESSAGE_SIZE = 4096;
constexpr size_t GCM_TAG_SIZE = 16;
constexpr size_t KEY_SIZE = 32;       // AES Key size
constexpr size_t DH_KEY_SIZE = 256;   // DH Key size (2048 bits)
constexpr size_t IV_SIZE = 12;
constexpr size_t HASH_SIZE = 32;
constexpr size_t SIGNATURE_SIZE = 256;
constexpr size_t HMAC_SIZE = 32;
constexpr size_t MAX_USERNAME_SIZE = 32;

// Message types
enum class MessageType : uint8_t {
    HANDSHAKE_INIT = 0x01,
    HANDSHAKE_RESPONSE = 0x02,
    HANDSHAKE_COMPLETE = 0x03,
    ENCRYPTED_MESSAGE = 0x04,
    KEY_ROTATION = 0x05,
    AUTHENTICATION = 0x06,
    ERROR_MESSAGE = 0xFF
};

// Protocol versions
enum class ProtocolVersion : uint8_t {
    V1_0 = 0x01
};

// Forward secrecy types
enum class ForwardSecrecyType : uint8_t {
    NONE = 0x00,
    DH = 0x01,
    ECDH = 0x02,
    PERFECT_FORWARD_SECRECY = 0x03
};

// Message header structure
struct MessageHeader {
    ProtocolVersion version;
    MessageType type;
    uint32_t sequence_number;
    uint32_t timestamp;
    uint16_t payload_size;
    uint16_t flags;
};

// Handshake message structure
struct HandshakeMessage {
    uint32_t client_id;
    uint32_t session_id;
    ForwardSecrecyType fs_type;
    uint8_t public_key[DH_KEY_SIZE];
    uint8_t nonce[IV_SIZE];
    char username[MAX_USERNAME_SIZE];
};

// Encrypted message structure
struct EncryptedMessage {
    uint32_t session_id;
    uint32_t message_id;
    uint32_t data_len; // Actual length of encrypted data
    uint8_t iv[IV_SIZE];
    uint8_t tag[GCM_TAG_SIZE];
    uint8_t encrypted_data[MAX_MESSAGE_SIZE];
    uint8_t signature[SIGNATURE_SIZE];
    char target_username[MAX_USERNAME_SIZE]; // Username to send to, or empty for broadcast
};

// Session information
struct SessionInfo {
    uint32_t session_id;
    uint32_t client_id;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_activity;
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> current_key;
    uint32_t message_counter;
    bool authenticated;
    bool key_rotated;
};

// Key pair structure
struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
};

// Authentication result
enum class AuthResult {
    SUCCESS,
    INVALID_SIGNATURE,
    EXPIRED_SESSION,
    INVALID_KEY,
    UNKNOWN_CLIENT
};

// Error codes
enum class ErrorCode : uint16_t {
    NONE = 0x0000,
    INVALID_MESSAGE = 0x0001,
    AUTHENTICATION_FAILED = 0x0002,
    SESSION_EXPIRED = 0x0003,
    KEY_ROTATION_FAILED = 0x0004,
    ENCRYPTION_FAILED = 0x0005,
    DECRYPTION_FAILED = 0x0006,
    INVALID_PROTOCOL_VERSION = 0x0007,
    INTERNAL_ERROR = 0x00FF
};

// Utility functions
inline std::string error_code_to_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::NONE: return "None";
        case ErrorCode::INVALID_MESSAGE: return "Invalid Message";
        case ErrorCode::AUTHENTICATION_FAILED: return "Authentication Failed";
        case ErrorCode::SESSION_EXPIRED: return "Session Expired";
        case ErrorCode::KEY_ROTATION_FAILED: return "Key Rotation Failed";
        case ErrorCode::ENCRYPTION_FAILED: return "Encryption Failed";
        case ErrorCode::DECRYPTION_FAILED: return "Decryption Failed";
        case ErrorCode::INVALID_PROTOCOL_VERSION: return "Invalid Protocol Version";
        case ErrorCode::INTERNAL_ERROR: return "Internal Error";
        default: return "Unknown Error";
    }
}

inline std::string message_type_to_string(MessageType type) {
    switch (type) {
        case MessageType::HANDSHAKE_INIT: return "Handshake Init";
        case MessageType::HANDSHAKE_RESPONSE: return "Handshake Response";
        case MessageType::HANDSHAKE_COMPLETE: return "Handshake Complete";
        case MessageType::ENCRYPTED_MESSAGE: return "Encrypted Message";
        case MessageType::KEY_ROTATION: return "Key Rotation";
        case MessageType::AUTHENTICATION: return "Authentication";
        case MessageType::ERROR_MESSAGE: return "Error";
        default: return "Unknown";
    }
}

inline std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

inline uint32_t generate_session_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<unsigned int> dis(1, 0xFFFFFFFF);
    return static_cast<uint32_t>(dis(gen));
}

inline uint32_t generate_client_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<unsigned int> dis(1, 0xFFFFFFFF);
    return static_cast<uint32_t>(dis(gen));
}

inline std::vector<uint8_t> generate_nonce(size_t size) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<unsigned int> dis(0, 255);
    
    std::vector<uint8_t> nonce(size);
    for (size_t i = 0; i < size; ++i) {
        nonce[i] = static_cast<uint8_t>(dis(gen));
    }
    return nonce;
}

inline std::chrono::system_clock::time_point get_current_timestamp() {
    return std::chrono::system_clock::now();
}

inline uint32_t get_current_timestamp_seconds() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    return static_cast<uint32_t>(seconds.count());
}

// Serialization helpers
inline std::vector<uint8_t> serialize_header(const MessageHeader& header) {
    std::vector<uint8_t> data(sizeof(MessageHeader));
    std::memcpy(data.data(), &header, sizeof(MessageHeader));
    return data;
}

inline MessageHeader deserialize_header(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(MessageHeader)) {
        throw std::runtime_error("Invalid header data size");
    }
    MessageHeader header;
    std::memcpy(&header, data.data(), sizeof(MessageHeader));
    return header;
}

inline std::vector<uint8_t> serialize_handshake(const HandshakeMessage& handshake) {
    std::vector<uint8_t> data(sizeof(HandshakeMessage));
    std::memcpy(data.data(), &handshake, sizeof(HandshakeMessage));
    return data;
}

inline HandshakeMessage deserialize_handshake(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(HandshakeMessage)) {
        throw std::runtime_error("Invalid handshake data size");
    }
    HandshakeMessage handshake;
    std::memcpy(&handshake, data.data(), sizeof(HandshakeMessage));
    return handshake;
}

inline std::vector<uint8_t> serialize_encrypted_message(const EncryptedMessage& msg) {
    std::vector<uint8_t> data(sizeof(EncryptedMessage));
    std::memcpy(data.data(), &msg, sizeof(EncryptedMessage));
    return data;
}

inline EncryptedMessage deserialize_encrypted_message(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(EncryptedMessage)) {
        throw std::runtime_error("Invalid encrypted message data size");
    }
    EncryptedMessage msg;
    std::memcpy(&msg, data.data(), sizeof(EncryptedMessage));
    return msg;
}

} // namespace SecureComm

#ifdef _MSC_VER
    #pragma pack(pop)
#endif 
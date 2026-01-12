#include "common.h"
#include "../crypto/crypto_utils.h"
#include <iostream>
#include <string>
#include <memory>
#include <algorithm>
#include <chrono>
#include <vector>
#include <thread>
#include <atomic>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

#include <cstring>

// using namespace SecureComm; // Removed to avoid namespace conflicts

class SecureClient {
private:
    int client_socket_;
    std::unique_ptr<SecureComm::CryptoManager> crypto_manager_;
    std::unique_ptr<SecureComm::SessionManager> session_manager_;
    std::unique_ptr<SecureComm::KeyManager> key_manager_;
    SecureComm::KeyPair client_keypair_;
    SecureComm::SessionInfo current_session_;
    std::vector<uint8_t> session_key_;
    uint32_t message_counter_;
    std::string username_;
    std::atomic<bool> running_;
    std::thread receive_thread_;

public:
    SecureClient(const std::string& username) : client_socket_(-1), message_counter_(0), running_(false), username_(username) {


#ifdef _WIN32
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif

        crypto_manager_ = std::make_unique<SecureComm::CryptoManager>();
        session_manager_ = std::make_unique<SecureComm::SessionManager>();
        key_manager_ = std::make_unique<SecureComm::KeyManager>();
        
        // Generate client's RSA key pair
        client_keypair_ = crypto_manager_->generate_rsa_keypair(2048);
        std::cout << "Client RSA key pair generated successfully" << std::endl;
    }

    ~SecureClient() {
        disconnect();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    bool connect(const std::string& server_ip, uint16_t port = SecureComm::DEFAULT_PORT) {
        client_socket_ = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
        if (client_socket_ < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
            std::cerr << "Invalid server address" << std::endl;
#ifdef _WIN32
            closesocket(client_socket_);
#else
            close(client_socket_);
#endif
            return false;
        }

                    if (::connect(client_socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Failed to connect to server" << std::endl;
#ifdef _WIN32
            closesocket(client_socket_);
#else
            close(client_socket_);
#endif
            return false;
        }

        std::cout << "Connected to server " << server_ip << ":" << port << std::endl;

        // Perform secure handshake
        if (!perform_handshake()) {
            std::cerr << "Handshake failed" << std::endl;
#ifdef _WIN32
            closesocket(client_socket_);
#else
            close(client_socket_);
#endif
            return false;
        }

        std::cout << "Secure connection established" << std::endl;
        return true;
    }

    void disconnect() {
        running_ = false;
        if (client_socket_ >= 0) {
#ifdef _WIN32
            shutdown(client_socket_, SD_BOTH);
            closesocket(client_socket_);
#else
            shutdown(client_socket_, SHUT_RDWR);
            close(client_socket_);
#endif
            client_socket_ = -1;
        }
        
        if (receive_thread_.joinable()) {
            receive_thread_.join();
        }
    }

    bool send_encrypted_message(const std::string& message, const std::string& target_user = "") {
        try {
            std::vector<uint8_t> message_data(message.begin(), message.end());
            std::vector<uint8_t> iv = crypto_manager_->generate_random_bytes(SecureComm::IV_SIZE);
            
            auto [encrypted_data, tag] = crypto_manager_->encrypt_aes_gcm(message_data, session_key_, iv);
            
            SecureComm::EncryptedMessage encrypted_msg;
            encrypted_msg.session_id = current_session_.session_id;
            encrypted_msg.message_id = message_counter_;
            encrypted_msg.data_len = static_cast<uint32_t>(encrypted_data.size());

            // Set Target Username
            std::memset(encrypted_msg.target_username, 0, SecureComm::MAX_USERNAME_SIZE);
            if (!target_user.empty()) {
                std::strncpy(encrypted_msg.target_username, target_user.c_str(), SecureComm::MAX_USERNAME_SIZE - 1);
            }
            
            // Copy IV
            size_t iv_copy_size = std::min<size_t>(iv.size(), SecureComm::IV_SIZE);
            std::copy(iv.begin(), iv.begin() + iv_copy_size, encrypted_msg.iv);

            // Copy Tag
            size_t tag_copy_size = std::min<size_t>(tag.size(), SecureComm::GCM_TAG_SIZE);
            std::copy(tag.begin(), tag.begin() + tag_copy_size, encrypted_msg.tag);
            
            // Copy encrypted data
            size_t data_copy_size = std::min<size_t>(encrypted_data.size(), SecureComm::MAX_MESSAGE_SIZE);
            std::copy(encrypted_data.begin(), encrypted_data.begin() + data_copy_size, encrypted_msg.encrypted_data);
            
            // Sign the encrypted data
            std::vector<uint8_t> signature = crypto_manager_->sign_data(encrypted_data, client_keypair_.private_key);
            size_t sig_copy_size = std::min<size_t>(signature.size(), SecureComm::SIGNATURE_SIZE);
            std::copy(signature.begin(), signature.begin() + sig_copy_size, encrypted_msg.signature);

            std::vector<uint8_t> msg_payload = SecureComm::serialize_encrypted_message(encrypted_msg);
            
            SecureComm::MessageHeader header;
            header.version = SecureComm::ProtocolVersion::V1_0;
            header.type = SecureComm::MessageType::ENCRYPTED_MESSAGE;
            header.sequence_number = message_counter_;
            header.timestamp = SecureComm::get_current_timestamp_seconds();
            header.payload_size = static_cast<uint16_t>(msg_payload.size());
            header.flags = 0;

            std::vector<uint8_t> request_data = SecureComm::serialize_header(header);
            request_data.insert(request_data.end(), msg_payload.begin(), msg_payload.end());

            if (!send_data(request_data)) {
                std::cerr << "Failed to send encrypted message" << std::endl;
                return false;
            }

            message_counter_++;
            std::cout << "Sent encrypted message: " << message << std::endl;

            // Response handling moved to receive_thread_
            return true;

        } catch (const std::exception& e) {
            std::cerr << "Failed to send encrypted message: " << e.what() << std::endl;
            return false;
        }
    }

    bool request_key_rotation() {
        try {
            SecureComm::MessageHeader header;
            header.version = SecureComm::ProtocolVersion::V1_0;
            header.type = SecureComm::MessageType::KEY_ROTATION;
            header.sequence_number = message_counter_;
            header.timestamp = SecureComm::get_current_timestamp_seconds();
            header.payload_size = 0;
            header.flags = 0;

            std::vector<uint8_t> request_data = SecureComm::serialize_header(header);
            
            if (!send_data(request_data)) {
                std::cerr << "Failed to send key rotation request" << std::endl;
                return false;
            }

            // Receive key rotation response
            std::vector<uint8_t> response_data = receive_data();
            if (response_data.empty()) {
                std::cerr << "No response to key rotation request" << std::endl;
                return false;
            }

            SecureComm::MessageHeader response_header = SecureComm::deserialize_header(response_data);
            if (response_header.type == SecureComm::MessageType::KEY_ROTATION) {
                // Update session key
                session_key_ = crypto_manager_->rotate_session_key(session_key_, 
                    std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&current_session_.session_id), 
                                        reinterpret_cast<const uint8_t*>(&current_session_.session_id) + sizeof(current_session_.session_id)));
                
                std::cout << "Key rotation completed successfully" << std::endl;
                return true;
            } else {
                std::cerr << "Unexpected response to key rotation request" << std::endl;
                return false;
            }

        } catch (const std::exception& e) {
            std::cerr << "Key rotation failed: " << e.what() << std::endl;
            return false;
        }
    }

    void interactive_mode() {
        std::cout << "\nInteractive mode - Type 'quit' to exit, 'rotate' to rotate keys" << std::endl;
        
        running_ = true;
        receive_thread_ = std::thread(&SecureClient::receive_loop, this);

        std::string input;
        
        while (running_) {
            // std::cout << "> "; // Prompt interferes with async output, removing for chat UI
            std::getline(std::cin, input);
            
            if (input == "quit" || input == "exit") {
                running_ = false;
                break;
            } else if (input == "rotate") {
                if (request_key_rotation()) {
                    std::cout << "Key rotation successful" << std::endl;
                } else {
                    std::cerr << "Key rotation failed" << std::endl;
                }
            } else if (!input.empty()) {
                // Check if it's a direct message: @username message
                std::string target_user = "";
                std::string msg_content = input;
                
                if (input.size() > 1 && input[0] == '@') {
                    size_t space_pos = input.find(' ');
                    if (space_pos != std::string::npos) {
                        target_user = input.substr(1, space_pos - 1);
                        msg_content = input.substr(space_pos + 1);
                    }
                }
                
                if (!send_encrypted_message(msg_content, target_user)) {
                    std::cerr << "Failed to send message" << std::endl;
                    break;
                }
            }
        }
        
        disconnect();
    }

    void receive_loop() {
        while (running_) {
            std::string message = receive_encrypted_message();
            if (!message.empty()) {
                std::cout << "[CHAT] " << message << std::endl; // Prefix for GUI parsing
            } else {
                if (!running_) break;
                // If empty and running, maybe just a keep-alive or silence; 
                // but if socket closed, receive_data returns empty and we should probably exit
                // For now, simple check: if socket invalid, break
                if (client_socket_ == -1) break;
            }
        }
    }

private:
    bool perform_handshake() {
        try {
            // Step 1: Generate DH key pair for forward secrecy
            SecureComm::KeyPair dh_keypair = crypto_manager_->generate_dh_keypair();
            
            // Step 2: Send handshake init
            uint32_t client_id = SecureComm::generate_client_id();
            current_session_.client_id = client_id;
            current_session_.session_id = SecureComm::generate_session_id();

            SecureComm::HandshakeMessage handshake;
            handshake.client_id = client_id;
            handshake.session_id = current_session_.session_id;
            handshake.fs_type = SecureComm::ForwardSecrecyType::PERFECT_FORWARD_SECRECY;
            
            // Set Username
            std::memset(handshake.username, 0, SecureComm::MAX_USERNAME_SIZE);
            std::strncpy(handshake.username, username_.c_str(), SecureComm::MAX_USERNAME_SIZE - 1);

            // Copy DH public key (not RSA public key)
            size_t key_copy_size = std::min<size_t>(dh_keypair.public_key.size(), SecureComm::DH_KEY_SIZE);
            std::copy(dh_keypair.public_key.begin(), 
                      dh_keypair.public_key.begin() + key_copy_size,
                      handshake.public_key);
            
            // Generate nonce
            std::vector<uint8_t> nonce = SecureComm::generate_nonce(SecureComm::IV_SIZE);
            std::copy(nonce.begin(), nonce.end(), handshake.nonce);

            SecureComm::MessageHeader header;
            header.version = SecureComm::ProtocolVersion::V1_0;
            header.type = SecureComm::MessageType::HANDSHAKE_INIT;
            header.sequence_number = 0;
            header.timestamp = SecureComm::get_current_timestamp_seconds();
            header.payload_size = sizeof(SecureComm::HandshakeMessage);
            header.flags = 0;

            std::vector<uint8_t> request_data = SecureComm::serialize_header(header);
            std::vector<uint8_t> handshake_payload = SecureComm::serialize_handshake(handshake);
            request_data.insert(request_data.end(), handshake_payload.begin(), handshake_payload.end());

            if (!send_data(request_data)) {
                std::cerr << "Failed to send handshake init" << std::endl;
                return false;
            }

            std::cout << "Sent handshake init" << std::endl;

            // Step 3: Receive handshake response
            std::vector<uint8_t> response_data = receive_data();
            if (response_data.empty()) {
                std::cerr << "No handshake response received" << std::endl;
                return false;
            }

            SecureComm::MessageHeader response_header = SecureComm::deserialize_header(response_data);
            if (response_header.type != SecureComm::MessageType::HANDSHAKE_RESPONSE) {
                std::cerr << "Expected HANDSHAKE_RESPONSE, got " << SecureComm::message_type_to_string(response_header.type) << std::endl;
                return false;
            }

            // Extract server handshake
            std::vector<uint8_t> payload(response_data.begin() + sizeof(SecureComm::MessageHeader), response_data.end());
            SecureComm::HandshakeMessage server_handshake = SecureComm::deserialize_handshake(payload);

            std::cout << "Received handshake response from server" << std::endl;

            // Step 4: Perform key exchange with DH keys
            std::vector<uint8_t> server_public_key(server_handshake.public_key, 
                                                  server_handshake.public_key + SecureComm::DH_KEY_SIZE);
            
            std::vector<uint8_t> shared_secret = crypto_manager_->perform_dh_key_exchange(
                dh_keypair.private_key, server_public_key);
            
            // Derive session key
            std::vector<uint8_t> server_nonce(server_handshake.nonce, server_handshake.nonce + SecureComm::IV_SIZE);
            session_key_ = crypto_manager_->derive_shared_secret(shared_secret, nonce);

            current_session_.shared_secret = shared_secret;
            current_session_.current_key = session_key_;
            current_session_.authenticated = true;

            std::cout << "Session key derived successfully" << std::endl;

            // Step 5: Send handshake complete
            SecureComm::MessageHeader complete_header;
            complete_header.version = SecureComm::ProtocolVersion::V1_0;
            complete_header.type = SecureComm::MessageType::HANDSHAKE_COMPLETE;
            complete_header.sequence_number = 1;
            complete_header.timestamp = SecureComm::get_current_timestamp_seconds();
            complete_header.payload_size = 0;
            complete_header.flags = 0;

            std::vector<uint8_t> complete_data = SecureComm::serialize_header(complete_header);
            
            if (!send_data(complete_data)) {
                std::cerr << "Failed to send handshake complete" << std::endl;
                return false;
            }

            std::cout << "Handshake completed successfully" << std::endl;
            return true;

        } catch (const std::exception& e) {
            std::cerr << "Handshake error: " << e.what() << std::endl;
            return false;
        }
    }

    std::string receive_encrypted_message() {
        try {
            std::vector<uint8_t> encrypted_data = receive_data();
            if (encrypted_data.empty()) {
                return "";
            }

            SecureComm::MessageHeader header = SecureComm::deserialize_header(encrypted_data);
            
            if (header.type == SecureComm::MessageType::ENCRYPTED_MESSAGE) {
                // Extract encrypted message
                std::vector<uint8_t> payload(encrypted_data.begin() + sizeof(SecureComm::MessageHeader), encrypted_data.end());
                SecureComm::EncryptedMessage encrypted_msg = SecureComm::deserialize_encrypted_message(payload);

                // Decrypt message
                std::vector<uint8_t> iv(encrypted_msg.iv, encrypted_msg.iv + SecureComm::IV_SIZE);
                
                std::vector<uint8_t> encrypted_payload(encrypted_msg.encrypted_data, 
                                                      encrypted_msg.encrypted_data + encrypted_msg.data_len);
                std::vector<uint8_t> tag(encrypted_msg.tag, encrypted_msg.tag + SecureComm::GCM_TAG_SIZE);
                std::vector<uint8_t> decrypted_data = crypto_manager_->decrypt_aes_gcm(
                    encrypted_payload, session_key_, iv, tag);

                std::string message(decrypted_data.begin(), decrypted_data.end());
                return message;

            } else if (header.type == SecureComm::MessageType::ERROR_MESSAGE) {
                std::vector<uint8_t> payload(encrypted_data.begin() + sizeof(SecureComm::MessageHeader), encrypted_data.end());
                if (payload.size() >= sizeof(SecureComm::ErrorCode)) {
                    SecureComm::ErrorCode error_code = *reinterpret_cast<const SecureComm::ErrorCode*>(payload.data());
                    std::cerr << "Server error: " << SecureComm::error_code_to_string(error_code) << std::endl;
                }
                return "";

            } else {
                std::cerr << "Unexpected message type: " << SecureComm::message_type_to_string(header.type) << std::endl;
                return "";
            }

        } catch (const std::exception& e) {
            std::cerr << "Error receiving encrypted message: " << e.what() << std::endl;
            return "";
        }
    }

    std::vector<uint8_t> receive_data() {
        // Read header
        std::vector<uint8_t> header_data(sizeof(SecureComm::MessageHeader));
        size_t total_received = 0;
        
        while (total_received < header_data.size()) {
            int received = recv(client_socket_, reinterpret_cast<char*>(header_data.data() + total_received), 
                            static_cast<int>(header_data.size() - total_received), 0);
            if (received <= 0) return {};
            total_received += received;
        }
        
        SecureComm::MessageHeader header;
        try {
            header = SecureComm::deserialize_header(header_data);
        } catch (...) {
            return {};
        }

        if (header.payload_size == 0) return header_data;

        // Read payload
        std::vector<uint8_t> payload(header.payload_size);
        total_received = 0;
        while (total_received < payload.size()) {
            int received = recv(client_socket_, reinterpret_cast<char*>(payload.data() + total_received), 
                            static_cast<int>(payload.size() - total_received), 0);
            if (received <= 0) return {};
            total_received += received;
        }
        
        header_data.insert(header_data.end(), payload.begin(), payload.end());
        return header_data;
    }

    bool send_data(const std::vector<uint8_t>& data) {
        int bytes_sent = send(client_socket_, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0);
        return bytes_sent == static_cast<int>(data.size());
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <server_ip> [port] <username>" << std::endl;
        std::cout << "Example: " << argv[0] << " 127.0.0.1 8080 User1" << std::endl;
        return 1;
    }

    std::string server_ip = argv[1];
    uint16_t port = (argc > 3) ? static_cast<uint16_t>(std::stoi(argv[2])) : SecureComm::DEFAULT_PORT;
    std::string username = (argc >= 3) ? argv[argc > 3 ? 3 : 2] : "User";

    try {
        SecureClient client(username);
        
        if (!client.connect(server_ip, port)) {
            std::cerr << "Failed to connect to server" << std::endl;
            return 1;
        }

        std::cout << "Secure Communication Client" << std::endl;
        std::cout << "Features:" << std::endl;
        std::cout << "- RSA-2048 key exchange" << std::endl;
        std::cout << "- AES-256-GCM encryption" << std::endl;
        std::cout << "- Perfect Forward Secrecy with DH key exchange" << std::endl;
        std::cout << "- Session authentication" << std::endl;
        std::cout << "- Manual key rotation" << std::endl;
        std::cout << "- Digital signatures" << std::endl;

        // Start interactive mode
        client.interactive_mode();

    } catch (const std::exception& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 
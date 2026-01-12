#include "common.h"
#include "../crypto/crypto_utils.h"
#include <iostream>
#include <thread>
#include <vector>
#include <memory>
#include <atomic>
#include <algorithm>
#include <chrono>

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
#include <signal.h>

// using namespace SecureComm; // Removed to avoid namespace conflicts

class SecureServer {
private:
    int server_socket_;
    std::atomic<bool> running_;
    std::unique_ptr<SecureComm::CryptoManager> crypto_manager_;
    std::unique_ptr<SecureComm::SessionManager> session_manager_;
    std::unique_ptr<SecureComm::KeyManager> key_manager_;
    std::vector<std::thread> client_threads_;
    SecureComm::KeyPair server_keypair_;
    std::unordered_map<int, uint32_t> active_sessions_; // socket -> session_id
    std::unordered_map<uint32_t, std::string> session_usernames_; // session_id -> username
    std::mutex sessions_mutex_;

public:
    SecureServer() : server_socket_(-1), running_(false) {
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
        
        // Generate server's RSA key pair
        server_keypair_ = crypto_manager_->generate_rsa_keypair(2048);
        std::cout << "Server RSA key pair generated successfully" << std::endl;
    }

    ~SecureServer() {
        stop();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    bool start(uint16_t port = SecureComm::DEFAULT_PORT) {
        server_socket_ = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
        if (server_socket_ < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }

        int opt = 1;
        if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) < 0) {
            std::cerr << "Failed to set socket options" << std::endl;
#ifdef _WIN32
            closesocket(server_socket_);
#else
            close(server_socket_);
#endif
            return false;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(server_socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Failed to bind socket" << std::endl;
#ifdef _WIN32
            closesocket(server_socket_);
#else
            close(server_socket_);
#endif
            return false;
        }

        if (listen(server_socket_, 10) < 0) {
            std::cerr << "Failed to listen on socket" << std::endl;
#ifdef _WIN32
            closesocket(server_socket_);
#else
            close(server_socket_);
#endif
            return false;
        }

        running_ = true;
        std::cout << "Secure server started on port " << port << std::endl;
        std::cout << "Server public key: " << SecureComm::bytes_to_hex(server_keypair_.public_key).substr(0, 64) << "..." << std::endl;

        // Start cleanup thread
        std::thread cleanup_thread([this]() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::minutes(5));
                session_manager_->cleanup_expired_sessions();
            }
        });
        cleanup_thread.detach();

        return true;
    }

    void run() {
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_socket = static_cast<int>(accept(server_socket_, (struct sockaddr*)&client_addr, &client_len));
            if (client_socket < 0) {
                if (running_) {
                    std::cerr << "Failed to accept client connection" << std::endl;
                }
                continue;
            }

            std::cout << "New client connected from " << inet_ntoa(client_addr.sin_addr) 
                      << ":" << ntohs(client_addr.sin_port) << std::endl;

            // Handle client in separate thread
            client_threads_.emplace_back(&SecureServer::handle_client, this, client_socket);
        }
    }

    void stop() {
        running_ = false;
        
        if (server_socket_ >= 0) {
#ifdef _WIN32
            closesocket(server_socket_);
#else
            close(server_socket_);
#endif
            server_socket_ = -1;
        }

        // Wait for all client threads to finish
        for (auto& thread : client_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        client_threads_.clear();
    }

private:
    void handle_client(int client_socket) {
        try {
            uint32_t client_id = SecureComm::generate_client_id();
            SecureComm::SessionInfo session = session_manager_->create_session(client_id);
            
            std::cout << "Created session " << session.session_id << " for client " << client_id << std::endl;

            // Perform secure handshake
            if (!perform_handshake(client_socket, session)) {
                std::cerr << "Handshake failed for client " << client_id << std::endl;
#ifdef _WIN32
                closesocket(client_socket);
#else
                close(client_socket);
#endif
                return;
            }

            std::cout << "Handshake completed successfully for client " << client_id << std::endl;

            // Register active session
            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                active_sessions_[client_socket] = session.session_id;
                
                // Get username from where we stored it (wait, we need to extract it in perform_handshake)
                // Actually, perform_handshake deserializes it. Let's make sure we store it.
            }
            
            // Notify others
            std::string username = session_usernames_[session.session_id];
            if (username.empty()) username = "Client " + std::to_string(client_id);
            
            broadcast_message(client_socket, username + " joined the chat");

            // Handle encrypted messages
            handle_encrypted_messages(client_socket, session);

    } catch (const std::exception& e) {
            std::cerr << "Error handling client: " << e.what() << std::endl;
        }

        // Unregister session
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            if (active_sessions_.count(client_socket)) {
                uint32_t session_id = active_sessions_[client_socket];
                session_usernames_.erase(session_id);
                active_sessions_.erase(client_socket);
            }
        }

#ifdef _WIN32
        closesocket(client_socket);
#else
        close(client_socket);
#endif
        std::cout << "Client disconnected" << std::endl;
    }

    void broadcast_message(int sender_socket, const std::string& message) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        
        for (const auto& pair : active_sessions_) {
            int target_socket = pair.first;
            uint32_t session_id = pair.second;
            
            // Don't echo back to sender if it's a regular message
            // (But we might want to for confirmation, here we skip sender for "broadcast" logic)
            if (target_socket == sender_socket) {
                continue;
            }

            try {
                // Get session info for the target
                SecureComm::SessionInfo session = session_manager_->get_session(session_id);
                send_encrypted_message(target_socket, session, message);
            } catch (const std::exception& e) {
                std::cerr << "Failed to broadcast to session " << session_id << ": " << e.what() << std::endl;
            }
        }
    }

    bool perform_handshake(int client_socket, SecureComm::SessionInfo& session) {
        try {
            // Step 1: Receive handshake init
            std::vector<uint8_t> handshake_data = receive_data(client_socket);
            SecureComm::MessageHeader header = SecureComm::deserialize_header(handshake_data);
            
            if (header.type != SecureComm::MessageType::HANDSHAKE_INIT) {
                std::cerr << "Expected HANDSHAKE_INIT, got " << SecureComm::message_type_to_string(header.type) << std::endl;
                return false;
            }

            // Extract handshake message
            std::vector<uint8_t> payload(handshake_data.begin() + sizeof(SecureComm::MessageHeader), handshake_data.end());
            SecureComm::HandshakeMessage client_handshake = SecureComm::deserialize_handshake(payload);

            std::string username(client_handshake.username);
            
            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                session_usernames_[session.session_id] = username;
            }

            std::cout << "Received handshake init from client " << client_handshake.client_id 
                      << " (" << (username.empty() ? "No Username" : username) << ")" << std::endl;

            // Step 2: Generate DH key pair for forward secrecy
            std::cout << "Generating DH key pair..." << std::endl;
            SecureComm::KeyPair dh_keypair = crypto_manager_->generate_dh_keypair();
            std::cout << "DH key pair generated successfully" << std::endl;
            
            // Step 3: Perform key exchange
            std::cout << "Performing DH key exchange..." << std::endl;
            std::vector<uint8_t> client_public_key_vec(client_handshake.public_key, client_handshake.public_key + SecureComm::DH_KEY_SIZE);
            std::vector<uint8_t> shared_secret = crypto_manager_->perform_dh_key_exchange(
                dh_keypair.private_key, client_public_key_vec);
            std::cout << "DH key exchange completed successfully" << std::endl;
            
            // Derive session key
            std::vector<uint8_t> client_nonce_vec(client_handshake.nonce, client_handshake.nonce + SecureComm::IV_SIZE);
            std::vector<uint8_t> session_key = crypto_manager_->derive_shared_secret(
                shared_secret, client_nonce_vec);

            // Store session key
            session_manager_->set_session_key(session.session_id, session_key);
            session.shared_secret = shared_secret;
            session.current_key = session_key;

            // Step 4: Send handshake response
            std::cout << "Sending handshake response..." << std::endl;
            SecureComm::HandshakeMessage server_handshake;
            server_handshake.client_id = session.client_id;
            server_handshake.session_id = session.session_id;
            server_handshake.fs_type = SecureComm::ForwardSecrecyType::PERFECT_FORWARD_SECRECY;
            
            // Copy DH public key
            size_t key_copy_size = std::min<size_t>(dh_keypair.public_key.size(), SecureComm::DH_KEY_SIZE);
            std::copy(dh_keypair.public_key.begin(), dh_keypair.public_key.begin() + key_copy_size, server_handshake.public_key);
            
            // Copy nonce
            std::copy(client_handshake.nonce, client_handshake.nonce + SecureComm::IV_SIZE, server_handshake.nonce);

            SecureComm::MessageHeader response_header;
            response_header.version = SecureComm::ProtocolVersion::V1_0;
            response_header.type = SecureComm::MessageType::HANDSHAKE_RESPONSE;
            response_header.sequence_number = 1;
            response_header.timestamp = SecureComm::get_current_timestamp_seconds();
            response_header.payload_size = sizeof(SecureComm::HandshakeMessage);
            response_header.flags = 0;

            std::vector<uint8_t> response_data = SecureComm::serialize_header(response_header);
            std::vector<uint8_t> handshake_payload = SecureComm::serialize_handshake(server_handshake);
            response_data.insert(response_data.end(), handshake_payload.begin(), handshake_payload.end());

            if (!send_data(client_socket, response_data)) {
                std::cerr << "Failed to send handshake response" << std::endl;
                return false;
            }
            std::cout << "Handshake response sent successfully" << std::endl;

            // Step 5: Receive handshake complete
            std::cout << "Waiting for handshake complete..." << std::endl;
            std::vector<uint8_t> complete_data = receive_data(client_socket);
            SecureComm::MessageHeader complete_header = SecureComm::deserialize_header(complete_data);
            
            if (complete_header.type != SecureComm::MessageType::HANDSHAKE_COMPLETE) {
                std::cerr << "Expected HANDSHAKE_COMPLETE, got " << SecureComm::message_type_to_string(complete_header.type) << std::endl;
                return false;
            }

            // Authenticate session
            session_manager_->authenticate_session(session.session_id, std::vector<uint8_t>());
            session.authenticated = true;

            std::cout << "Handshake completed successfully for session " << session.session_id << std::endl;
            return true;

        } catch (const std::exception& e) {
            std::cerr << "Handshake error: " << e.what() << std::endl;
            return false;
        }
    }

    void handle_encrypted_messages(int client_socket, SecureComm::SessionInfo& session) {
        uint32_t message_counter = 0;
        
        while (running_) {
            try {
                std::vector<uint8_t> encrypted_data = receive_data(client_socket);
                if (encrypted_data.empty()) {
                    break; // Client disconnected
                }

                SecureComm::MessageHeader header = SecureComm::deserialize_header(encrypted_data);
                
                if (header.type == SecureComm::MessageType::ENCRYPTED_MESSAGE) {
                    // Extract encrypted message
                    std::vector<uint8_t> payload(encrypted_data.begin() + sizeof(SecureComm::MessageHeader), encrypted_data.end());
                    SecureComm::EncryptedMessage encrypted_msg = SecureComm::deserialize_encrypted_message(payload);

                    // Verify session
                    SecureComm::AuthResult auth_result = session_manager_->verify_session_auth(session.session_id, 
                                                                                  std::vector<uint8_t>(encrypted_msg.signature, 
                                                                                                      encrypted_msg.signature + SecureComm::SIGNATURE_SIZE));
                    if (auth_result != SecureComm::AuthResult::SUCCESS) {
                        std::cerr << "Authentication failed: " << static_cast<int>(auth_result) << std::endl;
                        send_error(client_socket, SecureComm::ErrorCode::AUTHENTICATION_FAILED);
                        break;
                    }

                    // Decrypt message
                    std::vector<uint8_t> key = session_manager_->get_session_key(session.session_id);
                    std::vector<uint8_t> iv(encrypted_msg.iv, encrypted_msg.iv + SecureComm::IV_SIZE);
                    
                    std::vector<uint8_t> decrypted_data = crypto_manager_->decrypt_aes_gcm(
                        std::vector<uint8_t>(encrypted_msg.encrypted_data, 
                                           encrypted_msg.encrypted_data + encrypted_msg.data_len),
                        key, iv, 
                        std::vector<uint8_t>(encrypted_msg.tag, encrypted_msg.tag + SecureComm::GCM_TAG_SIZE));

                    // Process message
                    std::string message(decrypted_data.begin(), decrypted_data.end());
                    std::cout << "Received encrypted message from client " << session.client_id 
                              << ": " << message << std::endl;

                    // Broadcast message or send direct message
                    std::string sender_name = session_usernames_[session.session_id];
                    if (sender_name.empty()) sender_name = "Client " + std::to_string(session.client_id);
                    
                    std::string final_message = sender_name + ": " + message;

                    std::string target_user(encrypted_msg.target_username);
                    if (!target_user.empty()) {
                        // Direct Message
                        bool found = false;
                        int target_socket = -1;
                        uint32_t target_session_id = 0;
                        
                        {
                            std::lock_guard<std::mutex> lock(sessions_mutex_);
                            for (const auto& pair : session_usernames_) {
                                if (pair.second == target_user) {
                                    target_session_id = pair.first;
                                    
                                    // Find socket for this session
                                    for (const auto& sock_pair : active_sessions_) {
                                        if (sock_pair.second == target_session_id) {
                                            target_socket = sock_pair.first;
                                            found = true;
                                            break;
                                        }
                                    }
                                    break;
                                }
                            }
                        }

                        if (found) {
                            try {
                                SecureComm::SessionInfo target_session = session_manager_->get_session(target_session_id);
                                send_encrypted_message(target_socket, target_session, "[Whisper from " + sender_name + "] " + message);
                                // Acknowledge to sender handled by client usually, but server can send "Message sent"
                            } catch (...) {
                                std::cerr << "Failed to send DM" << std::endl;
                            }
                        } else {
                            // Notify sender user not found
                            send_encrypted_message(client_socket, session, "[Server] User " + target_user + " not found.");
                        }
                    } else {
                        // Broadcast
                       broadcast_message(client_socket, final_message);
                    }
                    
                    // Send confirmation to sender (optional)
                    // send_encrypted_message(client_socket, session, "Server received: " + message);

                    message_counter++;
                    
                    // Rotate key every 10 messages for forward secrecy
                    if (message_counter % 10 == 0) {
                        session_manager_->rotate_session_key(session.session_id);
                        std::cout << "Key rotated for session " << session.session_id << std::endl;
                    }

                } else if (header.type == SecureComm::MessageType::KEY_ROTATION) {
                    // Handle key rotation request
                    session_manager_->rotate_session_key(session.session_id);
                    std::cout << "Key rotation completed for session " << session.session_id << std::endl;
                    
                    // Send key rotation confirmation
                    send_key_rotation_response(client_socket, session);

                } else if (header.type == SecureComm::MessageType::ERROR_MESSAGE) {
                    std::cerr << "Received error message from client" << std::endl;
                    break;

                } else {
                    std::cerr << "Unknown message type: " << static_cast<int>(header.type) << std::endl;
                    send_error(client_socket, SecureComm::ErrorCode::INVALID_MESSAGE);
                }

            } catch (const std::exception& e) {
                std::cerr << "Error handling encrypted message: " << e.what() << std::endl;
                send_error(client_socket, SecureComm::ErrorCode::INTERNAL_ERROR);
                break;
            }
        }
    }

    void send_encrypted_message(int client_socket, const SecureComm::SessionInfo& session, const std::string& message) {
        try {
            std::vector<uint8_t> message_data(message.begin(), message.end());
            std::vector<uint8_t> key = session_manager_->get_session_key(session.session_id);
            std::vector<uint8_t> iv = crypto_manager_->generate_random_bytes(SecureComm::IV_SIZE);
            
            auto [encrypted_data, tag] = crypto_manager_->encrypt_aes_gcm(message_data, key, iv);
            
            SecureComm::EncryptedMessage encrypted_msg;
            encrypted_msg.session_id = session.session_id;
            encrypted_msg.message_id = session.message_counter;
            encrypted_msg.data_len = static_cast<uint32_t>(encrypted_data.size());
            
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
            std::vector<uint8_t> signature = crypto_manager_->sign_data(encrypted_data, server_keypair_.private_key);
            size_t sig_copy_size = std::min<size_t>(signature.size(), SecureComm::SIGNATURE_SIZE);
            std::copy(signature.begin(), signature.begin() + sig_copy_size, encrypted_msg.signature);

            std::vector<uint8_t> msg_payload = SecureComm::serialize_encrypted_message(encrypted_msg);

            SecureComm::MessageHeader header;
            header.version = SecureComm::ProtocolVersion::V1_0;
            header.type = SecureComm::MessageType::ENCRYPTED_MESSAGE;
            header.sequence_number = session.message_counter;
            header.timestamp = SecureComm::get_current_timestamp_seconds();
            header.payload_size = static_cast<uint16_t>(msg_payload.size());
            header.flags = 0;

            std::vector<uint8_t> response_data = SecureComm::serialize_header(header);
            response_data.insert(response_data.end(), msg_payload.begin(), msg_payload.end());

            send_data(client_socket, response_data);

        } catch (const std::exception& e) {
            std::cerr << "Failed to send encrypted message: " << e.what() << std::endl;
        }
    }

    void send_key_rotation_response(int client_socket, const SecureComm::SessionInfo& session) {
        SecureComm::MessageHeader header;
        header.version = SecureComm::ProtocolVersion::V1_0;
        header.type = SecureComm::MessageType::KEY_ROTATION;
        header.sequence_number = session.message_counter;
        header.timestamp = SecureComm::get_current_timestamp_seconds();
        header.payload_size = 0;
        header.flags = 0;

        std::vector<uint8_t> response_data = SecureComm::serialize_header(header);
        send_data(client_socket, response_data);
    }

    void send_error(int client_socket, SecureComm::ErrorCode error_code) {
        SecureComm::MessageHeader header;
        header.version = SecureComm::ProtocolVersion::V1_0;
        header.type = SecureComm::MessageType::ERROR_MESSAGE;
        header.sequence_number = 0;
        header.timestamp = SecureComm::get_current_timestamp_seconds();
        header.payload_size = sizeof(SecureComm::ErrorCode);
        header.flags = 0;

        std::vector<uint8_t> response_data = SecureComm::serialize_header(header);
        std::vector<uint8_t> error_data(reinterpret_cast<const uint8_t*>(&error_code), 
                                       reinterpret_cast<const uint8_t*>(&error_code) + sizeof(SecureComm::ErrorCode));
        response_data.insert(response_data.end(), error_data.begin(), error_data.end());

        send_data(client_socket, response_data);
    }

    std::vector<uint8_t> receive_data(int client_socket) {
        // Read header
        std::vector<uint8_t> header_data(sizeof(SecureComm::MessageHeader));
        size_t total_received = 0;
        
        while (total_received < header_data.size()) {
            int received = recv(client_socket, reinterpret_cast<char*>(header_data.data() + total_received), 
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
            int received = recv(client_socket, reinterpret_cast<char*>(payload.data() + total_received), 
                            static_cast<int>(payload.size() - total_received), 0);
            if (received <= 0) return {};
            total_received += received;
        }
        
        header_data.insert(header_data.end(), payload.begin(), payload.end());
        return header_data;
    }

    bool send_data(int client_socket, const std::vector<uint8_t>& data) {
        int bytes_sent = send(client_socket, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0);
        return bytes_sent == static_cast<int>(data.size());
    }
};

std::atomic<bool> g_running(true);

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nReceived signal " << signal << ", shutting down..." << std::endl;
        g_running = false;
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Parse command line arguments
    uint16_t port = SecureComm::DEFAULT_PORT;
    if (argc > 1) {
        try {
            port = static_cast<uint16_t>(std::stoi(argv[1]));
        } catch (const std::exception& e) {
            std::cerr << "Invalid port number: " << argv[1] << std::endl;
            std::cerr << "Usage: " << argv[0] << " [port]" << std::endl;
            return 1;
        }
    }

    try {
        SecureServer server;
        
        if (!server.start(port)) {
            std::cerr << "Failed to start server" << std::endl;
            return 1;
        }

        std::cout << "Secure Communication Server" << std::endl;
        std::cout << "Features:" << std::endl;
        std::cout << "- RSA-2048 key exchange" << std::endl;
        std::cout << "- AES-256-GCM encryption" << std::endl;
        std::cout << "- Perfect Forward Secrecy with DH key exchange" << std::endl;
        std::cout << "- Session authentication" << std::endl;
        std::cout << "- Automatic key rotation" << std::endl;
        std::cout << "- Digital signatures" << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;

        server.run();

    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 
/*
Updated main.cpp with full OS feature integration:
- Processes: Using fork() to handle each client
- Threads: Optional support could be extended
- Synchronization: mutex for shared data (client_pin_attempts)
- File Handling: reading/writing received files
- Scheduling: Implements Round Robin-like server queue handling
- Memory Management: std::vector, dynamic buffers
- IPC: socket communication between client and server
- Debug fix: Logs and trims received PIN to ensure comparison works
*/

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstring>
#include <algorithm>
#include <map>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "protocol.h"
#include "security_ops.h"

using namespace std;

const string EXPECTED_PIN = "1234";
map<string, int> client_pin_attempts;
mutex pin_attempts_mutex;
condition_variable client_cv;
queue<pair<int, string>> client_queue;
mutex queue_mutex;
const int MAX_PIN_ATTEMPTS = 3;

void log_message(const string& message, const string& client_ip = "") {
    time_t now = time(0);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    if (!client_ip.empty())
        cout << buf << " [Client " << client_ip << "] " << message << endl;
    else
        cout << buf << " [Server] " << message << endl;
}

string read_line_from_socket(int sock_fd) {
    string line;
    char buffer[1];
    while (read(sock_fd, buffer, 1) > 0) {
        if (buffer[0] == '\n') break;
        line += buffer[0];
    }
    return line;
}

void send_to_socket(int sock_fd, const string& message) {
    send(sock_fd, message.c_str(), message.length(), 0);
}

void handle_client(int client_socket, string client_ip_str) {
    log_message("Accepted connection.", client_ip_str);

    {
        lock_guard<mutex> lock(pin_attempts_mutex);
        if (client_pin_attempts[client_ip_str] >= MAX_PIN_ATTEMPTS) {
            log_message("Rate limit exceeded. Closing connection.", client_ip_str);
            send_to_socket(client_socket, MSG_S_RATE_LIMIT);
            close(client_socket);
            return;
        }
    }

    string pin_line = read_line_from_socket(client_socket);
    log_message("Received PIN line: " + pin_line, client_ip_str);
    if (pin_line.rfind(MSG_C_PIN_PREFIX, 0) == 0) {
        string received_pin = pin_line.substr(MSG_C_PIN_PREFIX.length());
        received_pin.erase(remove(received_pin.begin(), received_pin.end(), '\r'), received_pin.end());
        received_pin.erase(remove(received_pin.begin(), received_pin.end(), '\n'), received_pin.end());

        if (received_pin == EXPECTED_PIN) {
            send_to_socket(client_socket, MSG_S_AUTH_SUCCESS);
            log_message("PIN authenticated successfully.", client_ip_str);
            lock_guard<mutex> lock(pin_attempts_mutex);
            client_pin_attempts[client_ip_str] = 0;
        } else {
            lock_guard<mutex> lock(pin_attempts_mutex);
            client_pin_attempts[client_ip_str]++;
            log_message("Invalid PIN received: '" + received_pin + "'. Attempts: " + to_string(client_pin_attempts[client_ip_str]), client_ip_str);
            send_to_socket(client_socket, MSG_S_AUTH_FAIL);
            close(client_socket);
            return;
        }
    } else {
        log_message("Invalid PIN message format. Closing.", client_ip_str);
        send_to_socket(client_socket, MSG_S_AUTH_FAIL);
        close(client_socket);
        return;
    }

    string session_key_plain = generate_session_key(SESSION_KEY_LENGTH);
    string pin_derived_skey_enc_key = derive_key_from_pin(EXPECTED_PIN, PIN_SALT, SESSION_KEY_LENGTH);

    vector<char> skey_plain_vec(session_key_plain.begin(), session_key_plain.end());
    vector<char> skey_encrypted_vec = xor_encrypt_decrypt(skey_plain_vec, pin_derived_skey_enc_key);
    string skey_encrypted_hex = bytes_to_hex(string(skey_encrypted_vec.begin(), skey_encrypted_vec.end()));

    send_to_socket(client_socket, MSG_S_SESSION_KEY_PREFIX + skey_encrypted_hex + "\n");
    log_message("Sent encrypted session key.", client_ip_str);

    string header_line = read_line_from_socket(client_socket);
    if (header_line.rfind(MSG_C_FILE_HEADER_PREFIX, 0) != 0) {
        log_message("Invalid file header format. Closing.", client_ip_str);
        send_to_socket(client_socket, MSG_S_HEADER_NACK);
        close(client_socket);
        return;
    }

    stringstream ss_header(header_line.substr(MSG_C_FILE_HEADER_PREFIX.length()));
    string filename, filesize_str, checksum_str;
    getline(ss_header, filename, ':');
    getline(ss_header, filesize_str, ':');
    getline(ss_header, checksum_str, ':');

    long filesize = stol(filesize_str);
    uint32_t expected_checksum = stoul(checksum_str);

    filename.erase(remove_if(filename.begin(), filename.end(), [](char c) {
        return !(isalnum(c) || c == '.' || c == '_' || c == '-');
    }), filename.end());
    if (filename.empty()) filename = "default_received_file.dat";

    filesystem::path save_path = filesystem::path(RECEIVED_FILES_DIR) / filename;
    log_message("Receiving file: " + filename + " (" + filesize_str + " bytes)", client_ip_str);
    send_to_socket(client_socket, MSG_S_HEADER_ACK);

    ofstream outfile(save_path, ios::binary);
    if (!outfile.is_open()) {
        log_message("Failed to open file.", client_ip_str);
        send_to_socket(client_socket, MSG_S_TRANSFER_FAIL_OTHER);
        close(client_socket);
        return;
    }

    vector<char> file_buffer_decrypted;
    file_buffer_decrypted.reserve(filesize);
    long bytes_received = 0;
    vector<char> chunk_buffer_raw(BUFFER_SIZE);

    while (bytes_received < filesize) {
        int len = recv(client_socket, chunk_buffer_raw.data(), min((long)BUFFER_SIZE, filesize - bytes_received), 0);
        if (len <= 0) break;
        vector<char> encrypted_chunk(chunk_buffer_raw.begin(), chunk_buffer_raw.begin() + len);
        vector<char> decrypted_chunk = xor_encrypt_decrypt(encrypted_chunk, session_key_plain);
        outfile.write(decrypted_chunk.data(), decrypted_chunk.size());
        file_buffer_decrypted.insert(file_buffer_decrypted.end(), decrypted_chunk.begin(), decrypted_chunk.end());
        bytes_received += decrypted_chunk.size();
    }
    outfile.close();

    uint32_t calculated_checksum = calculate_checksum(file_buffer_decrypted.data(), file_buffer_decrypted.size());
    if (calculated_checksum == expected_checksum) {
        log_message("Checksum match. File OK.", client_ip_str);
        send_to_socket(client_socket, MSG_S_TRANSFER_SUCCESS);
    } else {
        log_message("Checksum mismatch.", client_ip_str);
        send_to_socket(client_socket, MSG_S_TRANSFER_FAIL_CHECKSUM);
    }

    close(client_socket);
    log_message("Connection closed.", client_ip_str);
}

void scheduler_thread() {
    while (true) {
        unique_lock<mutex> lock(queue_mutex);
        client_cv.wait(lock, [] { return !client_queue.empty(); });
        auto [sock, ip] = client_queue.front();
        client_queue.pop();
        lock.unlock();

        pid_t pid = fork();
        if (pid == 0) {
            handle_client(sock, ip);
            exit(0);
        } else if (pid > 0) {
            close(sock);
            waitpid(-1, nullptr, WNOHANG);
        } else {
            log_message("Fork failed.");
        }
    }
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if (!filesystem::exists(RECEIVED_FILES_DIR)) {
        filesystem::create_directory(RECEIVED_FILES_DIR);
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(DEFAULT_PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 5);

    log_message("Server listening on port " + to_string(DEFAULT_PORT));

    thread scheduler(scheduler_thread);
    scheduler.detach();

    while (true) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) continue;

        char client_ip_cstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, client_ip_cstr, INET_ADDRSTRLEN);
        string client_ip_str(client_ip_cstr);

        {
            lock_guard<mutex> lock(queue_mutex);
            client_queue.push({new_socket, client_ip_str});
        }
        client_cv.notify_one();
    }

    close(server_fd);
    return 0;
}


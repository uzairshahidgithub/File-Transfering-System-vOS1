# Secure File Transfer Terminal Application
## Overview
This project implements a secure file transfer system consisting of a C++ server and a Python client. The application allows authenticated clients to send files to the server, with a focus on demonstrating various operating system concepts and basic security mechanisms. Communication between the client and server is secured using a PIN-based authentication system, followed by the exchange of a session key used to encrypt file data via XOR encryption. The integrity of transferred files is verified using checksums.

**Server-side (C++)**: Handles client connections, authentication, session key generation, file reception, decryption, and storage. It uses a multi-process architecture (`fork()`) to manage multiple client requests concurrently, with a client queue and scheduler.
**Client-side (Python)**: Initiates connection, authenticates with the server using a PIN, receives and decrypts the session key, and sends files by encrypting them with the session key. It includes features like sending multiple files and a basic round-robin sending scheduler.

## Features
* **User Authentication**: PIN-based authentication before any file transfer operations.
* **Rate Limiting**: Basic protection against brute-force PIN attacks on the server.
* **Secure Session Key Exchange**:
    * Server generates a session key.
    * Session key is encrypted using a key derived from the user's PIN and a predefined salt.
    * Client decrypts the session key using the same PIN-derived key.
* **File Encryption**: File data is encrypted using XOR with the established session key before transmission and decrypted on receipt.
* **File Integrity Check**: Checksum calculation and verification to ensure data integrity during transfer.
* **Multi-Client Handling (Server)**: The C++ server uses `fork()` to handle each client connection in a separate process, managed by a client queue and a scheduler thread.
* **Multi-File Upload (Client)**: The Python client can take multiple files as arguments and send them sequentially.
* **Client-side Scheduler**: A simple round-robin scheduler in the Python client demonstrates managing file transfer tasks.
* **Logging**: Both client and server applications include logging for monitoring and debugging.
* **Configuration**: Key parameters like server IP, port, PIN salt, and buffer sizes are configurable.

## Architecture
The system follows a client-server architecture:
* **C++ Server**:
    * Listens for incoming TCP connections.
    * Manages a queue of connected clients.
    * A scheduler thread dispatches client handling to new processes created via `fork()`.
    * Each client process handles authentication, session key exchange, and file reception.
    * Received files are stored in a designated directory (`received_files/`).
* **Python Client**:
    * Connects to the C++ server.
    * Performs authentication by sending a PIN.
    * Receives and processes the encrypted session key.
    * Sends file metadata (name, size, checksum) followed by encrypted file data.
* **Communication Protocol**:
    * A simple text-based protocol is used for control messages (PIN, session key, acknowledgments).
    * Prefixes like `PIN:`, `SKEY:`, `FHDR:` are used to identify message types.
    * File data is sent as a raw byte stream after the header is acknowledged.

## Security Aspects
* **Authentication**: Access is protected by a PIN. The server uses `EXPECTED_PIN` for verification.
* **Session Key Cryptography**:
    * A key is derived from the user's PIN and a salt (`PIN_SALT`) to encrypt the session key. This salt must be identical on both client and server.
    * The actual file transfer is encrypted using a randomly generated session key.
    * XOR encryption is used for both session key protection and file data encryption.
* **Checksum**: A simple checksum is used to verify that files are not corrupted during transit.
* **Rate Limiting**: The server limits the number of PIN attempts from a single IP to mitigate basic brute-force attacks.

**Disclaimer**: The security mechanisms employed (PIN "hashing", XOR encryption) are for illustrative and educational purposes. XOR encryption, in particular, is not considered cryptographically secure for protecting sensitive data against determined attackers. This project should not be used for transferring highly sensitive information in a production environment without significant enhancements to its cryptographic schemes.

## Prerequisites
* **C++ Server**:
    * A C++ compiler supporting C++17 (for `std::filesystem`), e.g., GCC (g++) or Clang.
    * Standard C++ libraries.
    * POSIX-compliant system for `fork`, sockets etc. (Linux, macOS).
* **Python Client**:
    * Python 3.x.

## Build Instructions
### C++ Server

1.  Navigate to the `cpp_receiver` directory:
    ```bash
    cd cpp_receiver
    ```
2.  Compile the server code. For example, using g++:
    ```bash
   make
    ```
    *(The `-pthread` flag is good practice if you extend threading further, though `fork` is the primary concurrency model here for client handling)*

## Configuration
### Shared Settings
For the system to function correctly, certain security parameters **must be identical** in both the server and client configurations:
* **PIN Salt**:
    * Server: `PIN_SALT` in `cpp_server/protocol.h`
    * Client: `PIN_SALT_PY` in `python_client/config_client.py`
* **Session Key Length**:
    * Server: `SESSION_KEY_LENGTH` in `cpp_server/protocol.h`
    * Client: `SESSION_KEY_LENGTH_PY` in `python_client/config_client.py`
* **Checksum Logic**: The checksum calculation logic in `security_ops.cpp` and `security_ops_py.py` must be equivalent.
* **PIN "Hashing" / Derivation Logic**: The `derive_key_from_pin` functions in `security_ops.cpp` and `security_ops_py.py` must be equivalent.

### Server Configuration (`cpp_server/protocol.h`)
* `EXPECTED_PIN`: The PIN clients must use for authentication (default: "1234"). (This is directly in `main.cpp`, not `protocol.h`).
* `DEFAULT_PORT`: The port the server listens on (default: 8080).
* `RECEIVED_FILES_DIR`: Directory where uploaded files are stored (default: "received_files").

### Client Configuration (`python_client/config_client.py`)
* `SERVER_IP`: IP address of the C++ server (default: '127.0.0.1').
* `SERVER_PORT`: Port of the C++ server (must match `DEFAULT_PORT` on the server, default: 8080).
* `BUFFER_SIZE`: Network buffer size.

## Running the Application
1.  **Start the C++ Server**:
    * Navigate to the `cpp_receiver` directory.
    * Run the compiled server executable:
        ```bash
        ./cpp_server
        ```
    * The server will log that it's listening on the configured port.

2.  **Run the Python Client**:
    * Open a new terminal.
    * Navigate to the `python_sender` directory.
    * Run the client script with the required PIN and file path(s) as command-line arguments:
        ```bash
        python client.py <PIN> <file1_path> [file2_path] ...
        ```
        For example:
        ```bash
        python client.py 1234 /path/to/your/document.txt /path/to/another/image.jpg
        ```
    * The client will attempt to connect, authenticate, and send the specified files. Progress and status messages will be logged.

## Protocol Highlights
The communication protocol is defined by messages exchanged between client and server, often new-line terminated. Key prefixes include:
* Client to Server:
    * `PIN:<pin_value>\n`: Client sends its PIN.
    * `FHDR:<filename>:<filesize>:<checksum>\n`: Client sends file metadata.
* Server to Client:
    * `AUTH_SUCCESS\n` or `AUTH_FAIL\n` or `RATE_LIMIT\n`: Authentication status.
    * `SKEY:<encrypted_session_key_hex>\n`: Server sends the encrypted session key.
    * `HDR_ACK\n` or `HDR_NACK\n`: File header acknowledgment.
    * `TRANSFER_SUCCESS\n` or `TRANSFER_FAIL_CHECKSUM\n` or `TRANSFER_FAIL_OTHER\n`: Final transfer status.
(Refer to `cpp_server/protocol.h` for a more complete list of protocol messages and constants).

## OS Concepts Demonstrated
This project touches upon several operating system concepts:
* **Processes**: The C++ server uses `fork()` to create a new process for handling each client connection from its queue.
* **Threads**:
    * The C++ server uses a `std::thread` for its main client request scheduler.
    * The Python client uses `threading.Thread` for its round-robin file sending simulation.
* **Inter-Process Communication (IPC)**: Sockets (TCP/IP) are used for communication between the Python client process and the C++ server processes.
* **Synchronization**:
    * C++ Server: `std::mutex` is used to protect shared data like `client_pin_attempts` and the `client_queue`. `std::condition_variable` is used with the client queue.
    * Python Client: `multiprocessing.Queue` is used for passing file paths to the scheduler process, ensuring safe communication between processes. `queue.Queue` is used internally by the scheduler.
* **File Handling**: Both client and server perform file I/O operations (reading files for sending, writing received files).
* **Scheduling**:
    * Server: A simple FIFO queue (`client_queue`) and a dedicated thread manage incoming client connections before they are forked.
    * Client: A round-robin like scheduler (`round_robin_scheduler`) is implemented to send multiple files, simulating time-sliced execution for demonstration.
* **Memory Management**:
    * C++: Uses `std::vector<char>` for dynamic buffers, `std::string`, and manual memory management inherent with `fork()` (though `exit()` in child cleans up).
    * Python: Automatic memory management by the Python interpreter.

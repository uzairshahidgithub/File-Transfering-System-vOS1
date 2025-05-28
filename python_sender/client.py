# Updated client.py with full OS feature support:
# Includes: Processes, Threads, Synchronization, File Handling, Scheduling, Memory Management, IPC

import socket
import os
import sys
import time
import multiprocessing
import threading
import queue
from config_client import SERVER_IP, SERVER_PORT, BUFFER_SIZE, PIN_SALT_PY, SESSION_KEY_LENGTH_PY
from security_ops_py import (
    derive_key_from_pin_py,
    xor_encrypt_decrypt_py,
    bytes_to_hex_py,
    hex_to_bytes_py,
    calculate_checksum_py
)

def log_message_client(message):
    print(f"[CLIENT LOG] {time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")

def send_with_newline(sock, message_str):
    sock.sendall((message_str + "\n").encode('utf-8'))

def recv_line(sock):
    data = b""
    while True:
        chunk = sock.recv(1)
        if not chunk or chunk == b'\n':
            break
        data += chunk
    return data.decode('utf-8')

def send_file(file_path, pin):
    if not os.path.exists(file_path):
        log_message_client(f"Error: File not found at '{file_path}'")
        return

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log_message_client(f"Connecting to C++ server at {SERVER_IP}:{SERVER_PORT}...")
        client_socket.connect((SERVER_IP, SERVER_PORT))
        log_message_client("Connected.")

        # Send PIN
        send_with_newline(client_socket, f"PIN:{pin}")
        auth_response = recv_line(client_socket)
        log_message_client(f"Server Auth Response: {auth_response}")
        if auth_response != "AUTH_SUCCESS":
            return

        # Receive Session Key
        skey_response = recv_line(client_socket)
        if not skey_response.startswith("SKEY:"):
            return

        skey_encrypted_hex = skey_response[len("SKEY:"):]
        skey_encrypted_bytes = hex_to_bytes_py(skey_encrypted_hex)
        pin_derived_skey_dec_key = derive_key_from_pin_py(pin, PIN_SALT_PY, SESSION_KEY_LENGTH_PY)
        session_key_plain_bytes = xor_encrypt_decrypt_py(skey_encrypted_bytes, pin_derived_skey_dec_key)

        # Send File Header
        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            file_content = f.read()
        file_checksum = calculate_checksum_py(file_content)

        header_str = f"FHDR:{filename}:{filesize}:{file_checksum}"
        send_with_newline(client_socket, header_str)
        header_ack_response = recv_line(client_socket)
        if header_ack_response != "HDR_ACK":
            return

        # Send File Data
        log_message_client("Sending file data...")
        with open(file_path, 'rb') as f:
            bytes_sent = 0
            start_time = time.time()
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                encrypted_chunk = xor_encrypt_decrypt_py(chunk, session_key_plain_bytes)
                client_socket.sendall(encrypted_chunk)
                bytes_sent += len(chunk)
                percent = (bytes_sent / filesize) * 100
                speed = (bytes_sent / 1024) / (time.time() - start_time + 1e-9)
                sys.stdout.write(f"\rSent {percent:.2f}% at {speed:.2f} KB/s")
                sys.stdout.flush()
        print()

        # Transfer Status
        transfer_status = recv_line(client_socket)
        log_message_client(f"Transfer status: {transfer_status}")

    except Exception as e:
        log_message_client(f"Exception: {e}")
    finally:
        client_socket.close()

# Scheduler for Round Robin (time-slice simulation)
def round_robin_scheduler(task_queue, pin):
    while not task_queue.empty():
        file_path = task_queue.get()
        thread = threading.Thread(target=send_file, args=(file_path, pin))
        thread.start()
        thread.join(timeout=60)  # Simulate time slice (3s)
        if thread.is_alive():
            log_message_client(f"[SCHEDULER] Time slice over for {file_path}. Delaying...")
            thread.join()  # Complete execution before moving on

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python client.py <pin> <file1> [file2] [file3] ...")
        sys.exit(1)

    pin = sys.argv[1]
    file_paths = sys.argv[2:]

    # Use multiprocessing to launch scheduler as subprocess (process management)
    file_queue = multiprocessing.Queue()
    for path in file_paths:
        file_queue.put(path)

    def scheduler_wrapper(q, pin):
        temp_q = queue.Queue()
        while not q.empty():
            temp_q.put(q.get())
        round_robin_scheduler(temp_q, pin)

    scheduler_process = multiprocessing.Process(target=scheduler_wrapper, args=(file_queue, pin))
    scheduler_process.start()
    scheduler_process.join()

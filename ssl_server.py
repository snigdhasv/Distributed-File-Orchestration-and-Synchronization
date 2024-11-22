import socket
import threading
import os
import signal
import sys
import logging
from datetime import datetime
from cryptography.fernet import Fernet
import ssl
import json
import hashlib
import time
from collections import defaultdict

# Configuration Constants
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
RATE_LIMIT = 10  # Maximum requests per second
REQUESTS_WINDOW = 1  # Time window in seconds

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('server.log')
    ]
)
logger = logging.getLogger(__name__)

# Encryption key setup
if not os.path.exists("encryption_key.key"):
    encryption_key = Fernet.generate_key()
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(encryption_key)
        logger.info("New encryption key generated")

with open("encryption_key.key", "rb") as key_file:
    encryption_key = key_file.read()

cipher = Fernet(encryption_key)

# Rate Limiter Class
class RateLimiter:
    def __init__(self):
        self.clients = defaultdict(list)

    def allow_request(self, client_ip):
        current_time = time.time()
        if client_ip not in self.clients:
            self.clients[client_ip] = []
        # Remove timestamps outside the time window
        self.clients[client_ip] = [
            t for t in self.clients[client_ip] if t > current_time - REQUESTS_WINDOW
        ]
        if len(self.clients[client_ip]) < RATE_LIMIT:
            self.clients[client_ip].append(current_time)
            return True
        return False

# Path validation function
def sanitize_and_validate_path(base_dir, filename):
    """
    Sanitize and validate a file path to ensure it resides within the base directory.
    """
    sanitized_path = os.path.join(base_dir, os.path.basename(filename))
    if not os.path.abspath(sanitized_path).startswith(os.path.abspath(base_dir)):
        raise ValueError(f"Invalid file path: {sanitized_path}")
    return sanitized_path

# Load user credentials
def load_user_credentials():
    try:
        with open('id_passwd.txt', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Create default credentials if file doesn't exist
        default_credentials = {
            "admin": hashlib.sha256("admin123".encode()).hexdigest(),
            "user1": hashlib.sha256("user123".encode()).hexdigest(),
            "testuser": hashlib.sha256("testpassword".encode()).hexdigest(),
        }
        with open('id_passwd.txt', 'w') as f:
            json.dump(default_credentials, f, indent=4)
        return default_credentials

# Authenticate user
def authenticate_user(username, password):
    try:
        credentials = load_user_credentials()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return username in credentials and credentials[username] == hashed_password
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return False

# Centralized Error Logging
def log_and_send_error(conn, client_addr, message, exception=None):
    """
    Log an error message with optional exception details and send it to the client.
    """
    if exception:
        logger.error(f"{message} from client {client_addr}: {exception}")
    else:
        logger.error(f"{message} from client {client_addr}")
    conn.sendall(f"ERROR: {message}\n".encode())

# Secure File Server Class
class SecureFileServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.server_socket = None
        self.context = self.setup_ssl_context()
        self.active_connections = set()
        self.connection_lock = threading.Lock()
        self.rate_limiter = RateLimiter()

    def setup_ssl_context(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        return context

    def handle_client(self, conn, addr):
        client_ip = addr[0]
        with self.connection_lock:
            self.active_connections.add(conn)

        try:
            logger.info(f"Connected by {addr}")
            conn.sendall(b"Connection established. Please authenticate.\n")

            try:
                # Authentication
                conn.sendall(b"Username: ")
                username = conn.recv(1024).decode().strip()
                conn.sendall(b"Password: ")
                password = conn.recv(1024).decode().strip()

                logger.debug(f"Received credentials - Username: {username}, Password: {password}")
                if not authenticate_user(username, password):
                    log_and_send_error(conn, addr, "Authentication failed")
                    return

                conn.sendall(b"Authentication successful.\n")
                client_dir = f'server_storage/{username}'
                os.makedirs(client_dir, exist_ok=True)
                logger.info(f"Client directory created/verified for user '{username}'")

                # Command Loop
                while True:
                    # Rate limit check
                    if not self.rate_limiter.allow_request(client_ip):
                        conn.sendall(b"ERROR: Too many requests. Please slow down.\n")
                        continue

                    command_data = conn.recv(1024).decode()
                    if not command_data:
                        break

                    logger.debug(f"Received command from {addr}: {command_data}")
                    command_parts = command_data.split()
                    if len(command_parts) == 0:
                        log_and_send_error(conn, addr, "Invalid command")
                        continue

                    command = command_parts[0]

                    # Quit Command
                    if command == 'QUIT':
                        logger.info(f"Client {addr} disconnected")
                        break

                    # Delete Command
                    elif command == "DELETE" and len(command_parts) > 1:
                        filename = command_parts[1]
                        try:
                            filepath = sanitize_and_validate_path(client_dir, filename)
                            if os.path.exists(filepath):
                                os.remove(filepath)
                                conn.sendall(f"File '{filename}' deleted successfully.\n".encode())
                                logger.info(f"File '{filename}' deleted for client {addr}")
                            else:
                                log_and_send_error(conn, addr, f"File '{filename}' not found")
                        except ValueError as e:
                            log_and_send_error(conn, addr, "Invalid file path", e)

                    # Upload Command
                    elif command == 'UPLOAD' and len(command_parts) > 1:
                        filename = command_parts[1]
                        conn.sendall(b"ACK")
                        file_data = b""
                        total_size = 0

                        try:
                            while True:
                                chunk = conn.recv(1024)
                                if chunk == b"EOF":
                                    break
                                total_size += len(chunk)
                                if total_size > MAX_FILE_SIZE:
                                    log_and_send_error(conn, addr, "File size exceeded during upload")
                                    return
                                file_data += chunk

                            filepath = sanitize_and_validate_path(client_dir, filename)
                            encrypted_data = cipher.encrypt(file_data)
                            with open(filepath, 'wb') as f:
                                f.write(encrypted_data)
                            conn.sendall(b"SUCCESS")
                            logger.info(f"File '{filename}' uploaded and encrypted for client {addr}")
                        except ValueError as e:
                            log_and_send_error(conn, addr, "Invalid file path", e)
                        except Exception as e:
                            log_and_send_error(conn, addr, f"Error saving file '{filename}'", e)

                    # Download Command
                    elif command == 'DOWNLOAD' and len(command_parts) > 1:
                        filename = command_parts[1]
                        try:
                            filepath = sanitize_and_validate_path(client_dir, filename)
                            if os.path.exists(filepath):
                                with open(filepath, 'rb') as f:
                                    encrypted_data = f.read()
                                    decrypted_data = cipher.decrypt(encrypted_data)
                                    for i in range(0, len(decrypted_data), 1024):
                                        chunk = decrypted_data[i:i+1024]
                                        conn.sendall(chunk)
                                conn.sendall(b"EOF")
                                logger.info(f"File '{filename}' downloaded by client {addr}")
                            else:
                                log_and_send_error(conn, addr, f"File '{filename}' not found")
                        except ValueError as e:
                            log_and_send_error(conn, addr, "Invalid file path", e)
                        except Exception as e:
                            log_and_send_error(conn, addr, f"Error downloading file '{filename}'", e)

                    # List Files Command
                    elif command == "LIST":
                        try:
                            files = os.listdir(client_dir)
                            if len(files) == 0:
                                conn.sendall(b"The server directory is empty.\n")
                            else:
                                conn.sendall("\n".join(files).encode())
                            logger.info(f"File list sent to client {addr}")
                        except Exception as e:
                            log_and_send_error(conn, addr, "Error listing files", e)

                    # View File Command
                    elif command == "VIEW" and len(command_parts) > 1:
                        filename = command_parts[1]
                        try:
                            filepath = sanitize_and_validate_path(client_dir, filename)
                            if os.path.exists(filepath):
                                with open(filepath, 'rb') as f:
                                    file_content = f.read()
                                    decrypted_data = cipher.decrypt(file_content)
                                    conn.sendall(decrypted_data[:1024])
                                    logger.info(f"Preview of file '{filename}' sent to client {addr}")
                            else:
                                log_and_send_error(conn, addr, f"File '{filename}' not found")
                        except ValueError as e:
                            log_and_send_error(conn, addr, "Invalid file path", e)
                        except Exception as e:
                            log_and_send_error(conn, addr, f"Error previewing file '{filename}'", e)

                    # Invalid Command
                    else:
                        log_and_send_error(conn, addr, "Invalid command")

            except Exception as e:
                log_and_send_error(conn, addr, "Error handling client", e)

        finally:
            with self.connection_lock:
                self.active_connections.remove(conn)
            conn.close()
            logger.info(f"Connection closed for client {addr}")

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        logger.info(f"Server listening on {self.host}:{self.port}")

        def signal_handler(sig, frame):
            logger.info("Shutdown signal received. Closing connections and shutting down server...")
            self.shutdown()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

        while True:
            try:
                client_socket, addr = self.server_socket.accept()
                secure_client = self.context.wrap_socket(client_socket, server_side=True)
                thread = threading.Thread(target=self.handle_client, args=(secure_client, addr))
                thread.start()
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")

    def shutdown(self):
        logger.info("Closing all active connections...")
        with self.connection_lock:
            for conn in self.active_connections:
                try:
                    conn.close()
                except:
                    pass
        
        if self.server_socket:
            self.server_socket.close()
        logger.info("Server shutdown complete")

if __name__ == "__main__":
    server = SecureFileServer()
    server.start()

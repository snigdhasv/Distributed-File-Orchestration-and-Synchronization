import socket
import threading
import time
import random
import ssl
import os
import signal
import psutil

# Define server details
SERVER_HOST = 'localhost'
SERVER_PORT = 8080
NUM_CLIENTS = 20  # Number of clients to simulate
NUM_OPERATIONS = 20  # Number of operations per client

# List of possible commands
COMMANDS = ["UPLOAD", "DOWNLOAD", "DELETE", "LIST", "VIEW", "QUIT"]

# Create SSL context
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations("server.crt")

# Monitor system resources (CPU and memory)
def monitor_resources():
    while True:
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        print(f"CPU: {cpu}% | Memory: {memory}%")
        time.sleep(1)

def simulate_client_operations(client_id, done_event):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_HOST, SERVER_PORT))
            ssl_sock = context.wrap_socket(s, server_hostname=SERVER_HOST)
            
            # Set timeout for socket operations
            ssl_sock.settimeout(5)

            # Send username and password for authentication (replace with valid credentials)
            username = "testuser"
            password = "testpassword"

            # Authentication
            ssl_sock.recv(1024)  # Receive "Connection established"
            ssl_sock.sendall(f"{username}\n".encode())
            ssl_sock.recv(1024)  # Receive "Password: "
            ssl_sock.sendall(f"{password}\n".encode())
            
            response = ssl_sock.recv(1024).decode()
            if "ERROR" in response:
                print(f"Client {client_id}: Authentication failed")
                return

            print(f"Client {client_id}: Authentication successful")

            for i in range(NUM_OPERATIONS):
                # Randomly pick a command to execute
                command = random.choice(COMMANDS)
                file_name = f"test_file_{random.randint(1, 100)}.txt"

                if command == "UPLOAD":
                    ssl_sock.sendall(f"UPLOAD {file_name}\n".encode())
                    ssl_sock.recv(1024)  # ACK
                    data = b"Some test data" * 50  # Simulated file data
                    ssl_sock.sendall(data)
                    ssl_sock.sendall(b"EOF")  # End of file
                    
                    # Measure throughput and latency
                    end_time = time.time()
                    latency = end_time - start_time
                    throughput = len(data) / latency / 1024  # KB/s
                    print(f"Client {client_id}: Uploaded file {file_name} - Latency: {latency:.2f}s, Throughput: {throughput:.2f}KB/s")
                    
                    # 10% chance to simulate signal-driven interruption during file transfer
                    if random.random() < 0.1:
                        print(f"Client {client_id}: Simulating failure for file upload")
                        return  # Gracefully exit the current operation
                    
                elif command == "DOWNLOAD":
                    ssl_sock.sendall(f"DOWNLOAD {file_name}\n".encode())
                    response = ssl_sock.recv(1024).decode()
                    if "ERROR" not in response:
                        end_time = time.time()
                        latency = end_time - start_time
                        print(f"Client {client_id}: Downloaded file {file_name} - Latency: {latency:.2f}s")
                
                elif command == "DELETE":
                    ssl_sock.sendall(f"DELETE {file_name}\n".encode())
                    end_time = time.time()
                    latency = end_time - start_time
                    print(f"Client {client_id}: Sent delete request for {file_name}- Latency: {latency:.2f}s")
                
                elif command == "LIST":
                    ssl_sock.sendall("LIST\n".encode())
                    response = ssl_sock.recv(1024).decode()
                    print(f"Client {client_id}: Listed files - {response}")
                
                elif command == "VIEW":
                    ssl_sock.sendall(f"VIEW {file_name}\n".encode())
                    response = ssl_sock.recv(1024).decode()
                    print(f"Client {client_id}: Previewed file {file_name}")

                time.sleep(random.uniform(0.5, 1.5))  # Simulate random delay between operations

            ssl_sock.sendall("QUIT\n".encode())
            print(f"Client {client_id}: Connection closed")

    except Exception as e:
        print(f"Client {client_id}: Error - {e}")
    finally:
        done_event.set()  # Signal that this thread is done

def stress_test_server():
    threads = []
    done_events = []
    for i in range(NUM_CLIENTS):
        event = threading.Event()
        done_events.append(event)
        thread = threading.Thread(target=simulate_client_operations, args=(i + 1, event))
        threads.append(thread)
        thread.start()

    try:
        # Wait for all threads to finish
        for event in done_events:
            event.wait()

        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        print("Stress test interrupted. Cleaning up...")
        for event in done_events:
            event.set()  # Make sure threads are signaled to stop
        for thread in threads:
            thread.join()  # Ensure all threads finish

if __name__ == "__main__":
    resource_monitor_thread = threading.Thread(target=monitor_resources, daemon=True)
    resource_monitor_thread.start()

    start_time = time.time()
    stress_test_server()
    end_time = time.time()
    print(f"Stress test completed in {end_time - start_time:.2f} seconds")

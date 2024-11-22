#!/bin/bash

# Define file paths
CERTIFICATE="server.crt"
KEY="server.key"
CREDENTIALS="id_passwd.txt"
SERVER_SCRIPT="ssl_server.py"
CLIENT_SCRIPT="gui_client.py"

# Function to check if a command succeeded
check_success() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed. Exiting."
        exit 1
    fi
}

# Step 1: Generate SSL Certificates
echo "Checking for SSL certificates..."
if [ ! -f "$CERTIFICATE" ] || [ ! -f "$KEY" ]; then
    echo "Generating SSL certificates..."
    python3 generate_certificate.py
    check_success "Certificate generation"
else
    echo "SSL certificates already exist."
fi

# Step 2: Create User Credentials
echo "Checking for user credentials..."
if [ ! -f "$CREDENTIALS" ]; then
    echo "Creating user credentials..."
    python3 create_credentials.py
    check_success "User credential creation"
else
    echo "User credentials already exist."
fi

# Step 3: Start the Server
echo "Starting the server..."
python3 $SERVER_SCRIPT &
SERVER_PID=$!
check_success "Starting the server"
echo "Server is running with PID $SERVER_PID."

# Step 4: Launch the GUI Client
echo "Launching the GUI client..."
python3 $CLIENT_SCRIPT
check_success "Launching the GUI client"

# Step 5: Clean up (Stop the server when the client exits)
echo "Stopping the server..."
kill $SERVER_PID
echo "Server stopped."

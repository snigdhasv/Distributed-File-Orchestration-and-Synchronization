# Secure File Orchestration and Synchronization System

A secure client-server application for file management with SSL/TLS encryption, user authentication, and a modern GUI interface.

## Features

- **Secure Communication**

  - SSL/TLS encryption for all data transfers
  - Self-signed certificate support
  - Encrypted file storage
  - Secure user authentication

- **User Management**

  - Multiple user support
  - Password hashing with SHA-256
  - User-specific storage directories
  - Session management

- **File Operations**

  - Upload files
  - Download files
  - Delete files
  - View file previews
  - List files
  - Real-time file list updates

- **Modern GUI Client**

  - Tkinter-based graphical interface
  - Intuitive file operations
  - Progress indicators
  - Status updates
  - File preview window

- **Robust Server**
  - Multi-threaded connection handling
  - Graceful shutdown
  - Comprehensive logging
  - Error handling
  - Connection management

## Prerequisites

```bash
# Required Python packages
pip install cryptography
pip install pyOpenSSL
pip install tkinter
```

## Project Structure

```
distributed-file-orchestration-and-synchronization/
├── config.py                 # Configuration settings
├── create_credentials.py     # User credential management
├── generate_certificate.py   # SSL certificate generation
├── gui_client.py            # GUI client application
├── ssl_server.py            # Secure server implementation
├── server_storage/          # File storage directory
├── logs/                    # Log files
└── temp/                    # Temporary files
```

## Setup Instructions

1. **Generate SSL Certificates**

```bash
python generate_certificate.py
```

2. **Create User Credentials**

```bash
python create_credentials.py
```

3. **Start the Server**

```bash
python ssl_server.py
```

4. **Launch the GUI Client**

```bash
python gui_client.py
```

OR

Run the Script file

```bash
chmod +x run.sh
./run.sh
```

## Default Credentials

- Admin User:

  - Username: `admin`
  - Password: `admin123`

- Regular User:
  - Username: `user1`
  - Password: `user123`

## Configuration

The `config.py` file contains various settings:

- Server Configuration

  - Host and Port
  - Maximum Connections
  - Buffer Sizes
  - Storage Paths

- Security Settings

  - Login Attempt Limits
  - Session Timeouts
  - Password Requirements

- Logging Configuration
  - Log Levels
  - Log Formats
  - Log File Locations

## Security Features

1. **Data Protection**

   - SSL/TLS encryption for transport
   - Fernet encryption for stored files
   - Secure password hashing

2. **Access Control**

   - User authentication
   - User-specific directories
   - Session management

3. **System Security**
   - Input validation
   - Error handling
   - Secure file operations

## Usage

1. **Login**

   - Launch the GUI client
   - Enter credentials
   - Connect to server

2. **File Operations**
   - Upload: Select file to upload
   - Download: Select file and save location
   - Delete: Select file to remove
   - View: Preview file contents
   - Refresh: Update file list

## Error Handling

The system includes comprehensive error handling for:

- Connection issues
- Authentication failures
- File operation errors
- Encryption/decryption problems
- Invalid inputs

## Logging

Detailed logging is implemented for:

- Server operations
- Client connections
- File transfers
- Security events
- Error conditions

## Development

To extend the system:

1. **Add New Features**

   - Implement new command in server
   - Add corresponding client function
   - Update GUI as needed

2. **Modify Security**

   - Edit SSL configuration
   - Update encryption methods
   - Enhance authentication

3. **Custom Configuration**
   - Modify config.py settings
   - Update server parameters
   - Adjust client behavior

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to the branch
5. Create a Pull Request

## Authors

- Snigdha SV
- Sujay SC
- Subham R Bhuyan
- Vaishnavi R

## Acknowledgments

- Python SSL/TLS implementation
- Cryptography library
- Tkinter GUI framework

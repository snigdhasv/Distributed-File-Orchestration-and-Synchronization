import json
import hashlib
import os

def create_default_credentials():
    # Default credentials
    credentials = {
        "admin": hashlib.sha256("admin123".encode()).hexdigest(),
        "user1": hashlib.sha256("user123".encode()).hexdigest(),
        "testuser": hashlib.sha256("testpassword".encode()).hexdigest()
    }
    
    # Write to file with proper JSON formatting
    with open('id_passwd.txt', 'w') as f:
        json.dump(credentials, f, indent=4)
    
    print("Credentials file created successfully!")
    print("Available logins:")
    print("Username: admin, Password: admin123")
    print("Username: user1, Password: user123")
    print("Username: testuser, Password: testpassword")

if __name__ == "__main__":
    # Remove existing file if it exists
    if os.path.exists('id_passwd.txt'):
        os.remove('id_passwd.txt')
    
    create_default_credentials() 
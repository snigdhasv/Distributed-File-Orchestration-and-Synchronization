import os

CONFIG = {
    'SERVER': {
        'HOST': '0.0.0.0',
        'PORT': 8080,
        'MAX_CONNECTIONS': 10,
        'BUFFER_SIZE': 8192,
        'STORAGE_PATH': 'server_storage',
        'SSL_CERT': 'server.crt',
        'SSL_KEY': 'server.key'
    },
    'SECURITY': {
        'MAX_LOGIN_ATTEMPTS': 3,
        'SESSION_TIMEOUT': 3600,  # 1 hour
        'MIN_PASSWORD_LENGTH': 8
    },
    'LOGGING': {
        'LEVEL': 'INFO',
        'FORMAT': '%(asctime)s - %(levelname)s - %(message)s',
        'FILE': 'server.log'
    }
}

def create_directories():
    """Create necessary directories if they don't exist"""
    directories = [
        CONFIG['SERVER']['STORAGE_PATH'],
        'logs',
        'temp'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
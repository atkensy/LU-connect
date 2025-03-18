import logging
from cryptography.fernet import Fernet

# Configure logging for encryption operations.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Use a constant key for simplicity
KEY = b'1TtRNlJvFCyK8DKj5f5pcB8-sO3OmiztA7xkQPHMV90='  
fernet = Fernet(KEY)

def encrypt_message(message: str) -> str:
    #Encrypt a string message and return the encrypted string.
    try:
        encrypted = fernet.encrypt(message.encode()).decode()
        return encrypted
    except Exception as e:
        logging.error("Encryption failed: %s", e)
        raise

def decrypt_message(token: str) -> str:
    #Decrypt an encrypted string and return the original message.
    try:
        decrypted = fernet.decrypt(token.encode()).decode()
        return decrypted
    except Exception as e:
        logging.error("Decryption failed: %s", e)
        raise

from cryptography.fernet import Fernet

# Use a constant key for simplicity.
KEY = b'1TtRNlJvFCyK8DKj5f5pcB8-sO3OmiztA7xkQPHMV90='  
fernet = Fernet(KEY)

def encrypt_message(message: str) -> str:
    #Encrypt a string message and return the encrypted string.
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(token: str) -> str:
    #Decrypt an encrypted string and return the original message.
    return fernet.decrypt(token.encode()).decode()
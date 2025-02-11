from cryptography.fernet import Fernet
import os

KEY_FILE = "key.key"

def load_or_create_key():
    """Load encryption key from file or generate a new one securely."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            return file.read()
    
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as file:
        file.write(key)
    
    return key

# Load or generate key
encryption_key = load_or_create_key()
cipher = Fernet(encryption_key)

def encrypt_password(password):
    """Encrypt a password string."""
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    """Decrypt an encrypted password string, handling errors gracefully."""
    try:
        return cipher.decrypt(encrypted_password.encode()).decode()
    except Exception:
        return "Error: Unable to decrypt (Wrong Key?)"

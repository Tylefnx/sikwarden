import secrets
import string
import base64
import os
import bcrypt # type: ignore
import hashlib # Hashleme için eklendi
from cryptography.hazmat.primitives import hashes # type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # pyright: ignore[reportMissingImports]
from cryptography.hazmat.backends import default_backend # pyright: ignore[reportMissingImports]
from cryptography.fernet import Fernet  # type: ignore

def generate_secure_password(length=16):
    lower_case = string.ascii_lowercase
    upper_case = string.ascii_uppercase
    digits = string.digits
    special_chars = string.punctuation
    all_chars = lower_case + upper_case + digits + special_chars
    password = []
    password.append(secrets.choice(lower_case))
    password.append(secrets.choice(upper_case))
    password.append(secrets.choice(digits))
    password.append(secrets.choice(special_chars))
    for i in range(length - 4):
        password.append(secrets.choice(all_chars))
    secrets.SystemRandom().shuffle(password)
    return "".join(password)

def hash_master_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_master_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def hash_search_key(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=salt,
        iterations=480000, 
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))

def encrypt_data(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode('utf-8'))
    return encrypted_data.decode('utf-8'), "FERNET_TOKEN" 

def decrypt_data(encrypted_data, key):
    try:
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data.encode('utf-8'))
        return decrypted_data.decode('utf-8')
    except Exception:
        return "Şifre Çözme Hatası"
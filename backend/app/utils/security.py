from flask_argon2 import generate_password_hash, check_password_hash
import pyotp
import hmac
import hashlib
from cryptography.fernet import Fernet
from ..utils.validation import password_entropy
from datetime import datetime, timedelta
import secrets

def hash_password(password):
    return generate_password_hash(password)

def validate_password(password):
    # Minimalne wymagania: 8 znaków, duża litera, cyfra, znak specjalny
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in "!@#$%^&*()_+" for c in password):
        return False
    return password_entropy(password)  # Wykorzystaj funkcję z validation.py


def verify_password(stored_hash, password):
    try:
        return check_password_hash(password, stored_hash)
    except:
        return False

def generate_totp():
    return pyotp.random_base32()

def encrypt_note(content, password):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_content = cipher_suite.encrypt(content.encode())
    return encrypted_content, key

def decrypt_note(encrypted_content, key, password):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_content).decode()

def generate_signature(content, secret_key):
    return hmac.new(
        secret_key.encode(),
        content.encode(),
        hashlib.sha256
    ).hexdigest()

def verify_signature(content, signature, secret_key):
    expected = generate_signature(content, secret_key)
    return hmac.compare_digest(expected, signature)

def validate_totp(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def generate_csrf_token():
    token = secrets.token_urlsafe(64)
    # Zapis tokena do bazy lub sesji
    return token

def validate_login_request(data):
    # Dodatkowe sprawdzenia np. captcha
    return True
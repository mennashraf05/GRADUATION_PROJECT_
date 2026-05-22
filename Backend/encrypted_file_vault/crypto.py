import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_salt() -> bytes:
    return os.urandom(16)


def derive_key(password: str, salt: bytes) -> bytes:
    if not password or len(password.strip()) < 8:
        raise ValueError("Password must be at least 8 characters")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )

    return base64.urlsafe_b64encode(
        kdf.derive(password.encode("utf-8"))
    )


def get_cipher_from_password(password: str, salt: bytes) -> Fernet:
    key = derive_key(password, salt)
    return Fernet(key)
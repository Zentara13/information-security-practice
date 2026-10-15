# app/crypto/encryption.py
import hashlib
import hmac

from cryptography.fernet import InvalidToken

from app.crypto.key_manager import get_blind_index_key, get_fernet

DECRYPTION_ERROR = "[ПОМИЛКА РОЗШИФРУВАННЯ]"


def encrypt_field(value: str | None) -> str | None:
    """Шифрує рядок. Кожен виклик дає інший шифротекст (випадковий IV)."""
    if not value:
        return value
    return get_fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_field(token: str | None) -> str | None:
    """Розшифровує рядок. Змінений або чужий шифротекст не пройде перевірку HMAC."""
    if not token:
        return token
    try:
        return get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        return DECRYPTION_ERROR


def blind_index(value: str) -> str:
    """Детермінований HMAC-SHA256 для пошуку й унікальності без розшифрування."""
    normalized = value.strip().lower().encode("utf-8")
    return hmac.new(get_blind_index_key(), normalized, hashlib.sha256).hexdigest()

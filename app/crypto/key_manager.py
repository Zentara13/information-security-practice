# app/crypto/key_manager.py
import os
from functools import lru_cache

from cryptography.fernet import Fernet, MultiFernet


class EncryptionKeyError(RuntimeError):
    """Ключ відсутній або має невірний формат."""


def _load_key(env_name: str) -> Fernet | None:
    raw = os.getenv(env_name)
    if not raw:
        return None
    try:
        return Fernet(raw.encode())
    except ValueError as exc:
        raise EncryptionKeyError(
            f"{env_name}: невірний формат (потрібно 32 байти в urlsafe-base64)"
        ) from exc


@lru_cache(maxsize=1)
def get_fernet() -> MultiFernet:
    """MultiFernet([поточний, (старий)]): шифрує поточним, розшифровує будь-яким."""
    current = _load_key("ENCRYPTION_KEY")
    if current is None:
        raise EncryptionKeyError(
            "ENCRYPTION_KEY не встановлено: python -m scripts.generate_key → .env"
        )
    keys = [current]
    old = _load_key("ENCRYPTION_KEY_OLD")
    if old is not None:
        keys.append(old)
    return MultiFernet(keys)


@lru_cache(maxsize=1)
def get_blind_index_key() -> bytes:
    """Окремий ключ для HMAC «сліпого індексу» (не залежить від ротації ENCRYPTION_KEY)."""
    raw = os.getenv("BLIND_INDEX_KEY", "")
    if len(raw) < 32:
        raise EncryptionKeyError("BLIND_INDEX_KEY не встановлено (openssl rand -hex 32 → .env)")
    return raw.encode()

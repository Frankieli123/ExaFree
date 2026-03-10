"""
User auth utilities for multi-user API key management.
"""
import hashlib
import re
import secrets
from typing import Optional


USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
PBKDF2_ITERATIONS = 390_000


def normalize_username(username: Optional[str]) -> str:
    return (username or "").strip().lower()


def is_valid_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username or ""))


def is_valid_password(password: str) -> bool:
    if password is None:
        return False
    return PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    ).hex()
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(password: str, encoded_hash: str) -> bool:
    if not password or not encoded_hash:
        return False
    try:
        scheme, iter_text, salt, expected = encoded_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iter_text)
    except Exception:
        return False

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()
    return secrets.compare_digest(digest, expected)


def generate_api_key() -> str:
    return f"exf_{secrets.token_urlsafe(36)}"


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256((api_key or "").encode("utf-8")).hexdigest()


def key_prefix(api_key: str) -> str:
    key = api_key or ""
    if len(key) <= 10:
        return key
    return f"{key[:8]}...{key[-4:]}"

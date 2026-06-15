from __future__ import annotations

import os
import hmac
import hashlib
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type


# ===== KDF (Argon2id) =====
# Reasonable defaults for a diploma project; can be tuned later.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 2
MASTER_KEY_LEN = 32  # 256-bit


def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)


def derive_master_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("Salt must be at least 8 bytes.")

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=MASTER_KEY_LEN,
        type=Type.ID,
    )


def derive_kek(master_key: bytes) -> bytes:
    """
    Derive Key-Encryption-Key (KEK) from master_key using HKDF.
    This KEK is used to wrap (encrypt) per-image DEKs.
    """
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != MASTER_KEY_LEN:
        raise ValueError("Invalid master key length.")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"PHOTO_VAULT_KEK_V1",
    )
    return hkdf.derive(master_key)


def compute_password_verifier(master_key: bytes) -> bytes:
    """
    A lightweight verifier stored in DB to validate password without storing it.
    """
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != MASTER_KEY_LEN:
        raise ValueError("Invalid master key length.")
    return hmac.new(master_key, b"verify", hashlib.sha256).digest()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# ===== AES-GCM helpers =====
def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> Tuple[bytes, bytes]:
    """
    Returns (nonce, ciphertext_with_tag).
    cryptography's AESGCM appends tag to ciphertext internally.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes.")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise ValueError("Plaintext must be bytes.")
    nonce = os.urandom(12)  # recommended size for GCM
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce, ct


def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes | None = None) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes.")
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext_with_tag, aad)


def generate_dek() -> bytes:
    """Per-image Data Encryption Key (DEK)"""
    return os.urandom(32)

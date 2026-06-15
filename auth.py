from __future__ import annotations

from dataclasses import dataclass
import re
import pyotp

import db
from crypto_core import (
    generate_salt,
    derive_master_key,
    derive_kek,
    compute_password_verifier,
    constant_time_equal,
    aesgcm_decrypt,
    aesgcm_encrypt,
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
)


@dataclass
class Session:
    user_id: int
    username: str
    kek: bytes


def validate_email(email: str) -> bool:
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None


def validate_nist_password(password: str, username: str = "") -> None:
    common_passwords = {
        "password",
        "password123",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty123",
        "admin123",
        "letmein123",
        "welcome123",
        "photovault",
        "photo vault",
    }

    if not password:
        raise ValueError("Password is required.")

    if len(password) < 15:
        raise ValueError("NIST requirement: password must be at least 15 characters.")

    if len(password) > 64:
        raise ValueError("NIST recommendation: password must not exceed 64 characters.")

    if password.lower() in common_passwords:
        raise ValueError("NIST requirement: this password is too common.")

    if username and username.lower() in password.lower():
        raise ValueError("NIST requirement: password must not contain the username.")


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp_code(secret: str, code: str) -> bool:
    if not secret or not code:
        return False

    code = code.strip()

    if not code.isdigit() or len(code) != 6:
        return False

    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def get_totp_secret(username: str) -> str | None:
    user = db.get_user_by_username(username)
    if not user:
        return None

    return user.get("totp_secret")


def register(
    first_name: str,
    last_name: str,
    email: str,
    username: str,
    password: str
) -> Session:
    if not first_name.strip():
        raise ValueError("First name is required.")

    if not last_name.strip():
        raise ValueError("Last name is required.")

    if not email.strip():
        raise ValueError("Email is required.")

    if not validate_email(email):
        raise ValueError("Invalid email format.")

    if not username.strip():
        raise ValueError("Username is required.")

    validate_nist_password(password, username)

    existing = db.get_user_by_username(username)
    if existing:
        raise ValueError("Username already exists.")

    salt = generate_salt()
    master_key = derive_master_key(password, salt)
    kek = derive_kek(master_key)
    verifier = compute_password_verifier(master_key)

    totp_secret = generate_totp_secret()

    kdf_algo = "argon2id"
    kdf_params = (
        f"time={ARGON2_TIME_COST},"
        f"mem_kib={ARGON2_MEMORY_COST_KIB},"
        f"par={ARGON2_PARALLELISM},"
        f"len=32"
    )

    user_id = db.create_user(
        first_name.strip(),
        last_name.strip(),
        email.strip(),
        username.strip(),
        salt,
        kdf_algo,
        kdf_params,
        verifier,
        totp_secret
    )

    return Session(
        user_id=user_id,
        username=username.strip(),
        kek=kek
    )


def login(username: str, password: str) -> Session:
    if not username or not password:
        raise ValueError("Username and password required.")

    user = db.get_user_by_username(username)
    if not user:
        raise ValueError("Invalid username or password.")

    salt = user["salt"]
    stored_verifier = user["password_verifier"]

    master_key = derive_master_key(password, salt)
    verifier = compute_password_verifier(master_key)

    if not constant_time_equal(verifier, stored_verifier):
        raise ValueError("Invalid username or password.")

    kek = derive_kek(master_key)

    return Session(
        user_id=user["id"],
        username=user["username"],
        kek=kek
    )


def verify_password(username: str, password: str) -> bool:
    try:
        login(username, password)
        return True
    except Exception:
        return False


def change_password(username: str, old_password: str, new_password: str) -> None:
    if not username or not old_password or not new_password:
        raise ValueError("Попълни всички полета.")

    if old_password == new_password:
        raise ValueError("Новата парола трябва да е различна.")

    validate_nist_password(new_password, username)

    user = db.get_user_by_username(username)
    if not user:
        raise ValueError("Невалиден потребител.")

    old_master = derive_master_key(old_password, user["salt"])
    old_verifier = compute_password_verifier(old_master)

    if not constant_time_equal(old_verifier, user["password_verifier"]):
        raise ValueError("Старата парола е грешна.")

    old_kek = derive_kek(old_master)

    new_salt = generate_salt()
    new_master = derive_master_key(new_password, new_salt)
    new_kek = derive_kek(new_master)
    new_verifier = compute_password_verifier(new_master)

    kdf_algo = "argon2id"
    kdf_params = (
        f"time={ARGON2_TIME_COST},"
        f"mem_kib={ARGON2_MEMORY_COST_KIB},"
        f"par={ARGON2_PARALLELISM},"
        f"len=32"
    )

    image_ids = db.list_user_image_ids(user["id"])

    for image_id in image_ids:
        wrapped = db.get_wrapped_dek(image_id)

        if not wrapped:
            continue

        dek = aesgcm_decrypt(
            old_kek,
            wrapped["enc_dek_nonce"],
            wrapped["enc_dek_ct"],
            aad=None
        )

        new_nonce, new_ct = aesgcm_encrypt(
            new_kek,
            dek,
            aad=None
        )

        db.update_wrapped_dek(
            image_id,
            new_nonce,
            new_ct
        )

    db.update_user_auth(
        user["id"],
        new_salt,
        new_verifier,
        kdf_algo,
        kdf_params
    )
from __future__ import annotations

import sqlite3
from typing import Optional, List, Dict, Any

DB_PATH = "vault.db"


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT,
                last_name TEXT,
                email TEXT,
                username TEXT NOT NULL UNIQUE,
                salt BLOB NOT NULL,
                kdf_algo TEXT NOT NULL,
                kdf_params TEXT NOT NULL,
                password_verifier BLOB NOT NULL,
                totp_secret TEXT
            );

            CREATE TABLE IF NOT EXISTS images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                file_path TEXT NOT NULL,
                img_nonce BLOB NOT NULL,
                img_ct BLOB NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS keys (
                image_id INTEGER PRIMARY KEY,
                enc_dek_nonce BLOB NOT NULL,
                enc_dek_ct BLOB NOT NULL,
                FOREIGN KEY(image_id) REFERENCES images(id) ON DELETE CASCADE
            );
            """
        )

        columns = [
            "first_name TEXT",
            "last_name TEXT",
            "email TEXT",
            "totp_secret TEXT"
        ]

        for column in columns:
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {column};")
            except sqlite3.OperationalError:
                pass


def create_user(
    first_name: str,
    last_name: str,
    email: str,
    username: str,
    salt: bytes,
    kdf_algo: str,
    kdf_params: str,
    verifier: bytes,
    totp_secret: str
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO users (
                first_name,
                last_name,
                email,
                username,
                salt,
                kdf_algo,
                kdf_params,
                password_verifier,
                totp_secret
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                first_name,
                last_name,
                email,
                username,
                salt,
                kdf_algo,
                kdf_params,
                verifier,
                totp_secret,
            ),
        )
        return int(cur.lastrowid)


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        cur = conn.execute(
            """
            SELECT
                id,
                first_name,
                last_name,
                email,
                username,
                salt,
                kdf_algo,
                kdf_params,
                password_verifier,
                totp_secret
            FROM users
            WHERE username=?
            """,
            (username,),
        )

        row = cur.fetchone()

        if not row:
            return None

        return {
            "id": row[0],
            "first_name": row[1],
            "last_name": row[2],
            "email": row[3],
            "username": row[4],
            "salt": row[5],
            "kdf_algo": row[6],
            "kdf_params": row[7],
            "password_verifier": row[8],
            "totp_secret": row[9],
        }


def update_user_auth(
    user_id: int,
    new_salt: bytes,
    new_verifier: bytes,
    kdf_algo: str,
    kdf_params: str
) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE users
            SET salt=?, password_verifier=?, kdf_algo=?, kdf_params=?
            WHERE id=?
            """,
            (
                new_salt,
                new_verifier,
                kdf_algo,
                kdf_params,
                user_id,
            ),
        )


def add_image(
    user_id: int,
    original_name: str,
    created_at: str,
    file_path: str,
    img_nonce: bytes,
    img_ct: bytes
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO images (
                user_id,
                original_name,
                created_at,
                file_path,
                img_nonce,
                img_ct
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                original_name,
                created_at,
                file_path,
                img_nonce,
                img_ct,
            ),
        )
        return int(cur.lastrowid)


def save_wrapped_dek(
    image_id: int,
    enc_dek_nonce: bytes,
    enc_dek_ct: bytes
) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO keys (
                image_id,
                enc_dek_nonce,
                enc_dek_ct
            )
            VALUES (?, ?, ?)
            """,
            (
                image_id,
                enc_dek_nonce,
                enc_dek_ct,
            ),
        )


def update_wrapped_dek(
    image_id: int,
    enc_dek_nonce: bytes,
    enc_dek_ct: bytes
) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE keys
            SET enc_dek_nonce=?, enc_dek_ct=?
            WHERE image_id=?
            """,
            (
                enc_dek_nonce,
                enc_dek_ct,
                image_id,
            ),
        )


def list_images(user_id: int) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        cur = conn.execute(
            """
            SELECT id, original_name, created_at, file_path
            FROM images
            WHERE user_id=?
            ORDER BY id DESC
            """,
            (user_id,),
        )

        rows = cur.fetchall()

        return [
            {
                "id": r[0],
                "original_name": r[1],
                "created_at": r[2],
                "file_path": r[3],
            }
            for r in rows
        ]


def list_user_image_ids(user_id: int) -> List[int]:
    with get_conn() as conn:
        cur = conn.execute(
            """
            SELECT id
            FROM images
            WHERE user_id=?
            ORDER BY id
            """,
            (user_id,),
        )

        return [int(r[0]) for r in cur.fetchall()]


def get_image_record(
    image_id: int,
    user_id: int
) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        cur = conn.execute(
            """
            SELECT
                id,
                user_id,
                original_name,
                created_at,
                file_path,
                img_nonce,
                img_ct
            FROM images
            WHERE id=? AND user_id=?
            """,
            (
                image_id,
                user_id,
            ),
        )

        row = cur.fetchone()

        if not row:
            return None

        return {
            "id": row[0],
            "user_id": row[1],
            "original_name": row[2],
            "created_at": row[3],
            "file_path": row[4],
            "img_nonce": row[5],
            "img_ct": row[6],
        }


def get_wrapped_dek(image_id: int) -> Optional[Dict[str, bytes]]:
    with get_conn() as conn:
        cur = conn.execute(
            """
            SELECT enc_dek_nonce, enc_dek_ct
            FROM keys
            WHERE image_id=?
            """,
            (image_id,),
        )

        row = cur.fetchone()

        if not row:
            return None

        return {
            "enc_dek_nonce": row[0],
            "enc_dek_ct": row[1],
        }


def delete_image(
    image_id: int,
    user_id: int
) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            """
            DELETE FROM images
            WHERE id=? AND user_id=?
            """,
            (
                image_id,
                user_id,
            ),
        )

        return cur.rowcount > 0


def update_image_file_path(
    image_id: int,
    file_path: str
) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE images
            SET file_path=?
            WHERE id=?
            """,
            (
                file_path,
                image_id,
            ),
        )
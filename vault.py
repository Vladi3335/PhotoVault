from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Tuple

import db
from auth import Session
from crypto_core import (
    generate_dek,
    aesgcm_encrypt,
    aesgcm_decrypt,
)

VAULT_DIR = Path("vault_storage")


def ensure_user_dir(user_id: int) -> Path:
    user_dir = VAULT_DIR / str(user_id)
    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir


def add_image(session: Session, file_path: str) -> int:
    src = Path(file_path)
    if not src.exists() or not src.is_file():
        raise FileNotFoundError("Image file not found.")

    # Read original bytes (keep original format)
    plaintext = src.read_bytes()

    # Per-image key
    dek = generate_dek()

    # Encrypt image with DEK
    img_nonce, img_ct = aesgcm_encrypt(dek, plaintext, aad=None)

    # Wrap DEK with KEK
    enc_dek_nonce, enc_dek_ct = aesgcm_encrypt(session.kek, dek, aad=None)

    created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    # Create DB record first to get image_id
    user_dir = ensure_user_dir(session.user_id)
    # Temporary path; will be finalized after image_id known
    tmp_path = user_dir / "tmp.bin"

    # Save encrypted blob file on disk (ciphertext only is ok; nonce/tag kept in DB)
    tmp_path.write_bytes(b"")  # placeholder (optional)

    image_id = db.add_image(
        user_id=session.user_id,
        original_name=src.name,
        created_at=created_at,
        file_path="",  # update after we know final filename
        img_nonce=img_nonce,
        img_ct=img_ct,
    )

    final_path = user_dir / f"{image_id}.bin"
    final_path.write_bytes(img_ct)

    # Update file_path (simple approach: store relative path)
    # SQLite update inline:
    from db import get_conn
    with get_conn() as conn:
        conn.execute("UPDATE images SET file_path=? WHERE id=?", (str(final_path), image_id))

    db.save_wrapped_dek(image_id=image_id, enc_dek_nonce=enc_dek_nonce, enc_dek_ct=enc_dek_ct)

    # Cleanup tmp
    if tmp_path.exists():
        try:
            tmp_path.unlink()
        except Exception:
            pass

    return image_id


def list_images(session: Session):
    return db.list_images(session.user_id)


def decrypt_image_to_bytes(session: Session, image_id: int) -> Tuple[bytes, str]:
    rec = db.get_image_record(image_id, session.user_id)
    if not rec:
        raise ValueError("Image not found for this user.")

    wrapped = db.get_wrapped_dek(image_id)
    if not wrapped:
        raise ValueError("Missing key record for image.")

    # Unwrap DEK
    dek = aesgcm_decrypt(session.kek, wrapped["enc_dek_nonce"], wrapped["enc_dek_ct"], aad=None)

    # Read ciphertext (we stored only img_ct in file; nonce in DB)
    img_ct = Path(rec["file_path"]).read_bytes()
    img_nonce = rec["img_nonce"]

    plaintext = aesgcm_decrypt(dek, img_nonce, img_ct, aad=None)
    return plaintext, rec["original_name"]


def export_decrypted(session: Session, image_id: int, out_dir: str) -> str:
    outp = Path(out_dir)
    outp.mkdir(parents=True, exist_ok=True)

    data, original_name = decrypt_image_to_bytes(session, image_id)
    target = outp / original_name
    target.write_bytes(data)
    return str(target)


def delete_image(session: Session, image_id: int) -> bool:
    rec = db.get_image_record(image_id, session.user_id)
    if not rec:
        return False

    # delete file on disk
    fp = rec["file_path"]
    try:
        Path(fp).unlink(missing_ok=True)
    except Exception:
        pass

    return db.delete_image(image_id, session.user_id)

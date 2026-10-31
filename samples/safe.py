import hashlib
import hmac
import os
import sqlite3


def get_user(conn: sqlite3.Connection, username: str):
    return conn.execute(
        "SELECT id, name FROM users WHERE name = ?", (username,)
    ).fetchall()


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt, digest


def verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    _, digest = hash_password(password, salt)
    return hmac.compare_digest(digest, expected)

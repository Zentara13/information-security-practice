"""Тестове відновлення: python -m scripts.restore_db data/backups/<файл>.db.enc"""
import sqlite3
import sys
from pathlib import Path

from app.crypto.key_manager import get_fernet


def restore(enc_file: str, target: str = "data/restore_test.db") -> None:
    # InvalidToken = чужий ключ або пошкоджений файл
    data = get_fernet().decrypt(Path(enc_file).read_bytes())
    Path(target).write_bytes(data)
    con = sqlite3.connect(target)
    integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
    users = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    con.close()
    print(f"integrity_check={integrity}, users={users}, файл={target}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Використання: python -m scripts.restore_db data/backups/<файл>.db.enc")
    restore(sys.argv[1])

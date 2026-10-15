"""Консистентний зашифрований бекап SQLite: python -m scripts.backup_db"""
import hashlib
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from app.crypto.key_manager import get_fernet
from app.database import DATABASE_URL

DB_PATH = Path(DATABASE_URL.replace("sqlite:///", ""))
BACKUP_DIR = DB_PATH.parent / "backups"
KEEP_LAST = 7  # скільки останніх копій зберігати


def create_backup() -> Path:
    if not DB_PATH.exists():
        raise FileNotFoundError(f"БД не знайдено: {DB_PATH}")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(suffix=".db")  # /tmp (у контейнері — tmpfs)
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        src, dst = sqlite3.connect(DB_PATH), sqlite3.connect(tmp_path)
        with dst:
            src.backup(dst)  # Online Backup API: цілісний знімок під час запису
        src.close()
        dst.close()
        plain = tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)  # відкрита копія не лишається на диску

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = BACKUP_DIR / f"app_{ts}.db.enc"
    out.write_bytes(get_fernet().encrypt(plain))
    out.chmod(0o600)
    print(f"Бекап: {out}  SHA-256: {hashlib.sha256(out.read_bytes()).hexdigest()[:16]}…")

    for old in sorted(BACKUP_DIR.glob("app_*.db.enc"))[:-KEEP_LAST]:
        old.unlink()
    return out


if __name__ == "__main__":
    create_backup()

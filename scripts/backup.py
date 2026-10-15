import hashlib
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from app.crypto.key_manager import get_fernet
from app.database import DATABASE_URL

# Знаходимо абсолютний шлях до папки проєкту / додатка
BASE_DIR = Path(__file__).resolve().parent.parent
db_path_str = DATABASE_URL.replace('sqlite:///', '')
DB_PATH = (BASE_DIR / db_path_str).resolve()
BACKUP_DIR = DB_PATH.parent / 'backups'
KEEP_LAST = 7

def create_backup() -> Path:
    if not DB_PATH.exists():
        # Спробуємо альтернативний пошук, якщо шлях відносний до робочої директорії
        alt_path = Path(db_path_str).resolve()
        if alt_path.exists():
            global DB_PATH
            DB_PATH = alt_path
        else:
            raise FileNotFoundError(f'БД не знайдено ні за яким зі шляхів: {DB_PATH} або {alt_path}')
            
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        src, dst = sqlite3.connect(DB_PATH), sqlite3.connect(tmp_path)
        with dst:
            src.backup(dst)
        src.close()
        dst.close()
        plain = tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)
    
    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    out = BACKUP_DIR / f'app_{ts}.db.enc'
    out.write_bytes(get_fernet().encrypt(plain))
    out.chmod(0o600)
    print(f'Бекап успішно створено: {out} SHA-256: {hashlib.sha256(out.read_bytes()).hexdigest()[:16]}…')
    
    for old in sorted(BACKUP_DIR.glob('app_*.db.enc'))[:-KEEP_LAST]:
        old.unlink()
    return out

if __name__ == '__main__':
    create_backup()

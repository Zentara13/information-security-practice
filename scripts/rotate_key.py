"""БОНУС: ротація ENCRYPTION_KEY для всіх записів.

Порядок:
  1. У .env: ENCRYPTION_KEY_OLD=<старий ключ>, ENCRYPTION_KEY=<новий ключ>
  2. docker compose up -d   (перезапуск, щоб підхопити змінні)
  3. docker compose exec api python -m scripts.rotate_key
  4. Після успіху видаліть ENCRYPTION_KEY_OLD з .env і перезапустіть контейнер.
"""
from sqlalchemy import text

from app.crypto.key_manager import get_fernet
from app.database import SessionLocal


def rotate() -> None:
    f = get_fernet()  # MultiFernet([новий, старий])
    db = SessionLocal()
    try:
        rows = db.execute(text(
            "SELECT id, encrypted_email, encrypted_phone FROM users")).fetchall()
        n = 0
        for uid, email, phone in rows:
            new_email = f.rotate(email.encode()).decode() if email else email
            new_phone = f.rotate(phone.encode()).decode() if phone else phone
            db.execute(text("UPDATE users SET encrypted_email=:e, encrypted_phone=:p "
                            "WHERE id=:id"), {"e": new_email, "p": new_phone, "id": uid})
            n += 1
        db.commit()
        print(f"Перешифровано новим ключем записів: {n}")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    rotate()

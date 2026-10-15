"""Шифрує відкриті email існуючих користувачів: python -m scripts.migrate_encrypt"""
from sqlalchemy import text

from app.crypto.encryption import blind_index, encrypt_field
from app.database import SessionLocal


def migrate() -> None:
    db = SessionLocal()
    try:
        rows = db.execute(text(
            "SELECT id, email FROM users "
            "WHERE encrypted_email IS NULL AND email IS NOT NULL"
        )).fetchall()
        for user_id, email in rows:
            db.execute(
                text("UPDATE users SET encrypted_email = :enc, email_index = :idx "
                     "WHERE id = :id"),
                {"enc": encrypt_field(email), "idx": blind_index(email), "id": user_id},
            )
        db.commit()
        print(f"Зашифровано записів: {len(rows)}")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    migrate()

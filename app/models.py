from datetime import datetime, timezone

from sqlalchemy import (Boolean, Column, DateTime, Float, ForeignKey, Index,
                        Integer, String, Table, Text)
from sqlalchemy.orm import relationship

from app.crypto.encryption import blind_index, decrypt_field, encrypt_field
from app.database import Base

# --- Зв'язкові таблиці M:N (RBAC) ---
user_roles = Table(
    "user_roles", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id"), primary_key=True),
)

role_permissions = Table(
    "role_permissions", Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.id"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)

    # PII зберігається лише як шифротекст Fernet; email_index — HMAC для пошуку/унікальності
    _encrypted_email = Column("encrypted_email", String(500), nullable=True)
    email_index = Column(String(64), unique=True, nullable=True, index=True)
    _encrypted_phone = Column("encrypted_phone", String(500), nullable=True)

    full_name = Column(String(150), nullable=False)
    password_hash = Column(String(255), nullable=False)  # лише bcrypt-хеш!
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=True)

    roles = relationship("Role", secondary=user_roles, back_populates="users")
    group = relationship("Group", back_populates="students")
    grades = relationship("Grade", back_populates="student",
                          foreign_keys="Grade.student_id")

    # --- Прозоре шифрування: решта коду працює з user.email як зі звичайним рядком ---
    @property
    def email(self) -> str | None:
        return decrypt_field(self._encrypted_email)

    @email.setter
    def email(self, value: str | None) -> None:
        self._encrypted_email = encrypt_field(value)
        self.email_index = blind_index(value) if value else None

    @property
    def phone(self) -> str | None:
        return decrypt_field(self._encrypted_phone)

    @phone.setter
    def phone(self, value: str | None) -> None:
        self._encrypted_phone = encrypt_field(value) if value else None

    def __repr__(self):
        return f"<User {self.username}>"


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(Text, nullable=True)

    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions,
                               back_populates="roles")


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)

    roles = relationship("Role", secondary=role_permissions,
                         back_populates="permissions")


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(20), unique=True, nullable=False)
    department = Column(String(100), nullable=False)
    year = Column(Integer, nullable=False)

    students = relationship("User", back_populates="group")


class Subject(Base):
    __tablename__ = "subjects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), nullable=False)
    credits = Column(Float, nullable=False)
    semester = Column(Integer, nullable=False)

    grades = relationship("Grade", back_populates="subject")


class Grade(Base):
    __tablename__ = "grades"

    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    subject_id = Column(Integer, ForeignKey("subjects.id"), nullable=False)
    grade = Column(Integer, nullable=False)            # 0–100
    comment = Column(String(500), nullable=True)       # коментар викладача
    date_assigned = Column(DateTime, default=datetime.utcnow)
    assigned_by = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Два FK на users → потрібно явно вказати foreign_keys
    student = relationship("User", back_populates="grades",
                           foreign_keys=[student_id])
    subject = relationship("Subject", back_populates="grades")
    teacher = relationship("User", foreign_keys=[assigned_by])


class AuditLog(Base):
    """Журнал аудиту безпеки за правилом 5W."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    # WHO
    user_id = Column(Integer, nullable=True)
    username = Column(String(50), nullable=True)
    ip_address = Column(String(45), nullable=False)
    # WHAT
    action = Column(String(50), nullable=False)
    resource = Column(String(100), nullable=True)
    # WHEN (UTC)
    timestamp = Column(DateTime, nullable=False, index=True,
                       default=lambda: datetime.now(timezone.utc))
    # WHERE
    http_method = Column(String(10), nullable=True)
    endpoint = Column(String(200), nullable=True)
    # WHY / RESULT
    status = Column(String(20), nullable=False)  # success | failure | warning | error
    status_code = Column(Integer, nullable=True)
    details = Column(Text, nullable=True)        # JSON

    __table_args__ = (
        Index("ix_audit_action_ts", "action", "timestamp"),
        Index("ix_audit_ip_action", "ip_address", "action"),
        Index("ix_audit_user_ts", "user_id", "timestamp"),
    )

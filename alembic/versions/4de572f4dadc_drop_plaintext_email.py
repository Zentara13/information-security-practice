"""drop plaintext email

Revision ID: 4de572f4dadc
Revises: fb98b51a137e
Create Date: 2026-10-15 15:13:42.637105

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4de572f4dadc'
down_revision: Union[str, None] = 'fb98b51a137e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Запускати ЛИШЕ після python -m scripts.migrate_encrypt
    with op.batch_alter_table("users") as batch:
        batch.drop_index("ix_users_email")
        batch.drop_column("email")


def downgrade() -> None:
    # Відкриті email не відновлюються — лише порожня колонка
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("email", sa.String(100), nullable=True))

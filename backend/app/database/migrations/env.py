"""Alembic environment. Migrations run programmatically from app.database.session.init_db, or via
`alembic -c alembic.ini upgrade head` (uses CLOUDSHIELD_DATABASE_URL)."""

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import get_settings
from app.database.models import Base

config = context.config
target_metadata = Base.metadata


def run_with(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata,
                      render_as_batch=connection.dialect.name == "sqlite", compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


connection = config.attributes.get("connection")
if connection is not None:
    run_with(connection)
else:
    url = config.get_main_option("sqlalchemy.url") or get_settings().database_url
    engine = engine_from_config({"sqlalchemy.url": url}, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with engine.connect() as conn:
        run_with(conn)

"""
Database factory — SQLite (local dev) or PostgreSQL (production / Docker).
"""

import os

_db_instance = None


def get_database():
    """
    Return the active database handler.

    - PostgreSQL when DATABASE_URL is postgres/postgresql or DB_ENGINE=postgres
    - SQLite otherwise (zero-config local dev)
    """
    database_url = os.getenv("DATABASE_URL", "")
    db_engine = os.getenv("DB_ENGINE", "").lower()

    if (database_url.startswith("postgres://")
            or database_url.startswith("postgresql://")
            or db_engine in ("postgres", "postgresql")):
        from pg_database import PostgresDatabase
        return PostgresDatabase(database_url or None)

    if database_url.startswith("sqlite:///"):
        from database import APIDatabase
        return APIDatabase()

    print("Using SQLite database for local development (triksha.db)")
    from database import APIDatabase
    return APIDatabase(db_path="triksha.db")


def init_database():
    """Initialize the global database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = get_database()
    return _db_instance


def get_db():
    """Singleton accessor (compatible with legacy database.get_db())."""
    global _db_instance
    if _db_instance is None:
        _db_instance = init_database()
    return _db_instance

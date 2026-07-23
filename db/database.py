"""
db/database.py
==============
Async PostgreSQL connection pool for Navigo.

Uses asyncpg directly (no ORM overhead) for maximum throughput
in the FastAPI async context.

Usage
-----
    # In inference/main.py lifespan:
    await db.connect()
    ...
    await db.disconnect()

    # In any endpoint:
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT ...")
"""

import asyncio
import logging
import os
from typing import Optional

import asyncpg
from asyncpg import Pool

logger = logging.getLogger("navigo.db")

# ---------------------------------------------------------------------------
# Configuration — pulled from environment / .env
# ---------------------------------------------------------------------------
DB_HOST     = os.getenv("DB_HOST",     "localhost")
DB_PORT     = int(os.getenv("DB_PORT", "5432"))
DB_NAME     = os.getenv("DB_NAME",     "navigo_db")
DB_USER     = os.getenv("DB_USER",     "navigo")
DB_PASSWORD = os.getenv("DB_PASSWORD", "navigo-db-password-change-me")

DB_MIN_CONNECTIONS = int(os.getenv("DB_MIN_CONNECTIONS", "2"))
DB_MAX_CONNECTIONS = int(os.getenv("DB_MAX_CONNECTIONS", "10"))

DSN = (
    f"postgresql://{DB_USER}:{DB_PASSWORD}"
    f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)


class Database:
    """Singleton wrapper around asyncpg connection pool."""

    def __init__(self) -> None:
        self._pool: Optional[Pool] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Create the connection pool. Call once at application startup."""
        if self._pool is not None:
            return  # already connected

        logger.info(
            "Connecting to PostgreSQL at %s:%s/%s", DB_HOST, DB_PORT, DB_NAME
        )
        try:
            self._pool = await asyncpg.create_pool(
                dsn=DSN,
                min_size=DB_MIN_CONNECTIONS,
                max_size=DB_MAX_CONNECTIONS,
                command_timeout=30,
                # Keep connections healthy under idle load
                max_inactive_connection_lifetime=300,
            )
            # Verify the connection and schema version
            async with self._pool.acquire() as conn:
                version = await conn.fetchval("SELECT version()")
            logger.info("PostgreSQL connected: %s", version)
        except Exception as exc:
            logger.critical("Failed to connect to PostgreSQL: %s", exc)
            raise

    async def disconnect(self) -> None:
        """Gracefully close all connections. Call at application shutdown."""
        if self._pool:
            await self._pool.close()
            self._pool = None
            logger.info("PostgreSQL pool closed.")

    # ------------------------------------------------------------------
    # Pool accessor
    # ------------------------------------------------------------------

    @property
    def pool(self) -> Pool:
        if self._pool is None:
            raise RuntimeError(
                "Database.connect() has not been called. "
                "Ensure lifespan startup completed."
            )
        return self._pool

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    async def fetchrow(self, query: str, *args) -> Optional[asyncpg.Record]:
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def fetch(self, query: str, *args) -> list[asyncpg.Record]:
        async with self.pool.acquire() as conn:
            return await conn.fetch(query, *args)

    async def execute(self, query: str, *args) -> str:
        async with self.pool.acquire() as conn:
            return await conn.execute(query, *args)

    async def fetchval(self, query: str, *args):
        async with self.pool.acquire() as conn:
            return await conn.fetchval(query, *args)

    async def transaction(self):
        """
        Async context manager for explicit transactions.

        Usage:
            async with db.transaction() as conn:
                await conn.execute(...)
                await conn.execute(...)
        """
        return _TransactionContext(self.pool)


class _TransactionContext:
    """Helper that wraps pool.acquire + conn.transaction."""

    def __init__(self, pool: Pool):
        self._pool = pool
        self._conn = None
        self._tx = None

    async def __aenter__(self):
        self._conn = await self._pool.acquire()
        self._tx = self._conn.transaction()
        await self._tx.start()
        return self._conn

    async def __aexit__(self, exc_type, exc, tb):
        if exc_type:
            await self._tx.rollback()
        else:
            await self._tx.commit()
        await self._pool.release(self._conn)


# ---------------------------------------------------------------------------
# Singleton instance — import this everywhere
# ---------------------------------------------------------------------------
db = Database()
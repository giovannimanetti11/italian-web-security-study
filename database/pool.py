"""asyncpg connection pool, shared across a crawl run."""

import asyncpg

from config import DB


async def create_pool() -> asyncpg.Pool:
    return await asyncpg.create_pool(DB.dsn, min_size=5, max_size=25)

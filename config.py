"""Environment-based configuration. Loaded once at import time from .env."""

import os
from dataclasses import dataclass
from pathlib import Path

_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


@dataclass(frozen=True)
class DatabaseConfig:
    host: str = os.getenv("IWSS_DB_HOST", "127.0.0.1")
    port: int = int(os.getenv("IWSS_DB_PORT", "5432"))
    name: str = os.getenv("IWSS_DB_NAME", "iwss")
    user: str = os.getenv("IWSS_DB_USER", "iwss_user")
    password: str = os.getenv("IWSS_DB_PASSWORD", "")

    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


@dataclass(frozen=True)
class CrawlerConfig:
    user_agent: str = os.getenv(
        "IWSS_USER_AGENT",
        "iwss-research-crawler/0.1 (+https://f-hack.com/iwss)",
    )
    request_timeout: float = float(os.getenv("IWSS_REQUEST_TIMEOUT", "12"))
    concurrency: int = int(os.getenv("IWSS_CONCURRENCY", "100"))
    per_host_min_interval: float = float(os.getenv("IWSS_PER_HOST_MIN_INTERVAL", "1.0"))
    crawler_version: str = os.getenv("IWSS_CRAWLER_VERSION", "0.2.0")


DB = DatabaseConfig()
CRAWLER = CrawlerConfig()

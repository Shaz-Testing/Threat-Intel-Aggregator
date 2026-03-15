from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    ANTHROPIC_API_KEY: str = ""
    NVD_API_KEY: str = ""
    OTX_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    SLACK_WEBHOOK_URL: str = ""
    ALERT_EMAIL: str = ""

    SCRAPE_INTERVAL_MINUTES: int = 30
    MAX_THREATS_PER_RUN: int = 50
    CRITICAL_SEVERITY_THRESHOLD: float = 9.0

    DATABASE_URL: str = "sqlite+aiosqlite:///./threats.db"
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]
    DEBUG: bool = True

    class Config:
        env_file = ".env"


settings = Settings()

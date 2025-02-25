"""
Settings for the demo project
"""

from functools import lru_cache
from typing import Literal

from pydantic import HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ZITADEL_HOST: HttpUrl
    ZITADEL_PROJECT_ID: str
    OAUTH_CLIENT_ID: str
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "DEBUG"

    model_config = SettingsConfigDict(env_file="demo_project/.env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    """Singleton function to load settings."""
    return Settings()

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ZITADEL_DOMAIN: str
    ZITADEL_PROJECT_ID: str
    OAUTH_CLIENT_ID: str

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    """Singleton function to load settings."""
    return Settings()

import logging
from typing import Any
import httpx
from cachetools import TTLCache
import jwt

log = logging.getLogger("fastapi_zitadel_auth")


class KeyManager:
    """Manages JWKS keys with caching"""

    def __init__(
        self, jwks_url: str, algorithm: str, cache_ttl: int = 300, cache_size: int = 5
    ):
        self.jwks_url = jwks_url
        self.cache = TTLCache(maxsize=cache_size, ttl=cache_ttl)
        self.algorithm = algorithm

    async def get_public_key(self, kid: str) -> Any | None:
        """Get public key for kid, fetching JWKS if needed"""
        if "jwks" not in self.cache:
            self.cache["jwks"] = await self._fetch_jwks()

        for key in self.cache["jwks"]["keys"]:
            if key.get("use") == "sig" and key.get("kid") == kid:
                return jwt.PyJWK(key, algorithm=self.algorithm).key
        return None

    async def _fetch_jwks(self) -> dict[str, Any]:
        """Fetch JWKS from URL"""
        log.info(f"Getting JWKS from {self.jwks_url}")
        async with httpx.AsyncClient() as client:
            response = await client.get(self.jwks_url, timeout=10)
            response.raise_for_status()
            return response.json()

from asyncio import Lock
from datetime import datetime, timedelta
import logging
from typing import Any
import httpx
from jwt import PyJWK
from pydantic import BaseModel, ConfigDict, PositiveInt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from fastapi_zitadel_auth.exceptions import UnauthorizedException

log = logging.getLogger("fastapi_zitadel_auth")


class OpenIdConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, strict=True, extra="forbid")

    issuer_url: str
    config_url: str
    authorization_url: str
    token_url: str
    jwks_uri: str
    signing_keys: dict[str, RSAPublicKey] = {}

    refresh_lock: Lock = Lock()
    last_refresh_timestamp: datetime | None = None
    cache_ttl_seconds: PositiveInt = 600

    async def load_config(self) -> None:
        """Refresh the openid configuration and signing keys if necessary."""
        async with self.refresh_lock:
            if not self._needs_refresh():
                return
            log.debug("Loading OpenID configuration.")
            current_time = datetime.now()
            try:
                async with httpx.AsyncClient(timeout=10, http2=True) as client:
                    config = await self._fetch_config(client)
                    new_keys = await self._fetch_jwks(client)

                self.issuer_url = config["issuer"]
                self.authorization_url = config["authorization_endpoint"]
                self.token_url = config["token_endpoint"]
                self.jwks_uri = config["jwks_uri"]
                self.signing_keys = self._parse_jwks(new_keys)
                self.last_refresh_timestamp = current_time

            except Exception as e:
                log.exception(f"Unable to refresh configuration from identity provider: {e}")
                self.reset_cache()
                raise UnauthorizedException("Unable to refresh configuration from identity provider")

        log.info("fastapi-zitadel-auth loaded OpenID configuration and signing keys from Zitadel.")
        log.info("Issuer:               %s", self.issuer_url)
        log.info("Authorization url:    %s", self.authorization_url)
        log.info("Token url:            %s", self.token_url)
        log.debug("Keys url:            %s", self.jwks_uri)
        log.debug("Last refresh:        %s", self.last_refresh_timestamp)
        log.debug("Signing keys:        %s", len(self.signing_keys))
        log.debug("Cache TTL:           %s s", self.cache_ttl_seconds)

    async def get_key(self, kid: str) -> RSAPublicKey:
        """Get a signing key by its ID, refreshing JWKS once if necessary."""
        if kid not in self.signing_keys:
            log.debug("Key '%s' not found, refreshing JWKS", kid)
            await self.load_config()

        signing_key = self.signing_keys.get(kid)
        if signing_key is None:
            log.error(f"Unable to verify token, no signing keys found for key with ID: '{kid}'")
            raise UnauthorizedException("Unable to verify token, no signing keys found")
        return signing_key

    def reset_cache(self) -> None:
        """Reset the cache by clearing the timestamp and keys."""
        self.last_refresh_timestamp = None
        self.signing_keys = {}
        log.debug("Reset OpenID configuration cache")

    def _needs_refresh(self) -> bool:
        """Check if the cached keys should be refreshed based on cache state or time elapsed."""
        if not self.last_refresh_timestamp or not self.signing_keys:
            return True

        elapsed = datetime.now() - self.last_refresh_timestamp
        return elapsed > timedelta(seconds=self.cache_ttl_seconds)

    async def _fetch_config(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """Fetch OpenID Connect configuration."""
        log.info("Fetching OpenID configuration from %s", self.config_url)
        response = await client.get(self.config_url)
        response.raise_for_status()
        return response.json()

    async def _fetch_jwks(self, client: httpx.AsyncClient) -> dict[str, list]:
        """Fetch JWK Set from the jwks_uri."""
        log.info("Fetching JWKS from %s", self.jwks_uri)
        response = await client.get(self.jwks_uri)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _parse_jwks(jwks: dict[str, list]) -> dict[str, RSAPublicKey]:
        """Parse the JWKS response and return a dictionary of RSA public keys."""
        keys = {}
        available_keys = jwks.get("keys", [])
        for key in available_keys:
            if key.get("use") == "sig" and key.get("alg") == "RS256" and key.get("kty") == "RSA" and "kid" in key:
                log.debug("Loading public key %s", key)
                keys[key["kid"]] = PyJWK.from_dict(obj=key, algorithm="RS256").key
        return keys

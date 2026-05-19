"""
OpenID Connect discovery and JWKS caching for Zitadel authentication.

Two refresh paths share the same lock and signing-key cache:

* ``load_config`` — periodic full refresh gated by ``cache_ttl_seconds``. The
  JWKS endpoint is authoritative for currently-valid keys, so cached keys are
  *replaced*; upstream-removed keys (e.g. after revocation) are evicted.

* ``get_key`` — on-demand refresh triggered by an unknown ``kid`` from the
  unverified token header. A 10 s cooldown bounds the per-window cost of
  attacker-driven random-kid bursts to one sleep + one upstream GET. New keys
  are *merged* so a sparse upstream response cannot wipe legitimate cached
  keys held by in-flight requests.

The 1 s pre-refresh sleep covers Zitadel's keypair propagation lag: signing
keys are generated ad-hoc on token issuance, so JWKS may briefly lag behind
a freshly-issued ``kid``.
"""

from asyncio import Lock, sleep
from datetime import datetime, timedelta
import logging
from typing import Any
import httpx
from jwt import PyJWK
from pydantic import BaseModel, ConfigDict, Field, PositiveInt
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

    refresh_lock: Lock = Field(default_factory=Lock)
    last_refresh_timestamp: datetime | None = None
    last_refresh_attempt: datetime | None = None
    cache_ttl_seconds: PositiveInt = 600

    async def load_config(self) -> None:
        """Refresh OIDC discovery and JWKS if the cache is empty or the TTL has elapsed."""
        async with self.refresh_lock:
            if not self._needs_refresh():
                return
            log.debug("Loading OpenID configuration.")
            current_time = datetime.now()
            try:
                async with httpx.AsyncClient(timeout=10, http2=True) as client:
                    config = await self._fetch_config(client)
                    signing_keys = await self._fetch_signing_keys(client)

                self.issuer_url = config["issuer"]
                self.authorization_url = config["authorization_endpoint"]
                self.token_url = config["token_endpoint"]
                self.jwks_uri = config["jwks_uri"]
                self.signing_keys = signing_keys
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
        """Return the signing key for ``kid``, refreshing JWKS once per cooldown if missing.
        The sleep is inside the try/finally so the cooldown still engages if the request
        is canceled mid-sleep.
        """
        if kid in self.signing_keys:
            return self.signing_keys[kid]

        async with self.refresh_lock:
            if kid in self.signing_keys:
                return self.signing_keys[kid]

            if self._is_throttled():
                log.warning("JWKS refresh throttled; unknown kid '%s'", kid)
                raise UnauthorizedException("Unable to verify token, no signing keys found")

            log.debug("Key '%s' not found, waiting for Zitadel and merging JWKS", kid)
            try:
                await self._sleep()
                await self._refresh_jwks_merge()
            finally:
                self.last_refresh_attempt = datetime.now()

        if kid not in self.signing_keys:
            log.error("Unable to verify token, no signing keys found for key with ID: '%s'", kid)
            raise UnauthorizedException("Unable to verify token, no signing keys found")
        return self.signing_keys[kid]

    def _is_throttled(self) -> bool:
        """True if a refresh was attempted within the 10 s cooldown."""
        if self.last_refresh_attempt is None:
            return False
        elapsed = datetime.now() - self.last_refresh_attempt
        return elapsed < timedelta(seconds=10)

    async def _refresh_jwks_merge(self) -> None:
        """Fetch JWKS and merge new entries into ``signing_keys``."""
        try:
            async with httpx.AsyncClient(timeout=10, http2=True) as client:
                new_keys = await self._fetch_signing_keys(client)
            self.signing_keys = {**self.signing_keys, **new_keys}
        except Exception as e:
            log.exception(f"Unable to refresh JWKS from identity provider: {e}")
            raise UnauthorizedException("Unable to refresh JWKS from identity provider")

    def reset_cache(self) -> None:
        """Drop cached signing keys and the last-refresh timestamp."""
        self.last_refresh_timestamp = None
        self.signing_keys = {}
        log.debug("Reset OpenID configuration cache")

    @staticmethod
    async def _sleep() -> None:
        """Sleep briefly to absorb Zitadel's ad-hoc keypair propagation lag."""
        log.debug("Waiting for other tasks to finish...")
        await sleep(1)

    def _needs_refresh(self) -> bool:
        """True when there are no cached keys or the TTL has elapsed."""
        if not self.last_refresh_timestamp or not self.signing_keys:
            return True

        elapsed = datetime.now() - self.last_refresh_timestamp
        return elapsed > timedelta(seconds=self.cache_ttl_seconds)

    async def _fetch_config(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """GET the OIDC discovery document."""
        log.info("Fetching OpenID configuration from %s", self.config_url)
        response = await client.get(self.config_url)
        response.raise_for_status()
        return response.json()

    async def _fetch_signing_keys(self, client: httpx.AsyncClient) -> dict[str, RSAPublicKey]:
        """GET the JWKS and parse it into a ``kid → RSAPublicKey`` dict."""
        log.info("Fetching JWKS from %s", self.jwks_uri)
        response = await client.get(self.jwks_uri)
        response.raise_for_status()
        return self._parse_jwks(response.json())

    @staticmethod
    def _parse_jwks(jwks: dict[str, list]) -> dict[str, RSAPublicKey]:
        """Filter to RS256 signing keys and return as ``kid → RSAPublicKey``."""
        keys = {}
        available_keys = jwks.get("keys", [])
        for key in available_keys:
            if key.get("use") == "sig" and key.get("alg") == "RS256" and key.get("kty") == "RSA" and "kid" in key:
                log.debug("Loading public key %s", key)
                keys[key["kid"]] = PyJWK.from_dict(obj=key, algorithm="RS256").key
        return keys

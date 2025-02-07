import logging
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt import PyJWK
from httpx import AsyncClient
from pydantic import BaseModel, ConfigDict

from fastapi_zitadel_auth.exceptions import InvalidAuthException

log = logging.getLogger("fastapi_zitadel_auth")


class OpenIdConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, strict=True, extra="forbid")

    issuer_url: str
    config_url: str
    authorization_url: str
    token_url: str
    jwks_uri: str
    signing_keys: dict[str, RSAPublicKey] = {}
    last_refresh_timestamp: datetime | None = None
    cache_duration_minutes: int = 60

    async def load_config(self) -> None:
        """
        Refresh the OpenID Connect configuration if needed
        """
        if self._needs_refresh():
            try:
                log.info("Refreshing OpenID config and signing keys")
                await self._refresh()
                self.last_refresh_timestamp = datetime.now()
            except Exception as error:
                log.error("Error fetching OpenID config: %s", error)
                raise InvalidAuthException(
                    "Connection to Zitadel is down. Unable to fetch provider configuration"
                ) from error

            log.info("Loaded OpenID configuration from Zitadel.")
            log.info("Issuer:               %s", self.issuer_url)
            log.info("Authorization url:    %s", self.authorization_url)
            log.info("Token url:            %s", self.token_url)
            log.debug("Keys url:            %s", self.jwks_uri)
            log.debug("Last refresh:        %s", self.last_refresh_timestamp)
            log.debug("Signing keys:        %s", len(self.signing_keys))

    def get_signing_key(self, kid: str) -> RSAPublicKey | None:
        """Get the JWK signing key for the given key ID"""
        return self.signing_keys.get(kid)

    def _needs_refresh(self) -> bool:
        """Check if config needs refresh"""
        if not self.last_refresh_timestamp or not self.signing_keys:
            return True
        refresh_time = datetime.now() - timedelta(minutes=self.cache_duration_minutes)
        return self.last_refresh_timestamp < refresh_time

    async def _refresh(self) -> None:
        """Fetch both OpenID config and signing keys"""
        async with AsyncClient(timeout=10) as client:
            # Fetch OpenID config
            log.debug("Fetching OpenID config from %s", self.config_url)
            openid_response = await client.get(self.config_url)
            openid_response.raise_for_status()
            config = openid_response.json()

            # Update config values
            self.issuer_url = config["issuer"]
            self.authorization_url = config["authorization_endpoint"]
            self.token_url = config["token_endpoint"]
            self.jwks_uri = config["jwks_uri"]

            # Fetch and load signing keys
            log.debug("Fetching JWKS keys from %s", self.jwks_uri)
            jwks_response = await client.get(self.jwks_uri)
            jwks_response.raise_for_status()
            self._load_keys(jwks_response.json().get("keys", []))

    def _load_keys(self, keys: list[dict[str, str]]) -> None:
        """Load signing keys from JWKS response"""
        self.signing_keys = {
            key["kid"]: PyJWK(key, "RS256").key
            for key in keys
            if key.get("use") == "sig"
            and key.get("alg") == "RS256"
            and key.get("kty") == "RSA"
            and "kid" in key
        }

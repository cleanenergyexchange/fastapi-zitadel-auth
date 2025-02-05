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

    issuer: str
    config_url: str
    authorization_url: str
    token_url: str
    jwks_uri: str
    signing_keys: dict[str, RSAPublicKey] = {}
    last_refresh: datetime | None = None

    async def load_config(self) -> None:
        """
        Refresh the OpenID Connect configuration if it's older than 1 hour
        """
        refresh_time = datetime.now() - timedelta(hours=1)
        if not self.last_refresh or self.last_refresh < refresh_time:
            try:
                await self._refresh()
            except Exception as error:
                if self.last_refresh:
                    log.error(f"Error refreshing OpenID Connect config: {error}")
                    raise InvalidAuthException(
                        "Connection to Zitadel is down. Unable to fetch provider config"
                    ) from error
                else:
                    raise RuntimeError(
                        f"Unable to fetch OpenID Connect config. {error}"
                    ) from error

            log.info("Loaded OpenID Connect configuration from Zitadel")
            log.info("Issuer: %s", self.issuer)
            log.info("Authorization endpoint: %s", self.authorization_url)
            log.info("Token endpoint: %s", self.token_url)
            log.info("JWKS URI: %s", self.jwks_uri)

        else:
            log.debug(
                "Using cached OpenID Connect configuration. Last refresh: %s",
                self.last_refresh,
            )

    async def _refresh(self) -> None:
        """
        Fetch the OpenID Connect configuration from the issuer
        """
        async with AsyncClient(timeout=10) as client:
            log.debug("Fetching OpenID Connect config from %s", self.config_url)
            openid_response = await client.get(self.config_url)
            openid_response.raise_for_status()
            response = openid_response.json()
            self.issuer = response["issuer"]
            self.authorization_url = response["authorization_endpoint"]
            self.token_url = response["token_endpoint"]
            self.jwks_uri = response["jwks_uri"]

            log.debug("Fetching JWKS keys from %s", self.jwks_uri)
            jwks_response = await client.get(self.jwks_uri)
            jwks_response.raise_for_status()
            all_keys = jwks_response.json().get("keys")
            log.debug("Fetched %d keys", len(all_keys))
            self._load_keys(all_keys)

            self.last_refresh = datetime.now()

    def _load_keys(self, keys: list[dict[str, str]]) -> None:
        """
        Load the public keys from the JWKS endpoint
        """
        self.signing_keys = {
            key["kid"]: PyJWK(key, "RS256").key
            for key in keys
            if key.get("use") == "sig"
            and key.get("alg") == "RS256"
            and key.get("kty") == "RSA"
            and "kid" in key
        }

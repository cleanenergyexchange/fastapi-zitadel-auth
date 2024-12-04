import logging
from typing import Any, TYPE_CHECKING

import jwt
import httpx

from cachetools import TTLCache
from fastapi import HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer, SecurityScopes
from fastapi.security.base import SecurityBase
from jwt import (
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidIssuedAtError,
    ImmatureSignatureError,
    MissingRequiredClaimError,
    InvalidTokenError,
    ExpiredSignatureError,
)
from pydantic import BaseModel
from starlette.requests import Request

from .exceptions import InvalidAuthException

if TYPE_CHECKING:  # pragma: no cover
    from jwt.algorithms import AllowedPublicKeys  # noqa: F401

log = logging.getLogger("fastapi_zitadel_auth")
logging.basicConfig(level=logging.DEBUG)


# Cache for JWKS, with a TTL of 5 minutes and max 5 keys
jwks_cache = TTLCache(maxsize=5, ttl=300)

# Algorithm used for signing the token
ALGORITHM = "RS256"


def _get_public_key(kid: str, jwks_data: dict[str, Any]) -> Any | None:
    """
    Get the public key from the JWKS matching the `kid` from the token.
    """
    for key in jwks_data["keys"]:
        # Check if the key is a signature key and the key id matches
        if key.get("use") == "sig" and key.get("kid") == kid:
            log.debug(f"Loading public key from certificate: {key}")
            cert_obj = jwt.PyJWK(key, ALGORITHM)
            return cert_obj.key
    return None


def _get_unverified_header(access_token: str) -> dict[str, Any]:
    """
    Get header from the access token without verifying the signature
    """
    return dict(jwt.get_unverified_header(access_token))


def _get_unverified_claims(access_token: str) -> dict[str, Any]:
    """
    Get claims from the access token without verifying the signature
    """
    return dict(jwt.decode(access_token, options={"verify_signature": False}))


class OAuth2User(BaseModel):
    claims: dict[str, Any]
    access_token: str


class ZitadelAuthorizationCodeBearer(SecurityBase):
    """
    OAuth2AuthorizationCodeBearer class for Zitadel.
    """

    def __init__(
        self,
        app_client_id: str,
        project_id: str,
        base_url: str,
        scopes: dict[str, str] | None = None,
    ) -> None:
        self.app_client_id = app_client_id
        self.project_id = project_id
        self.base_url = base_url
        self.scopes = scopes
        self.openapi_authorization_url = f"{self.base_url}/oauth/v2/authorize"
        self.openapi_token_url = f"{self.base_url}/oauth/v2/token"
        self.openapi_description = "Zitadel OAuth2 authentication using bearer token"

        self.oauth = OAuth2AuthorizationCodeBearer(
            authorizationUrl=self.openapi_authorization_url,
            tokenUrl=self.openapi_token_url,
            scopes=self.scopes,
            scheme_name="ZitadelAuthorizationCodeBearer",
            description=self.openapi_description,
        )
        self.model = self.oauth.model
        self.scheme_name = self.oauth.scheme_name

    async def __call__(
        self, request: Request, security_scopes: SecurityScopes
    ) -> OAuth2User | None:
        """
        Extends call to also validate the token.
        """
        try:
            access_token = await self.extract_access_token(request)
            if access_token is None:
                raise InvalidAuthException("No access token provided")
            try:
                # Extract header and claims information of the token.
                header: dict[str, Any] = _get_unverified_header(access_token)
                claims: dict[str, Any] = _get_unverified_claims(access_token)
            except Exception as error:
                log.warning(
                    f"Malformed token received. {access_token}. Error: {error}",
                    exc_info=True,
                )
                raise InvalidAuthException("Invalid token format") from error

            log.debug(f"Header: {header}")
            log.debug(f"Claims: {claims}")
            log.debug(f"Required scopes: {security_scopes.scopes}")

            permission_claim = f"urn:zitadel:iam:org:project:{self.project_id}:roles"

            if permission_claim not in claims or not isinstance(
                claims[permission_claim], dict
            ):
                log.warning(
                    f"Missing or invalid roles in token claims: {permission_claim}"
                )
                raise InvalidAuthException("Invalid token structure")

            project_roles = claims[permission_claim]
            for required_scope in security_scopes.scopes:
                if required_scope not in project_roles:
                    log.warning(f"Token does not have required scope: {required_scope}")
                    raise InvalidAuthException("Not enough permissions")

            if "jwks" not in jwks_cache:
                jwks_cache["jwks"] = await self.load_jwks()

            try:
                # Use the `kid` from the header and try to find a matching signing key
                kid = header.get("kid", "")
                key = _get_public_key(kid, jwks_cache["jwks"])
                if key:
                    required_claims = ["exp", "aud", "iat", "sub"]
                    # Options for token validation
                    options = {
                        "verify_signature": True,
                        "verify_aud": True,
                        "verify_iat": True,
                        "verify_exp": True,
                        "verify_nbf": True,
                        "require": required_claims,
                        "leeway": 0,
                    }

                    # Validate token
                    token = self.validate(
                        access_token=access_token,
                        iss=self.base_url,
                        key=key,
                        options=options,
                    )

                    # Attach the user to the request. Can be accessed through `request.state.user`
                    user: OAuth2User = OAuth2User(
                        **{**token, "claims": token, "access_token": access_token}
                    )
                    request.state.user = user
                    return user

            except (
                InvalidAudienceError,
                InvalidIssuerError,
                InvalidIssuedAtError,
                ImmatureSignatureError,
                MissingRequiredClaimError,
            ) as error:
                log.info(f"Token contains invalid claims: {error}")
                raise InvalidAuthException("Token contains invalid claims") from error

            except ExpiredSignatureError as error:
                log.info(f"Token signature has expired. {error}")
                raise InvalidAuthException("Token signature has expired") from error

            except InvalidTokenError as error:
                log.warning(f"Invalid token. Error: {error}", exc_info=True)
                raise InvalidAuthException("Unable to validate token") from error

            except Exception as error:
                # Extra failsafe in case of a bug in a future version of the jwt library
                log.exception(f"Unable to process jwt token. Uncaught error: {error}")
                raise InvalidAuthException("Unable to process token") from error

            log.warning("Unable to verify token. No signing keys found")
            raise InvalidAuthException("Unable to verify token, no signing keys found")

        except (InvalidAuthException, HTTPException):
            raise

    async def extract_access_token(self, request: Request) -> str | None:
        """
        Extracts the access token from the request.
        """
        return await self.oauth(request=request)

    async def load_jwks(self) -> dict[str, Any]:
        """
        Load the JWKS from the Zitadel server.
        """
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/oauth/v2/keys"
            log.info(f"Fetching JWKS from {url}")
            response = await client.get(url, timeout=10)
            response.raise_for_status()
            log.debug(f"JWKS response: {response.json()}")
            return dict(response.json())

    def validate(
        self,
        access_token: str,
        key: "AllowedPublicKeys",
        iss: str,
        options: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Validates the token using the provided key and options.
        """
        # audiences to allow service users also to use the token,
        # otherwise we'd get "Token contains invalid claims: Audience doesn't match"
        aud = [self.app_client_id, self.project_id]
        return dict(
            jwt.decode(
                access_token,
                key=key,
                algorithms=[ALGORITHM],
                audience=aud,
                issuer=iss,
                leeway=0,
                options=options,
            )
        )

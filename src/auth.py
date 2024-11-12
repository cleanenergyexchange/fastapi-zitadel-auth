from typing import TYPE_CHECKING, Any
import httpx
import jwt
from cachetools import TTLCache
from fastapi import Request, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer, SecurityScopes
from fastapi.security.base import SecurityBase
from jwt.exceptions import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidTokenError,
    MissingRequiredClaimError,
)
from loguru import logger
from pydantic import BaseModel

from settings import get_settings

if TYPE_CHECKING:  # pragma: no cover
    from jwt.algorithms import AllowedPublicKeys  # noqa: F401

"""
Module for OAuth2 token validation using Zitadel.
"""

settings = get_settings()

# Cache for JWKS, with a TTL of 5 minutes and max 5 keys
jwks_cache = TTLCache(maxsize=5, ttl=300)

# Algorithm used for signing the token
ALGORITHM = "RS256"


async def load_jwks() -> dict[str, Any]:
    """
    Load the JWKS from the Zitadel server.
    """
    async with httpx.AsyncClient() as client:
        url = f"{settings.ZITADEL_DOMAIN}/oauth/v2/keys"
        logger.info(f"Fetching JWKS from {url}")
        response = await client.get(url, timeout=10)
        response.raise_for_status()
        logger.debug(f"JWKS response: {response.json()}")
        return dict(response.json())


def get_public_key(kid: str, jwks_data: dict[str, Any]) -> Any | None:
    """
    Get the public key from the JWKS matching the `kid` from the token.
    """
    for key in jwks_data["keys"]:
        # Check if the key is a signature key and the key id matches
        if key.get("use") == "sig" and key.get("kid") == kid:
            logger.debug(f"Loading public key from certificate: {key}")
            cert_obj = jwt.PyJWK(key, ALGORITHM)
            return cert_obj.key
    return None


def get_unverified_header(access_token: str) -> dict[str, Any]:
    """
    Get header from the access token without verifying the signature
    """
    return dict(jwt.get_unverified_header(access_token))


def get_unverified_claims(access_token: str) -> dict[str, Any]:
    """
    Get claims from the access token without verifying the signature
    """
    return dict(jwt.decode(access_token, options={"verify_signature": False}))


class InvalidAuth(HTTPException):
    def __init__(self, detail: str) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"www-authenticate": "bearer"},
        )


class OAuth2User(BaseModel):
    claims: dict[str, Any]
    access_token: str


class ZitadelAuthorizationCodeBearer(SecurityBase):
    """
    OAuth2AuthorizationCodeBearer class for Zitadel.

    :param app_client_id: str
            Your application client ID, this is the one you've configured in Zitadel.
    :param scopes: dict[str, str] | None
        Scopes, these are the ones you've configured in Zitadel. Key is scope, value is a description.
        Example:
            {
                f'urn:some:zitadel:scope': 'the description of the scope'
            }
    :param leeway: int
        By adding leeway, you define a tolerance window in terms of seconds, allowing the token to be
        considered valid even if it falls within the leeway time before or after the "exp" or "nbf" times.
    :param openapi_authorization_url: str
        Override OpenAPI authorization URL
    :param openapi_token_url: str
        Override OpenAPI token URL
    :param openapi_description: str
        Override OpenAPI description
    """

    def __init__(
        self,
        app_client_id: str,
        scopes: dict[str, str] | None = None,
        leeway: int = 0,
        openapi_authorization_url: str | None = None,
        openapi_token_url: str | None = None,
        openapi_description: str | None = None,
    ) -> None:
        self.app_client_id = app_client_id
        self.scopes = scopes
        self.leeway = leeway
        self.openapi_authorization_url = (
            openapi_authorization_url or f"{settings.ZITADEL_DOMAIN}/oauth/v2/authorize"
        )
        self.openapi_token_url = (
            openapi_token_url or f"{settings.ZITADEL_DOMAIN}/oauth/v2/token"
        )
        self.openapi_description = openapi_description

        self.oauth = OAuth2AuthorizationCodeBearer(
            authorizationUrl=self.openapi_authorization_url,
            tokenUrl=self.openapi_token_url,
            scopes=self.scopes,
            scheme_name="ZitadelAuthorizationCodeBearer",
            description=openapi_description or "`Leave client_secret blank`",
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
            try:
                if access_token is None:
                    raise InvalidAuth("No access token provided")
                # Extract header and claims information of the token.
                header: dict[str, Any] = get_unverified_header(access_token)
                claims: dict[str, Any] = get_unverified_claims(access_token)
            except Exception as error:
                logger.warning(
                    f"Malformed token received. {access_token}. Error: {error}",
                    exc_info=True,
                )
                raise InvalidAuth("Invalid token format") from error

            logger.debug(f"Header: {header}")
            logger.debug(f"Claims: {claims}")
            logger.debug(f"Required scopes: {security_scopes.scopes}")

            permission_claim = (
                f"urn:zitadel:iam:org:project:{settings.ZITADEL_PROJECT_ID}:roles"
            )

            if permission_claim not in claims or not isinstance(
                claims[permission_claim], dict
            ):
                logger.warning(
                    f"Missing or invalid roles in token claims: {permission_claim}"
                )
                raise InvalidAuth("Invalid token structure")

            project_roles = claims[permission_claim]
            for required_scope in security_scopes.scopes:
                if required_scope not in project_roles:
                    logger.warning(
                        f"Token does not have required scope: {required_scope}"
                    )
                    raise InvalidAuth("Not enough permissions")

            if "jwks" not in jwks_cache:
                jwks_cache["jwks"] = await load_jwks()

            try:
                # Use the `kid` from the header and try to find a matching signing key
                kid = header.get("kid", "")
                key = get_public_key(kid, jwks_cache["jwks"])
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
                        "leeway": self.leeway,
                    }

                    # Validate token
                    token = self.validate(
                        access_token=access_token,
                        iss=settings.ZITADEL_DOMAIN,
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
                logger.info(f"Token contains invalid claims: {error}")
                raise InvalidAuth("Token contains invalid claims") from error

            except ExpiredSignatureError as error:
                logger.info(f"Token signature has expired. {error}")
                raise InvalidAuth("Token signature has expired") from error

            except InvalidTokenError as error:
                logger.warning(f"Invalid token. Error: {error}", exc_info=True)
                raise InvalidAuth("Unable to validate token") from error

            except Exception as error:
                # Extra failsafe in case of a bug in a future version of the jwt library
                logger.exception(
                    f"Unable to process jwt token. Uncaught error: {error}"
                )
                raise InvalidAuth("Unable to process token") from error

            logger.warning("Unable to verify token. No signing keys found")
            raise InvalidAuth("Unable to verify token, no signing keys found")

        except (InvalidAuth, HTTPException):
            raise

    async def extract_access_token(self, request: Request) -> str | None:
        """
        Extracts the access token from the request.
        """
        return await self.oauth(request=request)

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
        aud = [self.app_client_id, settings.ZITADEL_PROJECT_ID]
        return dict(
            jwt.decode(
                access_token,
                key=key,
                algorithms=[ALGORITHM],
                audience=aud,
                issuer=iss,
                leeway=self.leeway,
                options=options,
            )
        )

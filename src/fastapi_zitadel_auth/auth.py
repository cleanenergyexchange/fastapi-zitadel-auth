"""
Authentication module for Zitadel OAuth2
"""

import logging
from typing import TYPE_CHECKING

from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer, SecurityScopes
from fastapi.security.base import SecurityBase
from jwt import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidTokenError,
    MissingRequiredClaimError,
)
from pydantic import HttpUrl
from starlette.requests import Request

from .exceptions import InvalidAuthException
from .models import AuthenticatedUser, ZitadelClaims
from .openid_config import OpenIdConfig
from .token import TokenValidator

if TYPE_CHECKING:  # pragma: no cover
    from jwt.algorithms import AllowedPublicKeys  # noqa: F401

log = logging.getLogger("fastapi_zitadel_auth")


class ZitadelAuth(SecurityBase):
    """
    Zitadel OAuth2 authentication using bearer token
    """

    def __init__(
        self,
        issuer: HttpUrl,
        project_id: str,
        client_id: str,
        scopes: dict[str, str],
        leeway: float = 0,
    ) -> None:
        """
        Initialize the ZitadelAuth object
        """
        self.client_id = client_id
        self.project_id = project_id
        self.issuer = str(issuer).rstrip("/")
        self.leeway = leeway

        self.openid_config = OpenIdConfig(
            issuer=self.issuer,
            config_url=f"{self.issuer}/.well-known/openid-configuration",
            authorization_url=f"{self.issuer}/oauth/v2/authorize",
            token_url=f"{self.issuer}/oauth/v2/token",
            jwks_uri=f"{self.issuer}/oauth/v2/keys",
        )

        self.oauth = OAuth2AuthorizationCodeBearer(
            authorizationUrl=self.openid_config.authorization_url,
            tokenUrl=self.openid_config.token_url,
            scopes=scopes,
            scheme_name="ZitadelAuthorizationCodeBearer",
            description="Zitadel OAuth2 authentication using bearer token",
        )

        self.token_validator = TokenValidator()
        self.model = self.oauth.model
        self.scheme_name = self.oauth.scheme_name

    async def __call__(
        self, request: Request, security_scopes: SecurityScopes
    ) -> AuthenticatedUser | None:
        """
        Extend the SecurityBase __call__ method to validate the Zitadel OAuth2 token
        """

        try:
            # extract token from request
            access_token = await self._extract_access_token(request)
            if access_token is None:
                raise InvalidAuthException("No access token provided")

            # Parse unverified header and claims
            header, claims = self.token_validator.parse_unverified(token=access_token)
            log.debug("Header: %s", header)
            log.debug("Claims: %s", claims)
            log.debug("Required scopes: %s", ",".join(security_scopes.scopes))

            # Validate scopes
            self.token_validator.validate_scopes(
                self.project_id, claims, security_scopes.scopes
            )

            # Load or refresh the openid config
            await self.openid_config.load_config()

            # Get the JWKS key for the token
            key = self.openid_config.signing_keys.get(header.get("kid", ""))
            if key is None:
                raise InvalidAuthException("No valid signing key found")

            # Verify the token with the public key
            verified_claims = self.token_validator.verify(
                token=access_token,
                key=key,
                audiences=[self.client_id, self.project_id],
                issuer=self.openid_config.issuer,
                leeway=self.leeway,
            )

            # Create the authenticated user object and attach it to starlette.request.state
            user = AuthenticatedUser(
                claims=ZitadelClaims.model_validate(verified_claims),
                access_token=access_token,
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
            log.warning(f"Token contains invalid claims: {error}")
            raise InvalidAuthException("Token contains invalid claims") from error

        except ExpiredSignatureError as error:
            log.warning(f"Token signature has expired. {error}")
            raise InvalidAuthException("Token signature has expired") from error

        except InvalidTokenError as error:
            log.warning(f"Invalid token. Error: {error}", exc_info=True)
            raise InvalidAuthException("Unable to validate token") from error

        except (InvalidAuthException, HTTPException):
            raise

        except Exception as error:
            # Extra failsafe in case of a bug
            log.exception(f"Unable to process jwt token. Uncaught error: {error}")
            raise InvalidAuthException("Unable to process token") from error

    async def _extract_access_token(self, request: Request) -> str | None:
        """
        Extract the access token from the request
        """
        return await self.oauth(request=request)

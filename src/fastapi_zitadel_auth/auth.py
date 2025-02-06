"""
Authentication module for Zitadel OAuth2
"""

import logging
from typing import TYPE_CHECKING, Type

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
from .user import ClaimsT, DefaultZitadelClaims, DefaultZitadelUser, UserT
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
        issuer: HttpUrl | str,
        project_id: str,
        client_id: str,
        scopes: dict[str, str],
        leeway: float = 0,
        claims_model: Type[ClaimsT] = DefaultZitadelClaims,  # type: ignore
        user_model: Type[UserT] = DefaultZitadelUser,  # type: ignore
    ) -> None:
        """
        Initialize the ZitadelAuth object
        """
        self.client_id = client_id
        self.project_id = project_id
        self.issuer = str(issuer).rstrip("/")
        self.leeway = leeway

        self.claims_model = claims_model
        self.user_model = user_model

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
    ) -> UserT | None:
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
            log.debug("Unverified header: %s", header)
            log.debug("Unverified claims: %s", claims)

            # Validate header
            if header.get("alg") != "RS256":
                raise InvalidAuthException("Unsupported token algorithm")
            if header.get("typ") != "JWT":
                raise InvalidAuthException("Unsupported token type")

            log.debug("Required scopes: '%s'", security_scopes.scope_str)
            # Validate scopes
            self.token_validator.validate_scopes(claims, security_scopes.scopes)

            # Load or refresh the openid config
            await self.openid_config.load_config()

            # Get the JWKS key for the token
            log.debug("Token header kid: %s", header.get("kid", ""))
            key = self.openid_config.signing_keys.get(header.get("kid", ""))
            log.debug("Public key: %s", key)
            if key is None:
                raise InvalidAuthException(
                    "Unable to verify token, no signing keys found"
                )

            # Verify the token with the public key
            verified_claims = self.token_validator.verify(
                token=access_token,
                key=key,
                audiences=[self.client_id, self.project_id],
                issuer=self.openid_config.issuer,
                leeway=self.leeway,
            )

            # Create the user object
            user: UserT = self.user_model(  # type: ignore
                claims=self.claims_model.model_validate(verified_claims),
                access_token=access_token,
            )
            # Attach user to starlette.request.state
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

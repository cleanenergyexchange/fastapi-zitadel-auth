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

from .exceptions import UnauthorizedException, InvalidRequestException, ForbiddenException
from .user import (
    ClaimsT,
    DefaultZitadelClaims,
    DefaultZitadelUser,
    UserT,
    JwtClaims,
    BaseZitadelUser,
)
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
        issuer_url: HttpUrl | str,
        project_id: str,
        app_client_id: str,
        allowed_scopes: dict[str, str],
        token_leeway: float = 0,
        cache_ttl_seconds: int = 600,
        claims_model: Type[ClaimsT] = DefaultZitadelClaims,  # type: ignore
        user_model: Type[UserT] = DefaultZitadelUser,  # type: ignore
    ) -> None:
        """
        Initialize the ZitadelAuth object

        :param issuer_url: HttpUrl | str
            The Zitadel issuer URL

        :param project_id: str
            The Zitadel project ID

        :param app_client_id: str
            The Zitadel application client ID

        :param allowed_scopes: dict[str, str]
            The allowed scopes for the application. Key is the scope name and value is the description.
            Example:
                {
                    "read": "Read access"
                }

        :param token_leeway: float
            The tolerance time in seconds for token validation

        :param cache_ttl_seconds: int
            The time in seconds to cache the OpenID configuration

        :param claims_model: Type[ClaimsT]
            The claims model to use, e.g. DefaultZitadelClaims. See user.py

        :param user_model:  Type[UserT]
            The user model to use, e.g. DefaultZitadelUser. See user.py
        """

        self.client_id = app_client_id
        self.project_id = project_id
        self.issuer_url = str(issuer_url).rstrip("/")
        self.token_leeway = token_leeway

        if not issubclass(claims_model, JwtClaims):
            raise ValueError("claims_model must be a subclass of JwtClaims")

        if not issubclass(user_model, BaseZitadelUser):
            raise ValueError("user_model must be a subclass of BaseZitadelUser")

        self.claims_model = claims_model
        self.user_model = user_model

        self.openid_config = OpenIdConfig(
            issuer_url=self.issuer_url,
            config_url=f"{self.issuer_url}/.well-known/openid-configuration",
            authorization_url=f"{self.issuer_url}/oauth/v2/authorize",
            token_url=f"{self.issuer_url}/oauth/v2/token",
            jwks_uri=f"{self.issuer_url}/oauth/v2/keys",
            cache_ttl_seconds=cache_ttl_seconds,
        )

        self.oauth = OAuth2AuthorizationCodeBearer(
            authorizationUrl=self.openid_config.authorization_url,
            tokenUrl=self.openid_config.token_url,
            scopes=allowed_scopes,
            scheme_name="ZitadelAuthorizationCodeBearer",
            description="Zitadel OAuth2 authentication using bearer token",
        )

        self.token_validator = TokenValidator()
        self.model = self.oauth.model
        self.scheme_name = self.oauth.scheme_name

    async def __call__(self, request: Request, security_scopes: SecurityScopes) -> UserT | None:
        """
        Extend the SecurityBase.__call__ method to validate the Zitadel OAuth2 token.
        see also FastAPI -> "Advanced Dependency".
        """
        try:
            access_token = await self._extract_access_token(request)
            if access_token is None:
                raise InvalidRequestException("No access token provided")

            unverified_header, unverified_claims = self.token_validator.parse_unverified_token(access_token)
            self.token_validator.validate_header(unverified_header)
            self.token_validator.validate_scopes(unverified_claims, security_scopes.scopes)

            await self.openid_config.load_config()
            signing_key = await self.openid_config.get_key(unverified_header["kid"])

            try:
                verified_claims = self.token_validator.verify(
                    token=access_token,
                    key=signing_key,
                    audiences=[self.client_id, self.project_id],
                    issuer=self.openid_config.issuer_url,
                    token_leeway=self.token_leeway,
                )
            except (
                InvalidAudienceError,
                InvalidIssuerError,
                InvalidIssuedAtError,
                ImmatureSignatureError,
                MissingRequiredClaimError,
            ) as error:
                log.info(f"Token contains invalid claims: {error}")
                raise UnauthorizedException("Token contains invalid claims") from error

            except ExpiredSignatureError as error:
                log.info(f"Token signature has expired. {error}")
                raise UnauthorizedException("Token signature has expired") from error

            except InvalidTokenError as error:
                log.warning(f"Invalid token. Error: {error}", exc_info=True)
                raise UnauthorizedException("Unable to validate token") from error

            except Exception as error:
                # Extra failsafe in case of a bug in PyJWT
                log.exception(f"Unable to process jwt token. Uncaught error: {error}")
                raise UnauthorizedException("Unable to process token") from error

            else:
                user: UserT = self.user_model(  # type: ignore
                    claims=self.claims_model.model_validate(verified_claims),
                    access_token=access_token,
                )
                # Add the user to the request state
                request.state.user = user
                return user

        except (UnauthorizedException, InvalidRequestException, ForbiddenException, HTTPException):
            raise

        except Exception as error:
            # Failsafe in case of error in OAuth2AuthorizationCodeBearer.__call__
            log.warning(f"Unable to extract token from request. Error: {error}")
            raise InvalidRequestException("Unable to extract token from request") from error

    async def _extract_access_token(self, request: Request) -> str | None:
        """
        Extract the access token from the request
        """
        return await self.oauth(request=request)

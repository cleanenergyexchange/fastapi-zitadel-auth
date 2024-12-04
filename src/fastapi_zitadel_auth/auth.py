import logging
from typing import TYPE_CHECKING, Any

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
from starlette.requests import Request

from .config import AuthConfig
from .exceptions import InvalidAuthException
from .jwks import KeyManager
from .models import AuthenticatedUser, ZitadelClaims
from .token import TokenValidator

if TYPE_CHECKING:  # pragma: no cover
    from jwt.algorithms import AllowedPublicKeys  # noqa: F401

log = logging.getLogger("fastapi_zitadel_auth")
logging.basicConfig(level=logging.DEBUG)


class ZitadelAuth(SecurityBase):
    """
    Zitadel OAuth2 authentication using bearer token
    """

    def __init__(self, config: AuthConfig) -> None:
        """
        Initialize the ZitadelAuth object

        :param config: AuthConfig object
        """
        self.config = config
        self.oauth = OAuth2AuthorizationCodeBearer(
            authorizationUrl=config.authorization_url,
            tokenUrl=config.token_url,
            scopes=config.scopes,
            scheme_name="ZitadelAuthorizationCodeBearer",
            description="Zitadel OAuth2 authentication using bearer token",
        )
        self.token_validator = TokenValidator(algorithm=config.algorithm)
        self.key_manager = KeyManager(
            jwks_url=config.jwks_url, algorithm=config.algorithm
        )
        self.model = self.oauth.model
        self.scheme_name = self.oauth.scheme_name

    async def __call__(
        self, request: Request, security_scopes: SecurityScopes
    ) -> AuthenticatedUser | None:
        try:
            # extract token from request
            access_token = await self.oauth(request=request)
            if access_token is None:
                raise InvalidAuthException("No access token provided")

            # Parse unverified header and claims
            header, claims = self.token_validator.parse_unverified(token=access_token)
            log.debug(f"Header: {header}")
            log.debug(f"Claims: {claims}")
            log.debug(f"Required scopes: {security_scopes.scopes}")

            # Validate scopes
            if not self._validate_scopes(claims, security_scopes.scopes):
                raise InvalidAuthException("Insufficient permissions")

            # Get the JWKS public key
            key = await self.key_manager.get_public_key(header.get("kid", ""))
            if not key:
                raise InvalidAuthException("No valid signing key found")

            # Verify the token with the public key
            verified_claims = self.token_validator.verify(
                token=access_token,
                key=key,
                audiences=[self.config.client_id, self.config.project_id],
                issuer=self.config.issuer,
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

        except Exception as error:
            # Extra failsafe in case of a bug in a future version of the jwt library
            log.exception(f"Unable to process jwt token. Uncaught error: {error}")
            raise InvalidAuthException("Unable to process token") from error

    def _validate_scopes(
        self, claims: dict[str, Any], required_scopes: list[str]
    ) -> bool:
        permission_claim = f"urn:zitadel:iam:org:project:{self.config.project_id}:roles"

        if permission_claim not in claims or not isinstance(
            claims[permission_claim], dict
        ):
            log.warning(f"Missing or invalid roles in token claims: {permission_claim}")
            raise InvalidAuthException("Invalid token structure")

        project_roles = claims[permission_claim]
        for required_scope in required_scopes:
            if required_scope not in project_roles:
                log.warning(f"Token does not have required scope: {required_scope}")
                raise InvalidAuthException("Not enough permissions")
        return True

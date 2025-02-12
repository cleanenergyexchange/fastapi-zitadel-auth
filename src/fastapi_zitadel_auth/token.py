import logging
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from fastapi_zitadel_auth.exceptions import UnauthorizedException, ForbiddenException

log = logging.getLogger("fastapi_zitadel_auth")


class TokenValidator:
    """Handles JWT token validation and parsing"""

    @staticmethod
    def validate_scopes(claims: dict[str, Any], required_scopes: list[str] | None) -> bool:
        """
        Validates that the token has the required scopes
        """
        if required_scopes is None:
            return True

        # Check if the token has the scope field and it is a string
        token_scope_str = claims.get("scope", "")
        if not isinstance(token_scope_str, str):
            log.warning("Invalid scope format: %s", token_scope_str)
            raise UnauthorizedException("Token contains invalid formatted scopes")
        token_scopes = token_scope_str.split()

        # Check if all required scopes are present
        for required_scope in required_scopes:
            if required_scope not in token_scopes:
                log.debug(f"Missing required scope: {required_scope}. Available scopes: {token_scopes}")
                raise ForbiddenException(f"Missing required scope: {required_scope}")
        return True

    @staticmethod
    def parse_unverified_token(
        access_token: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Parse header and claims without verification"""
        try:
            header = dict(jwt.get_unverified_header(access_token))
            claims = dict(jwt.decode(access_token, options={"verify_signature": False}))
            return header, claims
        except Exception as e:
            log.warning(
                "Malformed token received. %s. Error: %s",
                access_token,
                e,
                exc_info=True,
            )
            raise UnauthorizedException("Invalid token format") from e

    @staticmethod
    def validate_header(header: dict[str, Any]) -> None:
        """Validate token header"""
        if header.get("alg") != "RS256" or header.get("typ") != "JWT":
            raise UnauthorizedException("Invalid token header")

    @staticmethod
    def verify(
        token: str,
        key: RSAPublicKey,
        audiences: list[str],
        issuer: str,
        token_leeway: float = 0,
    ) -> dict[str, Any]:
        """Verify token signature and claims with provided key"""
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
            "verify_sub": True,
            "verify_jti": True,
            "require": ["exp", "nbf", "iat", "aud", "iss", "sub", "jti"],
        }
        return jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=audiences,
            issuer=issuer,
            leeway=token_leeway,
            options=options,
        )

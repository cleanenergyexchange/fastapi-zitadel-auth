import logging
from typing import Any

import jwt

from fastapi_zitadel_auth.exceptions import InvalidAuthException

log = logging.getLogger("fastapi_zitadel_auth")


class TokenValidator:
    """Handles JWT token validation and parsing"""

    @staticmethod
    def validate_scopes(
        claims: dict[str, Any], required_scopes: list[str] | None
    ) -> bool:
        """
        Validates that the token has the required scopes
        """
        if required_scopes is None:
            return True

        token_scopes = claims.get("scope", "").split()

        # Check if all required scopes are present
        for required_scope in required_scopes:
            if required_scope not in token_scopes:
                log.warning(
                    f"Missing required scope: {required_scope}. "
                    f"Available scopes: {token_scopes}"
                )
                raise InvalidAuthException(f"Missing required scope: {required_scope}")
        return True

    @staticmethod
    def parse_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Parse header and claims without verification"""
        try:
            header = dict(jwt.get_unverified_header(token))
            claims = dict(jwt.decode(token, options={"verify_signature": False}))
            return header, claims
        except Exception as e:
            raise InvalidAuthException("Invalid token format") from e

    @staticmethod
    def verify(
        token: str,
        key: Any,
        audiences: list[str],
        issuer: str,
        leeway: float = 0,
    ) -> dict[str, Any]:
        """Verify token signature and claims"""
        options = {
            "verify_signature": True,
            "verify_aud": True,
            "verify_iat": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iss": True,
            "require": ["exp", "aud", "iat", "nbf", "sub", "iss"],
        }
        return jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=audiences,
            issuer=issuer,
            leeway=leeway,
            options=options,
        )

from typing import Any

import jwt

from fastapi_zitadel_auth.exceptions import InvalidAuthException


class TokenValidator:
    """Handles JWT token validation and parsing"""

    def __init__(self, algorithm: str = "RS256"):
        self.algorithm = algorithm

    @staticmethod
    def parse_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Parse header and claims without verification"""
        try:
            header = dict(jwt.get_unverified_header(token))
            claims = dict(jwt.decode(token, options={"verify_signature": False}))
            return header, claims
        except Exception as e:
            raise InvalidAuthException("Invalid token format") from e

    def verify(
        self, token: str, key: Any, audiences: list[str], issuer: str
    ) -> dict[str, Any]:
        """Verify token signature and claims"""
        options = {
            "verify_signature": True,
            "verify_aud": True,
            "verify_iat": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iss": True,
            "require": ["exp", "aud", "iat", "nbf", "sub"],
            "leeway": 0,
        }
        return jwt.decode(
            token,
            key=key,
            algorithms=[self.algorithm],
            audience=audiences,
            issuer=issuer,
            options=options,
        )

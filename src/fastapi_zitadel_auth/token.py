import logging
from typing import Any

import jwt

from fastapi_zitadel_auth.exceptions import InvalidAuthException

log = logging.getLogger("fastapi_zitadel_auth")


class TokenValidator:
    """Handles JWT token validation and parsing"""

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
    def validate_scopes(
        project_id: str, claims: dict[str, Any], required_scopes: list[str]
    ) -> bool:
        """
        Validate the token scopes against the required scopes
        """
        permission_claim = f"urn:zitadel:iam:org:project:{project_id}:roles"

        if permission_claim not in claims or not isinstance(
            claims[permission_claim], dict
        ):
            log.warning(f"Missing or invalid roles in token claims: {permission_claim}")
            raise InvalidAuthException(
                f"Missing or invalid roles in token claims: {permission_claim}"
            )

        project_roles = claims[permission_claim]
        for required_scope in required_scopes:
            if required_scope not in project_roles:
                log.warning(f"Token does not have required scope: {required_scope}")
                raise InvalidAuthException(
                    f"Token does not have required scope: {required_scope}"
                )
        return True

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

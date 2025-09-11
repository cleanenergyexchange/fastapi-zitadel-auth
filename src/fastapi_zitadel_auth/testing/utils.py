"""
Utility functions and constants for testing Zitadel authentication
"""

import logging
import os
from datetime import datetime, timedelta
from typing import (
    TypeVar,
    Generic,
    Any,  # noqa
)

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.requests import Request
from fastapi.security import SecurityScopes
from fastapi_zitadel_auth.exceptions import InvalidRequestException, UnauthorizedException, ForbiddenException
from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.auth import BaseZitadelUser, JwtClaims

ClaimsT = TypeVar("ClaimsT", bound="JwtClaims")
UserT = TypeVar("UserT", bound="BaseZitadelUser[Any]")

log = logging.getLogger("fastapi_zitadel_auth")

# Test constants - can be overridden with environment variables or custom values
ZITADEL_ISSUER = os.environ.get("ZITADEL_HOST")
ZITADEL_PROJECT_ID = os.environ.get("ZITADEL_PROJECT_ID")
ZITADEL_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID")
ZITADEL_PRIMARY_DOMAIN = os.environ.get("ZITADEL_PRIMARY_DOMAIN")


def openid_config_url(issuer: str = ZITADEL_ISSUER) -> str:
    """Generate OpenID configuration URL"""
    return f"{issuer}/.well-known/openid-configuration"


def keys_url(issuer: str = ZITADEL_ISSUER) -> str:
    """Generate JWKS URL"""
    return f"{issuer}/oauth/v2/keys"


def openid_configuration(issuer: str = ZITADEL_ISSUER) -> dict[str, Any]:
    """Generate mock OpenID configuration"""
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/v2/authorize",
        "token_endpoint": f"{issuer}/oauth/v2/token",
        "introspection_endpoint": f"{issuer}/oauth/v2/introspect",
        "userinfo_endpoint": f"{issuer}/oidc/v1/userinfo",
        "revocation_endpoint": f"{issuer}/oauth/v2/revoke",
        "end_session_endpoint": f"{issuer}/oidc/v1/end_session",
        "device_authorization_endpoint": f"{issuer}/oauth/v2/device_authorization",
        "jwks_uri": f"{issuer}/oauth/v2/keys",
        "scopes_supported": [
            "openid",
            "profile",
            "email",
            "phone",
            "address",
            "offline_access",
        ],
        "response_types_supported": ["code", "id_token", "id_token token"],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "request_object_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
        "revocation_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ],
        "revocation_endpoint_auth_signing_alg_values_supported": ["RS256"],
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "private_key_jwt",
        ],
        "introspection_endpoint_auth_signing_alg_values_supported": ["RS256"],
        "claims_supported": [
            "sub",
            "aud",
            "exp",
            "iat",
            "iss",
            "auth_time",
            "nonce",
            "acr",
            "amr",
            "c_hash",
            "at_hash",
            "act",
            "scopes",
            "client_id",
            "azp",
            "preferred_username",
            "name",
            "family_name",
            "given_name",
            "locale",
            "email",
            "email_verified",
            "phone_number",
            "phone_number_verified",
        ],
        "code_challenge_methods_supported": ["S256"],
        "ui_locales_supported": [
            "bg",
            "cs",
            "de",
            "en",
            "es",
            "fr",
            "hu",
            "id",
            "it",
            "ja",
            "ko",
            "mk",
            "nl",
            "pl",
            "pt",
            "ru",
            "sv",
            "zh",
        ],
        "request_parameter_supported": True,
        "request_uri_parameter_supported": False,
    }


def create_test_token(
    kid: str = "test-key-1",
    expired: bool = False,
    invalid_iss: bool = False,
    invalid_aud: bool = False,
    scopes: str = "openid profile",
    evil: bool = False,
    role: str | None = None,
    typ: str = "JWT",
    alg: str = "RS256",
    subject: str = "user123",
    client_id: str = ZITADEL_CLIENT_ID,
    issuer: str = ZITADEL_ISSUER,
    project_id: str = ZITADEL_PROJECT_ID,
    primary_domain: str = ZITADEL_PRIMARY_DOMAIN,
    additional_claims: dict[str, Any] | None = None
) -> str:
    """
    Create a test JWT token for testing purposes
    
    Args:
        kid: Key ID to use in header
        expired: Whether token should be expired
        invalid_iss: Whether to use invalid issuer
        invalid_aud: Whether to use invalid audience
        scopes: Space-separated scopes string
        evil: Whether to sign with different key than claimed
        role: Role to add to token claims
        typ: Token type
        alg: Algorithm
        subject: Token subject (user ID)
        client_id: OAuth client ID
        issuer: Token issuer
        project_id: Zitadel project ID
        primary_domain: Primary domain for role claims
        additional_claims: Additional claims to include
    
    Returns:
        JWT token string
    """
    now = datetime.now()
    claims = {
        "aud": ["wrong-id"] if invalid_aud else [project_id, client_id],
        "client_id": client_id,
        "exp": int((now - timedelta(hours=1)).timestamp()) if expired else int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "iss": "wrong-issuer" if invalid_iss else issuer,
        "sub": subject,
        "nbf": int(now.timestamp()),
        "jti": "unique-token-id",
        "scope": scopes,
    }

    if role:
        claims[f"urn:zitadel:iam:org:project:{project_id}:roles"] = {role: {"role_id": primary_domain}}

    if additional_claims:
        claims.update(additional_claims)

    # For evil token use the evil key but claim it's from the valid key
    signing_key = evil_key if evil else valid_key
    headers = {"kid": kid, "typ": typ, "alg": alg}

    private_key = signing_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(claims, private_key, algorithm="RS256", headers=headers)


def create_openid_keys(
    empty_keys: bool = False,
    no_valid_keys: bool = False,
    additional_key: str = None
) -> dict[str, Any]:
    """
    Create mock JWKS response
    
    Args:
        empty_keys: Return empty keys list
        no_valid_keys: Return keys that aren't valid for signing
        additional_key: Add an additional key with this kid
    
    Returns:
        JWKS dictionary
    """
    if empty_keys:
        return {"keys": []}
    elif no_valid_keys:
        # Return a random key that is not valid for the test
        return {
            "keys": [
                {
                    "use": "sig",
                    "kty": "RSA",
                    "kid": "305924551714316751",
                    "alg": "RS256",
                    "n": "rXjVHSfeFS5rtqtDSpdBwolJcteLCDOPVZV8WR0IGrYM7x0fssPimzdWr4PzNY0JvX8CCkYpD99iPhNpwzArC27T2EXrVJmwE93SeyAbwLAXE21h3GIE18UM82y7p7GM-kTc9E9Icvr8UeF9mprARXKVDNq6KdDrwOU70BmUO_FOMBRKpjwIyI1OLIOP69qQ7c6sDLiaQsBHcwolGvMMunzyCLtgWEb6rjRG5wDwu1syqVK4ADWbipFoqx4NGOXzU0yeaiSqnBeu2eJh7r6MTp41IdVz9FPnA0HTXLB3pJZspbDB27g9u1F8RhpDNFYbgcX4YJB6CO6DCKOYEmTxUw",
                    "e": "AQAB",
                }
            ]
        }
    elif additional_key:
        return {
            "keys": [
                {
                    "use": "sig",
                    "kid": "test-key-1",
                    "kty": "RSA",
                    "alg": "RS256",
                    **jwt.algorithms.RSAAlgorithm.to_jwk(
                        valid_key.public_key(),
                        as_dict=True,
                    ),
                },
                {
                    "use": "sig",
                    "kid": additional_key,
                    "kty": "RSA",
                    "alg": "RS256",
                    **jwt.algorithms.RSAAlgorithm.to_jwk(
                        valid_key.public_key(),
                        as_dict=True,
                    ),
                },
            ]
        }
    else:
        return {
            "keys": [
                {
                    "use": "sig",
                    "kid": "test-key-1",
                    "kty": "RSA",
                    "alg": "RS256",
                    **jwt.algorithms.RSAAlgorithm.to_jwk(
                        valid_key.public_key(),
                        as_dict=True,
                    ),
                }
            ]
        }


class MockZitadelAuth(ZitadelAuth):
    """
    Mock ZitadelAuth for testing that bypasses actual Zitadel validation
    
    Useful for testing when you want to control the authentication behavior
    without making actual HTTP requests to Zitadel.
    """
    
    def __init__(
        self,
        mock_user_id: str = "test-user",
        mock_scopes: list = None,
        **kwargs
    ):
        print("MockZitadelAuth.__init__ called!")
        super().__init__(**kwargs)
        self.mock_user_id = mock_user_id
        self.mock_scopes = mock_scopes or ["openid", "profile"]
    
    async def __call__(self, request: Request, security_scopes: SecurityScopes) -> UserT | None:
        """
        Extend the SecurityBase.__call__ method to validate the Zitadel OAuth2 token.
        see also FastAPI -> "Advanced Dependency".
        """
        print("MockZitadelAuth.__call__ is being called!")
        try:
            access_token = await self._extract_access_token(request)
            if access_token is None:
                raise InvalidRequestException("No access token provided")

            unverified_header, unverified_claims = self.token_validator.parse_unverified_token(access_token)
            self.token_validator.validate_header(unverified_header)
            self.token_validator.validate_scopes(unverified_claims, security_scopes.scopes)

            print("Unverified claims:", unverified_claims)  # Debug line

            user: UserT = self.user_model(  # type: ignore
                # here we check the unverified claims instead of verified ones!
                claims=self.claims_model.model_validate(unverified_claims), 
                access_token=access_token,
            )
            # Add the user to the request state
            request.state.user = user
            return user
        
        except (UnauthorizedException, InvalidRequestException, ForbiddenException):
            raise

        except Exception as error:
            # Failsafe in case of error in OAuth2AuthorizationCodeBearer.__call__
            log.warning(f"Unable to extract token from request. Error: {error}")
            raise InvalidRequestException("Unable to extract token from request") from error

# Generate test RSA keys
valid_key = rsa.generate_private_key(
    backend=default_backend(), 
    public_exponent=65537, 
    key_size=2048
)

evil_key = rsa.generate_private_key(
    backend=default_backend(), 
    public_exponent=65537, 
    key_size=2048
)

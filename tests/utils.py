"""
Test utilities
"""

import os
from datetime import datetime, timedelta

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Global test settings
ZITADEL_ISSUER = os.environ["ZITADEL_HOST"]  # The Zitadel issuer URL
ZITADEL_PROJECT_ID = os.environ["ZITADEL_PROJECT_ID"]  # The project ID where the API app is located
ZITADEL_CLIENT_ID = os.environ["OAUTH_CLIENT_ID"]  # The client ID of the API app
ZITADEL_PRIMARY_DOMAIN = "client-fza.region.zitadel.cloud"  # The primary domain of a Zitadel client


def openid_config_url() -> str:
    """OpenID configuration URL fixture"""
    return f"{ZITADEL_ISSUER}/.well-known/openid-configuration"


def keys_url() -> str:
    """OpenID keys URL fixture"""
    return f"{ZITADEL_ISSUER}/oauth/v2/keys"


def openid_configuration() -> dict:
    """OpenID configuration fixture"""
    return {
        "issuer": ZITADEL_ISSUER,
        "authorization_endpoint": f"{ZITADEL_ISSUER}/oauth/v2/authorize",
        "token_endpoint": f"{ZITADEL_ISSUER}/oauth/v2/token",
        "introspection_endpoint": f"{ZITADEL_ISSUER}/oauth/v2/introspect",
        "userinfo_endpoint": f"{ZITADEL_ISSUER}/oidc/v1/userinfo",
        "revocation_endpoint": f"{ZITADEL_ISSUER}/oauth/v2/revoke",
        "end_session_endpoint": f"{ZITADEL_ISSUER}/oidc/v1/end_session",
        "device_authorization_endpoint": f"{ZITADEL_ISSUER}/oauth/v2/device_authorization",
        "jwks_uri": f"{ZITADEL_ISSUER}/oauth/v2/keys",
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
    scopes: str = "scope1",
    evil: bool = False,
    role: str | None = None,
    typ: str = "JWT",
    alg: str = "RS256",
) -> str:
    """Create JWT tokens for testing"""
    now = datetime.now()
    claims = {
        "aud": ["wrong-id"] if invalid_aud else [ZITADEL_PROJECT_ID, ZITADEL_CLIENT_ID],
        "client_id": ZITADEL_CLIENT_ID,
        "exp": int((now - timedelta(hours=1)).timestamp()) if expired else int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "iss": "wrong-issuer" if invalid_iss else ZITADEL_ISSUER,
        "sub": "user123",
        "nbf": int(now.timestamp()),
        "jti": "unique-token-id",
        "scope": scopes,
    }

    if role:
        claims[f"urn:zitadel:iam:org:project:{ZITADEL_PROJECT_ID}:roles"] = {role: {"role_id": ZITADEL_PRIMARY_DOMAIN}}

    # For evil token use the evil key but claim it's from the valid key
    signing_key = evil_key if evil else valid_key
    headers = {"kid": kid, "typ": typ, "alg": alg}

    private_key = signing_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(claims, private_key, algorithm="RS256", headers=headers)


def create_openid_keys(empty_keys: bool = False, no_valid_keys: bool = False, additional_key: str = "") -> dict:
    """
    Create OpenID keys
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


valid_key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)
evil_key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)

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


def create_openid_keys(empty_keys: bool = False, no_valid_keys: bool = False) -> dict:
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

"""
Test utilities
"""

import time

import jwt
from cryptography.hazmat.primitives import serialization


def create_test_token(
    test_keys,
    kid="test-key-1",
    expired=False,
    invalid_claims=False,
    invalid_roles=False,
    evil=False,
) -> str:
    """
    Create JWT tokens for testing
    """
    now = int(time.time())
    claims = {
        "sub": "user123",
        "iss": "https://issuer.zitadel.cloud",
        "aud": ["123456789", "987654321"] if not invalid_claims else ["wrong-audience"],
        "exp": now - 300 if expired else now + 3600,
        "iat": now,
        "nbf": now,
        "urn:zitadel:iam:org:project:987654321:roles": {"system": True}
        if not invalid_roles
        else {},
    }

    # For evil token use the evil key but claim it's from the valid key
    signing_key = test_keys["evil"] if evil else test_keys["valid"]
    headers = {"kid": kid, "typ": "JWT", "alg": "RS256"}

    private_key = signing_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(claims, private_key, algorithm="RS256", headers=headers)

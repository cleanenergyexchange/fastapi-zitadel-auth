"""
Test the jwks module
"""

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from httpx import Response

from fastapi_zitadel_auth.jwks import KeyManager

MOCK_JWKS_URL = "https://api.example.com/.well-known/jwks.json"
MOCK_JWKS_RESPONSE = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "test-key-1",
            "use": "sig",
            "n": "xd-yGq9DV3M8xCz8UagZ6HoX7C_Jj6B3eJQBwvOk_GkpyIh_XE4TRHqWzKz3d8sZLxphxhOkVhLR01T2g4JDhP9yJo8lQZe4T2jGmgpL8o5UZlxTY5Pj5YmUeCZxf0iKkg_j2ZxG9D7eGGWmI6GPOwzd5HBiUS8GnFvqGHmjNcV3_nzHv6yGfYsUZh8uZ8S2GVT5znDDvZYGB3MIR0H2k4qVNUGEZzLPBHXiH-xnB7Tq2wuPEITk2TMokS4KQXJjxiBWN_hRlK8VhwWgXTTWpkwl8sWFY4EFOvpBdRKZQAL5jNRUnO3pDO5X53Bv_SG6DUqyxZoQ7W5CZ6F7tQ",
            "e": "AQAB",
        }
    ]
}


@pytest.mark.asyncio
async def test_get_public_key_success(mock_api):
    """
    Test successful retrieval of public key from JWKS
    """
    key_manager = KeyManager(jwks_url=MOCK_JWKS_URL, algorithm="RS256")

    mock_api.get(MOCK_JWKS_URL).mock(
        return_value=Response(200, json=MOCK_JWKS_RESPONSE)
    )

    public_key = await key_manager.get_public_key("test-key-1")

    assert public_key is not None
    assert isinstance(public_key, RSAPublicKey)


@pytest.mark.asyncio
async def test_get_public_key_invalid_kid(mock_api):
    """
    Test retrieval of public key with invalid Key ID
    """
    key_manager = KeyManager(jwks_url=MOCK_JWKS_URL, algorithm="RS256")

    mock_api.get(MOCK_JWKS_URL).mock(
        return_value=Response(200, json=MOCK_JWKS_RESPONSE)
    )

    public_key = await key_manager.get_public_key("non-existent-kid")

    assert public_key is None


@pytest.mark.asyncio
async def test_jwks_fetch_error(mock_api):
    """
    Test error handling when fetching JWKS
    """
    key_manager = KeyManager(jwks_url=MOCK_JWKS_URL, algorithm="RS256")

    mock_api.get(MOCK_JWKS_URL).mock(return_value=Response(500))

    with pytest.raises(httpx.HTTPStatusError):
        await key_manager.get_public_key("test-key-1")


@pytest.mark.asyncio
async def test_cache_reuse(mock_api):
    """
    Test that the JWKS cache is reused
    """
    key_manager = KeyManager(jwks_url=MOCK_JWKS_URL, algorithm="RS256")

    route = mock_api.get(MOCK_JWKS_URL).mock(
        return_value=Response(200, json=MOCK_JWKS_RESPONSE)
    )

    await key_manager.get_public_key("test-key-1")
    assert route.call_count == 1

    await key_manager.get_public_key("test-key-1")
    assert route.call_count == 1  # Still 1, indicating cache was used

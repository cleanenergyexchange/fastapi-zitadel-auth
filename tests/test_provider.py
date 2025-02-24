"""
Test the provider configuration (Zitadel) fetching.
"""

import asyncio
import logging
from datetime import datetime, timedelta

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from httpx import AsyncClient, ASGITransport, HTTPError

from demo_project.dependencies import zitadel_auth
from demo_project.main import app
from fastapi_zitadel_auth.exceptions import UnauthorizedException
from tests.conftest import openid_configuration
from tests.utils import create_test_token, openid_config_url, keys_url, create_openid_keys

log = logging.getLogger(__name__)


async def test_successful_config_load(mock_openid_and_keys):
    """Test that OpenIdConfig loads config and keys correctly"""

    test_start = datetime.now()
    assert len(zitadel_auth.openid_config.signing_keys) == 0
    assert zitadel_auth.openid_config.last_refresh_timestamp is None

    await zitadel_auth.openid_config.load_config()

    assert len(zitadel_auth.openid_config.signing_keys) == 1
    assert isinstance(zitadel_auth.openid_config.signing_keys, dict)
    assert isinstance(zitadel_auth.openid_config.signing_keys["test-key-1"], RSAPublicKey)

    assert zitadel_auth.openid_config.last_refresh_timestamp is not None
    assert isinstance(zitadel_auth.openid_config.last_refresh_timestamp, datetime)
    assert test_start <= zitadel_auth.openid_config.last_refresh_timestamp <= datetime.now()

    assert zitadel_auth.openid_config.issuer_url
    assert zitadel_auth.openid_config.config_url
    assert zitadel_auth.openid_config.authorization_url
    assert zitadel_auth.openid_config.token_url
    assert zitadel_auth.openid_config.jwks_uri
    assert isinstance(zitadel_auth.openid_config.cache_ttl_seconds, int)
    assert zitadel_auth.openid_config.cache_ttl_seconds > 0


async def test_caching_behavior():
    """Test that caching works and prevents unnecessary refreshes"""
    with respx.mock(assert_all_called=True) as mock:
        mock.get(openid_config_url()).mock(return_value=httpx.Response(200, json=openid_configuration()))
        mock.get(keys_url()).mock(return_value=httpx.Response(200, json=create_openid_keys()))

        # First load
        await zitadel_auth.openid_config.load_config()
        first_timestamp = zitadel_auth.openid_config.last_refresh_timestamp

        # Second immediate load should use cache
        await zitadel_auth.openid_config.load_config()
        assert zitadel_auth.openid_config.last_refresh_timestamp == first_timestamp
        assert mock.calls.call_count == 2  # Only called once for initial load


async def test_cache_expiration():
    """Test that cache refreshes after expiration"""
    with respx.mock(assert_all_called=True) as mock:
        mock.get(openid_config_url()).mock(return_value=httpx.Response(200, json=openid_configuration()))
        mock.get(keys_url()).mock(return_value=httpx.Response(200, json=create_openid_keys()))

        # First load
        await zitadel_auth.openid_config.load_config()

        # Manually expire cache
        zitadel_auth.openid_config.last_refresh_timestamp = datetime.now() - timedelta(
            seconds=zitadel_auth.openid_config.cache_ttl_seconds + 1
        )

        # Should trigger refresh
        await zitadel_auth.openid_config.load_config()
        assert mock.calls.call_count == 4  # Two calls for each load


async def test_concurrent_refresh_requests():
    """Test that concurrent refreshes are handled correctly"""
    with respx.mock(assert_all_called=True) as mock:

        async def slow_config_response(*args, **kwargs):
            await asyncio.sleep(0.2)
            return httpx.Response(200, json=openid_configuration())

        async def slow_keys_response(*args, **kwargs):
            await asyncio.sleep(0.2)
            return httpx.Response(200, json=create_openid_keys())

        config_route = mock.get(openid_config_url()).mock(side_effect=slow_config_response)
        keys_route = mock.get(keys_url()).mock(side_effect=slow_keys_response)

        zitadel_auth.openid_config.reset_cache()

        tasks = [zitadel_auth.openid_config.load_config() for _ in range(5)]
        await asyncio.gather(*tasks)

        assert len(config_route.calls) == 1, "Config endpoint called multiple times"
        assert len(keys_route.calls) == 1, "Keys endpoint called multiple times"
        assert len(zitadel_auth.openid_config.signing_keys) == 1


async def test_provider_connection_failure_openid(fastapi_app):
    """Test that the app handles connection failures to the provider on OpenID config fetch"""
    with respx.mock(assert_all_called=True) as mock:
        mock.get(openid_config_url()).mock(side_effect=HTTPError("Connection failed"))

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": "Bearer " + create_test_token(role="admin")},
        ) as ac:
            response = await ac.get("/api/protected/admin")

            assert response.status_code == 401
            assert response.json() == {
                "detail": {
                    "error": "invalid_token",
                    "message": "Unable to refresh configuration from identity provider",
                }
            }
            assert response.headers["WWW-Authenticate"] == "Bearer"

        assert mock.calls.call_count == 1
        assert zitadel_auth.openid_config.last_refresh_timestamp is None
        assert len(zitadel_auth.openid_config.signing_keys) == 0


async def test_provider_connection_failure_jwks(fastapi_app):
    """Test that the app handles connection failures to the provider on JWKS fetch"""
    with respx.mock(assert_all_called=True) as mock:
        mock.get(openid_config_url()).mock(return_value=httpx.Response(200, json=openid_configuration()))
        mock.get(keys_url()).mock(side_effect=HTTPError("Connection failed"))

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": "Bearer " + create_test_token(role="admin")},
        ) as ac:
            response = await ac.get("/api/protected/admin")

            assert response.status_code == 401
            assert response.json() == {
                "detail": {
                    "error": "invalid_token",
                    "message": "Unable to refresh configuration from identity provider",
                }
            }
            assert response.headers["WWW-Authenticate"] == "Bearer"

        assert mock.calls.call_count == 2
        assert zitadel_auth.openid_config.last_refresh_timestamp is None
        assert len(zitadel_auth.openid_config.signing_keys) == 0


async def test_invalid_config_response():
    """Test handling of invalid config response"""
    with respx.mock(assert_all_called=True) as mock:
        mock.get(openid_config_url()).mock(return_value=httpx.Response(200, json={"invalid": "config"}))

        with pytest.raises(UnauthorizedException):
            await zitadel_auth.openid_config.load_config()


async def test_invalid_jwks_response():
    """Test handling of invalid JWKS response"""
    with respx.mock(assert_all_called=True) as mock:
        mock.get(openid_config_url()).mock(return_value=httpx.Response(200, json=openid_configuration()))
        mock.get(keys_url()).mock(return_value=httpx.Response(200, json={"keys": [{"invalid": "key"}]}))

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": "Bearer " + create_test_token(role="admin")},
        ) as ac:
            response = await ac.get("/api/protected/admin")

            assert response.status_code == 401

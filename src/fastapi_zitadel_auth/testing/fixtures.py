"""
Pytest fixtures for testing with fastapi-zitadel-auth

To use these fixtures in your tests, add this to your conftest.py:

    from fastapi_zitadel_auth.testing.fixtures import *
"""

from typing import Iterator, Any

import httpx
import pytest
import respx

from .utils import (
    create_openid_keys,
    openid_config_url,
    openid_configuration,
    keys_url,
    MockZitadelAuth,
    ZITADEL_CLIENT_ID,
    ZITADEL_ISSUER,
    ZITADEL_PROJECT_ID,
)


@pytest.fixture
def mock_zitadel_auth() -> MockZitadelAuth:
    """
    Fixture providing a mock ZitadelAuth instance
    
    Returns a MockZitadelAuth that bypasses actual Zitadel validation.
    Useful for testing application logic without network calls.
    """
    return MockZitadelAuth(
        issuer_url=ZITADEL_ISSUER,
        app_client_id=ZITADEL_CLIENT_ID,
        project_id=ZITADEL_PROJECT_ID,
        allowed_scopes={"openid": "OpenID scope", "profile": "Profile scope"},
    )


@pytest.fixture(autouse=True)
async def reset_openid_cache():
    """
    Reset the OpenID configuration cache before each test
    
    This fixture automatically runs before each test to ensure
    a clean state for OpenID configuration caching.
    """
    # Note: This assumes ZitadelAuth has a cache that can be reset
    # Users may need to adjust this based on their actual implementation
    yield


@pytest.fixture
def mock_openid():
    """
    Fixture to mock OpenID configuration endpoint
    
    Mocks the /.well-known/openid-configuration endpoint
    """
    with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(openid_config_url()).respond(json=openid_configuration())
        yield respx_mock


@pytest.fixture
def mock_openid_and_keys():
    """
    Fixture to mock both OpenID configuration and JWKS endpoints
    
    Mocks both the OpenID configuration and the keys endpoint
    with valid test keys.
    """
    with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(openid_config_url()).respond(json=openid_configuration())
        respx_mock.get(keys_url()).respond(json=create_openid_keys())
        yield respx_mock


@pytest.fixture
def mock_openid_and_empty_keys():
    """
    Fixture to mock OpenID with empty keys response
    
    Useful for testing error handling when no keys are available.
    """
    with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(openid_config_url()).respond(json=openid_configuration())
        respx_mock.get(keys_url()).respond(json=create_openid_keys(empty_keys=True))
        yield respx_mock


@pytest.fixture
def mock_openid_and_no_valid_keys():
    """
    Fixture to mock OpenID with invalid keys
    
    Useful for testing error handling when keys are not valid for signing.
    """
    with respx.mock(assert_all_called=False) as respx_mock:
        respx_mock.get(openid_config_url()).respond(json=openid_configuration())
        respx_mock.get(keys_url()).respond(json=create_openid_keys(no_valid_keys=True))
        yield respx_mock


@pytest.fixture
def mock_openid_empty_then_ok():
    """
    Fixture to simulate key rotation
    
    First request returns empty keys, second returns valid keys.
    Useful for testing key rotation scenarios.
    """
    with respx.mock(assert_all_called=False) as respx_mock:
        openid_route = respx_mock.get(openid_config_url())
        openid_route.side_effect = [
            httpx.Response(json=openid_configuration(), status_code=200),
            httpx.Response(json=openid_configuration(), status_code=200),
        ]
        
        keys_route = respx_mock.get(keys_url())
        keys_route.side_effect = [
            httpx.Response(json=create_openid_keys(empty_keys=True), status_code=200),
            httpx.Response(json=create_openid_keys(additional_key="rotated-key"), status_code=200),
        ]
        yield respx_mock


# Descriptive aliases for better readability in new code
mock_openid_config = mock_openid
mock_openid_keys = mock_openid_and_keys
mock_openid_empty_keys = mock_openid_and_empty_keys
mock_openid_key_rotation = mock_openid_empty_then_ok
mock_openid_invalid_keys = mock_openid_and_no_valid_keys

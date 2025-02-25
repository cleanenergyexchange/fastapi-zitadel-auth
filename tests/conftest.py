"""
Pytest conftest.py file to define fixtures available to all tests
"""

from typing import Iterator

import httpx
import pytest
import respx
from blockbuster import blockbuster_ctx, BlockBuster
from starlette.testclient import TestClient

from demo_project.dependencies import zitadel_auth
from demo_project.main import app
from fastapi_zitadel_auth import ZitadelAuth
from tests.utils import (
    create_openid_keys,
    openid_config_url,
    openid_configuration,
    keys_url,
    ZITADEL_CLIENT_ID,
    ZITADEL_ISSUER,
    ZITADEL_PROJECT_ID,
)


@pytest.fixture
def fastapi_app():
    """FastAPI app fixture"""
    zitadel_auth_overrides = ZitadelAuth(
        issuer_url=ZITADEL_ISSUER,
        app_client_id=ZITADEL_CLIENT_ID,
        project_id=ZITADEL_PROJECT_ID,
        allowed_scopes={"scope1": "Some scope"},
    )
    app.dependency_overrides[zitadel_auth] = zitadel_auth_overrides
    yield


@pytest.fixture(autouse=True)
def blockbuster() -> Iterator[BlockBuster]:
    """Detect blocking calls within an asynchronous event loop"""
    with blockbuster_ctx() as bb:
        yield bb


@pytest.fixture(autouse=True)
async def reset_openid_config():
    """Reset the OpenID configuration before each test"""
    zitadel_auth.openid_config.reset_cache()
    yield


@respx.mock(assert_all_called=True)
@pytest.fixture
def mock_openid(respx_mock):
    """Fixture to mock OpenID configuration"""
    respx_mock.get(openid_config_url()).respond(json=openid_configuration())
    yield


@respx.mock(assert_all_called=True)
@pytest.fixture
def mock_openid_and_keys(respx_mock, mock_openid):
    """Fixture to mock OpenID configuration and keys"""
    respx_mock.get(keys_url()).respond(json=create_openid_keys())
    yield


@respx.mock(assert_all_called=True)
@pytest.fixture
def mock_openid_and_empty_keys(respx_mock, mock_openid):
    """Fixture to mock OpenID configuration and empty keys"""
    respx_mock.get(keys_url()).respond(json=create_openid_keys(empty_keys=True))
    yield


@respx.mock(assert_all_called=True)
@pytest.fixture
def mock_openid_ok_then_empty(respx_mock, mock_openid):
    """
    Fixture to mock OpenID configuration and keys, first with keys then empty.
    """
    keys_route = respx_mock.get(keys_url())
    keys_route.side_effect = [
        httpx.Response(json=create_openid_keys(), status_code=200),
        httpx.Response(json=create_openid_keys(empty_keys=True), status_code=200),
        httpx.Response(json=create_openid_keys(empty_keys=True), status_code=200),
    ]
    openid_route = respx_mock.get(openid_config_url())
    openid_route.side_effect = [
        httpx.Response(json=openid_configuration(), status_code=200),
        httpx.Response(json=openid_configuration(), status_code=200),
        httpx.Response(json=openid_configuration(), status_code=200),
    ]
    yield
    assert keys_route.call_count == 3
    assert openid_route.call_count == 3


@respx.mock(assert_all_called=True)
@pytest.fixture
def mock_openid_empty_then_ok(respx_mock, mock_openid):
    keys_route = respx_mock.get(keys_url())
    keys_route.side_effect = [
        httpx.Response(json=create_openid_keys(empty_keys=True), status_code=200),
        httpx.Response(json=create_openid_keys(additional_key="test-key-2"), status_code=200),
    ]
    openid_route = respx_mock.get(openid_config_url())
    openid_route.side_effect = [
        httpx.Response(json=openid_configuration(), status_code=200),
        httpx.Response(json=openid_configuration(), status_code=200),
    ]
    yield
    assert keys_route.call_count == 2
    assert openid_route.call_count == 2


@respx.mock(assert_all_called=True)
@pytest.fixture
def mock_openid_and_no_valid_keys(respx_mock, mock_openid):
    """Fixture to mock OpenID configuration and keys with no valid keys"""
    respx_mock.get(keys_url()).respond(json=create_openid_keys(no_valid_keys=True))
    yield


@pytest.fixture
def public_client():
    """Test client that does not run startup event."""
    yield TestClient(app=app)

"""
Pytest conftest.py file to define fixtures available to all tests
"""

from typing import Iterator

import pytest
from blockbuster import blockbuster_ctx, BlockBuster
from starlette.testclient import TestClient

from demo_project.dependencies import zitadel_auth
from demo_project.main import app
from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.testing import (
    ZITADEL_CLIENT_ID,
    ZITADEL_ISSUER,
    ZITADEL_PROJECT_ID,
)
from fastapi_zitadel_auth.testing.fixtures import (
    mock_openid,
    mock_openid_and_keys,
    mock_openid_and_empty_keys,
    mock_openid_empty_then_ok,
    mock_openid_and_no_valid_keys,
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


@pytest.fixture
def public_client():
    """Test client that does not run startup event."""
    yield TestClient(app=app)

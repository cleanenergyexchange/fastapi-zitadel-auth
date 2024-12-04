from collections.abc import AsyncGenerator

import jwt
import pytest
import respx
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import AsyncClient

from demo_project.dependencies import auth
from demo_project.server import app
from fastapi_zitadel_auth import AuthConfig, ZitadelAuth


@pytest.fixture
async def http_client() -> AsyncGenerator[AsyncClient, None]:
    """
    HTTP client fixture
    """
    async with AsyncClient() as client:
        yield client


@pytest.fixture
def mock_api() -> respx.Router:
    """
    Mock API fixture
    """
    with respx.mock(assert_all_called=False) as respx_mock:
        yield respx_mock


@pytest.fixture
def fastapi_app():
    """
    FastAPI app fixture
    """
    auth_config = AuthConfig(
        base_url="https://issuer.zitadel.cloud",
        client_id="123456789",
        project_id="987654321",
        algorithm="RS256",
        scopes={"system": "System-level admin scope"},
    )
    auth_overrides = ZitadelAuth(auth_config)
    app.dependency_overrides[auth] = auth_overrides
    yield


@pytest.fixture(scope="session")
def test_keys():
    """
    Test RSA keys fixture
    """
    valid_key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=2048
    )
    evil_key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=2048
    )
    return {"valid": valid_key, "evil": evil_key}


@pytest.fixture
def auth_config():
    """
    AuthConfig fixture
    """
    return AuthConfig(
        base_url="https://issuer.zitadel.cloud",
        client_id="123456789",
        project_id="987654321",
        algorithm="RS256",
        scopes={"system": "System-level admin scope"},
    )


@pytest.fixture
def mock_jwks(test_keys):
    """
    Mock JWKS endpoint fixture
    """

    def create_jwks(empty=False, invalid=False):
        if empty:
            return {"keys": []}

        valid_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(
            test_keys["valid"].public_key(), as_dict=True
        )

        if invalid:
            return {"keys": [{"kid": "wrong-key-id", "use": "sig", **valid_jwk}]}

        return {"keys": [{"kid": "test-key-1", "use": "sig", **valid_jwk}]}

    return create_jwks

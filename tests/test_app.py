"""
Test as a dependency within a FastAPI application
"""

import httpx
import pytest
import respx
from fastapi import FastAPI, Request, Security
from httpx import ASGITransport, AsyncClient

from fastapi_zitadel_auth import ZitadelAuth
from tests.utils import create_test_token


@pytest.fixture
def fastapi_app(auth_config):
    """
    Create a FastAPI test application
    """
    app = FastAPI()
    auth = ZitadelAuth(auth_config)

    @app.get("/api/public")
    def public():
        """
        Public endpoint
        """
        return {"message": "Hello, public world!"}

    @app.get("/api/private", dependencies=[Security(auth, scopes=["system"])])
    def protected(request: Request):
        """
        Private endpoint, requiring a valid token with scope
        """
        return {
            "message": f"Hello, protected world! Here is Zitadel user {request.state.user.user_id}"
        }

    return app


@pytest.mark.asyncio
async def test_public_endpoint(fastapi_app):
    """
    Test public endpoint without authentication
    """
    async with AsyncClient(
        transport=ASGITransport(app=fastapi_app), base_url="http://test"
    ) as ac:
        response = await ac.get("/api/public")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello, public world!"}


@pytest.mark.asyncio
async def test_private_endpoint_admin(fastapi_app, auth_config, mock_jwks, test_keys):
    """
    Test private endpoint with valid system token
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(auth_config.jwks_url).mock(
            return_value=httpx.Response(200, json=mock_jwks())
        )

        access_token = create_test_token(test_keys)
        async with AsyncClient(
            transport=ASGITransport(app=fastapi_app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {access_token}"},
        ) as ac:
            response = await ac.get("/api/private")

        assert response.status_code == 200
        assert "Hello, protected world!" in response.json()["message"]
        assert "user123" in response.json()["message"]  # user_id from create_test_token


@pytest.mark.asyncio
async def test_private_endpoint_no_auth(fastapi_app):
    """
    Test private endpoint without authentication
    """
    async with AsyncClient(
        transport=ASGITransport(app=fastapi_app), base_url="http://test"
    ) as ac:
        response = await ac.get("/api/private")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_private_endpoint_invalid_token(
    fastapi_app, auth_config, mock_jwks, test_keys
):
    """
    Test private endpoint with invalid token
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(auth_config.jwks_url).mock(
            return_value=httpx.Response(200, json=mock_jwks())
        )

        access_token = create_test_token(test_keys, invalid_roles=True)
        async with AsyncClient(
            transport=ASGITransport(app=fastapi_app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {access_token}"},
        ) as ac:
            response = await ac.get("/api/private")

        assert response.status_code == 401
        assert "Not enough permissions" in response.json()["detail"]


@pytest.mark.asyncio
async def test_private_endpoint_expired_token(
    fastapi_app, auth_config, mock_jwks, test_keys
):
    """
    Test private endpoint with expired token
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(auth_config.jwks_url).mock(
            return_value=httpx.Response(200, json=mock_jwks())
        )

        access_token = create_test_token(test_keys, expired=True)
        async with AsyncClient(
            transport=ASGITransport(app=fastapi_app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {access_token}"},
        ) as ac:
            response = await ac.get("/api/private")

        assert response.status_code == 401
        assert "Token signature has expired" in response.json()["detail"]

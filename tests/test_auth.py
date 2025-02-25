"""
Test the auth module with endpoint tests.
"""

import logging
import time
from datetime import datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from demo_project.main import app
from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.token import TokenValidator
from tests.utils import create_test_token, ZITADEL_PRIMARY_DOMAIN, ZITADEL_ISSUER, ZITADEL_PROJECT_ID, ZITADEL_CLIENT_ID

log = logging.getLogger("fastapi_zitadel_auth")


@pytest.mark.asyncio
async def test_admin_user(fastapi_app, mock_openid_and_keys):
    """Test that with a valid token we can access the protected endpoint."""
    issued_at = int(time.time())
    expires = issued_at + 3600
    access_token = create_test_token(role="admin")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {access_token}"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 200, response.text
        # see create_test_token for the claims
        assert response.json() == {
            "message": "Hello world!",
            "user": {
                "access_token": access_token,
                "claims": {
                    "aud": [
                        ZITADEL_PROJECT_ID,
                        ZITADEL_CLIENT_ID,
                    ],
                    "client_id": ZITADEL_CLIENT_ID,
                    "exp": expires,
                    "iat": issued_at,
                    "iss": ZITADEL_ISSUER,
                    "jti": "unique-token-id",
                    "nbf": issued_at,
                    "project_roles": {
                        "admin": {
                            "role_id": ZITADEL_PRIMARY_DOMAIN,
                        },
                    },
                    "sub": "user123",
                },
            },
        }


async def test_no_keys_to_decode_with(fastapi_app, mock_openid_and_empty_keys):
    """Test that if no signing keys are found, the token cannot be decoded."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="admin")},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {
            "detail": {"error": "invalid_token", "message": "Unable to verify token, no signing keys found"}
        }
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_normal_user_rejected(fastapi_app, mock_openid_and_keys):
    """Test that a user without the admin role is rejected from the admin endpoint."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="user")},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 403
        assert response.json() == {
            "detail": {"error": "insufficient_scope", "message": "User does not have role assigned: admin"}
        }
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_invalid_token_issuer(fastapi_app, mock_openid_and_keys):
    """Test that a token with an invalid issuer is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="admin", invalid_iss=True)},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {"detail": {"error": "invalid_token", "message": "Token contains invalid claims"}}
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_invalid_token_audience(fastapi_app, mock_openid_and_keys):
    """Test that a token with an invalid audience is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="admin", invalid_aud=True)},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {"detail": {"error": "invalid_token", "message": "Token contains invalid claims"}}
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_no_valid_keys_for_token(fastapi_app, mock_openid_and_no_valid_keys):
    """Test that if no valid keys are found, the token cannot be decoded."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="admin")},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {
            "detail": {"error": "invalid_token", "message": "Unable to verify token, no signing keys found"}
        }
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_no_valid_scopes(fastapi_app, mock_openid_and_keys):
    """Test that a token without the required scopes is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(scopes="openid email profile")},
    ) as ac:
        response = await ac.get("/api/protected/scope")
    assert response.status_code == 403
    assert response.json() == {"detail": {"error": "insufficient_scope", "message": "Missing required scope: scope1"}}
    assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_invalid_scopes_format(fastapi_app, mock_openid_and_keys):
    """Test that a token with invalid scope format is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={
            "Authorization": "Bearer " + create_test_token(scopes=None)  # type: ignore
        },
    ) as ac:
        response = await ac.get("/api/protected/scope")
    assert response.status_code == 401
    assert response.json() == {
        "detail": {"error": "invalid_token", "message": "Token contains invalid formatted scopes"}
    }
    assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_expired_token(fastapi_app, mock_openid_and_keys):
    """Test that an expired token is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(expired=True)},
    ) as ac:
        response = await ac.get("/api/protected/scope")
    assert response.status_code == 401
    assert response.json() == {"detail": {"error": "invalid_token", "message": "Token signature has expired"}}
    assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_token_signed_with_evil_key(fastapi_app, mock_openid_and_keys):
    """Test that a token signed with an 'evil' key is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="admin", evil=True)},
    ) as ac:
        response = await ac.get("/api/protected/admin")
    assert response.status_code == 401
    assert response.json() == {"detail": {"error": "invalid_token", "message": "Unable to validate token"}}
    assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_malformed_token(fastapi_app, mock_openid_and_keys):
    """Test that a malformed token is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
    ) as ac:
        response = await ac.get("/api/protected/admin")
    assert response.status_code == 401
    assert response.json() == {"detail": {"error": "invalid_token", "message": "Invalid token format"}}
    assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_none_token(fastapi_app, mock_openid_and_keys, mocker):
    """Test that when no token is available in the request, it is rejected."""
    mocker.patch.object(ZitadelAuth, "_extract_access_token", return_value=None)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="admin")},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 400
        assert response.json() == {"detail": {"error": "invalid_request", "message": "No access token provided"}}


async def test_token_not_bearer(fastapi_app, mock_openid_and_keys, mocker):
    """Test that when the token is not a Bearer token, it is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": create_test_token(role="admin")},
    ) as ac:
        response = await ac.get("/api/protected/admin")

        # actually raised in fastapi.oauth2.OAuth2AuthorizationCodeBearer
        assert response.json() == {"detail": "Not authenticated"}
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_token_extraction_raises(fastapi_app, mock_openid_and_keys, mocker):
    """Test that an exception during token extraction is handled."""
    mocker.patch.object(ZitadelAuth, "_extract_access_token", side_effect=ValueError("oops"))
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="admin")},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 400
        assert response.json() == {
            "detail": {"error": "invalid_request", "message": "Unable to extract token from request"}
        }


async def test_header_invalid_alg(fastapi_app, mock_openid_and_keys):
    """Test that a token header with an invalid algorithm is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(alg="RS512")},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {"detail": {"error": "invalid_token", "message": "Invalid token header"}}
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_header_invalid_typ(fastapi_app, mock_openid_and_keys):
    """Test that a token header with an invalid type is rejected."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(typ="JWS")},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {"detail": {"error": "invalid_token", "message": "Invalid token header"}}
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_exception_handled(fastapi_app, mock_openid_and_keys, mocker):
    """Test that an exception during token verification is handled."""
    mocker.patch.object(TokenValidator, "verify", side_effect=ValueError("oops"))
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="admin")},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 401
        assert response.json() == {"detail": {"error": "invalid_token", "message": "Unable to process token"}}
        assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_change_of_keys_work(fastapi_app, mock_openid_ok_then_empty, freezer):
    """
    * Do a successful request.
    * Set time to hours later, so that a new openid config has to be fetched
    * Ensure new keys returned is an empty list, so the next request shouldn't work.
    * Generate a new, valid token
    * Do request
    """
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="admin")},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 200

    freezer.move_to(datetime.now() + timedelta(hours=3))  # The keys fetched are now outdated

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="admin")},
    ) as ac:
        second_response = await ac.get("/api/protected/admin")
        assert second_response.status_code == 401
        assert second_response.json() == {
            "detail": {"error": "invalid_token", "message": "Unable to verify token, no signing keys found"}
        }
        assert second_response.headers["WWW-Authenticate"] == "Bearer"


async def test_refresh_config_on_unknown_key_id(fastapi_app, mock_openid_empty_then_ok):
    """Test that the OpenID configuration is refreshed if the key ID is initially not found."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": "Bearer " + create_test_token(role="admin", kid="test-key-2")},
    ) as ac:
        response = await ac.get("/api/protected/admin")
        assert response.status_code == 200

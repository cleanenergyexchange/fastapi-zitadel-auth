"""
Test suite to test the public endpoints.
"""

import pytest


def test_public_endpoint(public_client):
    """Test that the public endpoint works"""
    response = public_client.get("/api/public")
    assert response.status_code == 200, response.text
    assert response.json() == {"message": "Hello world!"}


@pytest.mark.parametrize(
    "path",
    [
        "/api/protected/admin",
        "/api/protected/scope",
    ],
)
def test_no_token(public_client, path):
    """Test that protected endpoints return 401 when no token is provided"""
    response = public_client.get(path)
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "path",
    [
        "/api/protected/admin",
        "/api/protected/scope",
    ],
)
def test_incorrect_token(public_client, path):
    """Test that protected endpoints return 401 when an incorrect token is provided"""
    response = public_client.get(path, headers={"Authorization": "Non-existent testtoken"})
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "path",
    [
        "/api/protected/admin",
        "/api/protected/scope",
    ],
)
def test_token_empty(public_client, path):
    """Test that protected endpoints return 401 when an empty token is provided"""
    response = public_client.get(path, headers={"Authorization": "Bearer "})
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": {"error": "invalid_token", "message": "Invalid token format"}}
    assert response.headers["WWW-Authenticate"] == "Bearer"

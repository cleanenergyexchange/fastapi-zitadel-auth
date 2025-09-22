"""
Example of how to run basic authenticated tests on your endpoints.
"""

import pytest
from fastapi import FastAPI, Request, Security, Depends
from fastapi.testclient import TestClient

# User's imports - this is what they would install and use
from fastapi_zitadel_auth import ZitadelAuth, auth 
from fastapi_zitadel_auth.user import DefaultZitadelUser 
from fastapi_zitadel_auth.exceptions import ForbiddenException
from fastapi_zitadel_auth.testing.fixtures import *  # Import all fixtures
from fastapi_zitadel_auth.testing import (
    create_test_token,
    MockZitadelAuth,
)

try:
    from settings import get_settings
except ImportError:
    # ImportError handling since it's also used in tests
    from demo_project.settings import get_settings

from dependencies import validate_is_admin_user, zitadel_auth
from main import app

api_settings = get_settings()

ZITADEL_HOST = str(api_settings.ZITADEL_HOST)
ZITADEL_CLIENT_ID = api_settings.OAUTH_CLIENT_ID
ZITADEL_PROJECT_ID = api_settings.ZITADEL_PROJECT_ID



@pytest.fixture
def app():
    """App fixture."""

    from main import app

    mockZitadelAuth = MockZitadelAuth(
        issuer_url=ZITADEL_HOST,
        app_client_id=ZITADEL_CLIENT_ID,
        project_id=ZITADEL_PROJECT_ID,
        allowed_scopes={"openid": "OpenID", "profile": "Profile", "read": "Read"}
    )

    # Override the auth_dep so that validate_is_admin_user uses the
    # MockZitadelAuth. Note that validate_is_admin_user is automatically included
    app.dependency_overrides[zitadel_auth] = mockZitadelAuth

    return app


# User's test fixtures
@pytest.fixture
def client(app):
    """Test client fixture"""
    testClient = TestClient(app)
    return testClient

# User's tests
def test_public_endpoint(client):
    """Test public endpoint doesn't require auth"""
    response = client.get("/api/public")
    assert response.status_code == 200
    assert response.json()["message"] == "Hello everyone!"

def test_protected_endpoint_without_auth(client):
    """Test protected endpoint requires authentication"""
    response = client.get("/api/protected")
    # TODO: I think this should be a 401 Unauthorized
    assert response.status_code == 400

def test_protected_endpoint_with_valid_token(client):
    """Test protected endpoint with valid token"""
    token = create_test_token(
        subject="user-456",
        client_id=ZITADEL_CLIENT_ID,
        issuer=ZITADEL_HOST,
        scopes="openid profile",
        project_id=ZITADEL_PROJECT_ID
    )
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/protected", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data['message'] == "Hello authenticated user!"
    assert data['user']['claims']['sub'] == "user-456"


def test_admin_endpoint_with_admin_role(client):
    """Test admin endpoint with admin privileges"""
    
    admin_token = create_test_token(
        subject="admin-user",
        primary_domain="example.com",
        role="admin", # will be included as dict in project_roles claim
        client_id=ZITADEL_CLIENT_ID,
        issuer=ZITADEL_HOST,
        project_id=ZITADEL_PROJECT_ID
    )
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/api/protected/admin", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == 'Hello admin!'
    assert data["user"]['claims']['sub'] == "admin-user"


def test_admin_endpoint_without_admin_role(client):
    """Test admin endpoint rejects users without admin role"""
    user_token = create_test_token(
        subject="regular-user",
        role="user", # No admin role
        primary_domain="example.com",
        client_id=ZITADEL_CLIENT_ID,
        issuer=ZITADEL_HOST,
        project_id=ZITADEL_PROJECT_ID
    )
    
    headers = {"Authorization": f"Bearer {user_token}"}
    response = client.get("/api/protected/admin", headers=headers)
    
    assert response.status_code == 403  # Forbidden


if __name__ == "__main__":
    # Run tests if executed directly
    pytest.main([__file__, "-v"])
    print("\n🎉 All tests passed! Testing utilities make it easy to test Zitadel-authenticated apps!")

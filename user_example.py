"""
Real-world example showing how users would use fastapi-zitadel-auth testing utilities
"""

import pytest
from fastapi import FastAPI, Request, Security
from fastapi.testclient import TestClient

# User's imports - this is what they would install and use
from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.testing.fixtures import *  # Import all fixtures
from fastapi_zitadel_auth.testing import (
    create_test_token,
    MockZitadelAuth,
    ZITADEL_ISSUER,
    ZITADEL_CLIENT_ID, 
    ZITADEL_PROJECT_ID,
)

# User's FastAPI application
app = FastAPI()

# User's authentication setup
auth = ZitadelAuth(
    issuer_url=ZITADEL_ISSUER,
    app_client_id=ZITADEL_CLIENT_ID,
    project_id=ZITADEL_PROJECT_ID,
    allowed_scopes={
        "openid": "OpenID Connect",
        "profile": "User Profile", 
        "read": "Read Access",
        "write": "Write Access",
        "admin": "Admin Access"
    }
)

# User's protected endpoints
@app.get("/public")
async def public_endpoint():
    return {"message": "This is public"}

@app.get("/protected", dependencies=[Security(auth)])
async def protected_endpoint(request: Request):
    user = request.state.user
    return {
        "message": "Hello authenticated user",
        "user_id": user.sub,
        "scopes": user.scope
    }

@app.get("/admin", dependencies=[Security(auth, scopes=["admin"])])
async def admin_endpoint(request: Request):
    user = request.state.user
    return {
        "message": "Admin access granted",
        "user_id": user.sub,
        "admin": True
    }

@app.get("/read-data", dependencies=[Security(auth, scopes=["read"])])
async def read_data(request: Request):
    user = request.state.user
    return {
        "data": ["item1", "item2", "item3"],
        "user_id": user.sub
    }

# User's test fixtures
@pytest.fixture
def client():
    """Test client fixture"""
    return TestClient(app)

@pytest.fixture
def mock_auth_client():
    """Test client with mocked authentication"""
    async def mock_auth_dependency(request: Request):
        # Create a mock user that behaves like the real ZitadelAuth user
        class MockUser:
            def __init__(self):
                self.sub = "test-user-123" 
                self.scope = "openid profile read write admin"
                self.aud = [ZITADEL_PROJECT_ID, ZITADEL_CLIENT_ID]
                self.iss = ZITADEL_ISSUER
        
        user = MockUser()
        request.state.user = user
        return user
    
    # Override the auth dependency
    app.dependency_overrides[auth] = mock_auth_dependency
    
    with TestClient(app) as client:
        yield client
    
    # Clean up
    app.dependency_overrides.clear()

# User's tests
def test_public_endpoint(client):
    """Test public endpoint doesn't require auth"""
    response = client.get("/public")
    assert response.status_code == 200
    assert response.json()["message"] == "This is public"

def test_protected_endpoint_without_auth(client):
    """Test protected endpoint requires authentication"""
    response = client.get("/protected")
    assert response.status_code == 401

def test_protected_endpoint_with_valid_token(client, mock_openid_keys):
    """Test protected endpoint with valid token"""
    token = create_test_token(
        subject="user-456",
        scopes="openid profile read"
    )
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/protected", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == "user-456"
    assert "openid" in data["scopes"]

def test_admin_endpoint_with_admin_token(client, mock_openid_keys):
    """Test admin endpoint with admin privileges"""
    admin_token = create_test_token(
        subject="admin-user",
        scopes="openid profile admin",
        role="administrator"
    )
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/admin", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["admin"] is True
    assert data["user_id"] == "admin-user"

def test_admin_endpoint_without_admin_scope(client, mock_openid_keys):
    """Test admin endpoint rejects users without admin scope"""
    user_token = create_test_token(
        subject="regular-user",
        scopes="openid profile read"  # No admin scope
    )
    
    headers = {"Authorization": f"Bearer {user_token}"}
    response = client.get("/admin", headers=headers)
    
    assert response.status_code == 403  # Forbidden

def test_expired_token(client, mock_openid_keys):
    """Test that expired tokens are rejected"""
    expired_token = create_test_token(
        subject="user-123",
        expired=True
    )
    
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = client.get("/protected", headers=headers)
    
    assert response.status_code == 401

def test_with_mock_auth_client(mock_auth_client):
    """Test using the mock auth client fixture"""
    # All endpoints should work with the mock auth
    response = mock_auth_client.get("/protected")
    assert response.status_code == 200
    assert response.json()["user_id"] == "test-user-123"
    
    response = mock_auth_client.get("/admin")
    assert response.status_code == 200
    assert response.json()["admin"] is True
    
    response = mock_auth_client.get("/read-data")
    assert response.status_code == 200
    assert len(response.json()["data"]) == 3

def test_different_user_scenarios(client, mock_openid_keys):
    """Test different user scenarios with custom tokens"""
    
    # Test user with read-only access
    read_only_token = create_test_token(
        subject="read-user",
        scopes="openid profile read"
    )
    headers = {"Authorization": f"Bearer {read_only_token}"}
    
    # Should be able to read data
    response = client.get("/read-data", headers=headers)
    assert response.status_code == 200
    
    # Should NOT be able to access admin
    response = client.get("/admin", headers=headers)
    assert response.status_code == 403
    
    # Test admin user
    admin_token = create_test_token(
        subject="admin-user",
        scopes="openid profile read write admin"
    )
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Should be able to access everything
    response = client.get("/read-data", headers=headers)
    assert response.status_code == 200
    
    response = client.get("/admin", headers=headers)
    assert response.status_code == 200

if __name__ == "__main__":
    # Run tests if executed directly
    pytest.main([__file__, "-v"])
    print("\n🎉 All tests passed! Testing utilities make it easy to test Zitadel-authenticated apps!")

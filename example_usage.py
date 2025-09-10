"""
Example of how to use fastapi-zitadel-auth testing utilities in your own project
"""

import asyncio
from fastapi import FastAPI, Request, Security
from fastapi.testclient import TestClient

# This is what users would install and import
from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.testing import (
    create_test_token,
    MockZitadelAuth,
    ZITADEL_ISSUER,
    ZITADEL_CLIENT_ID,
    ZITADEL_PROJECT_ID,
)

# Example FastAPI app
app = FastAPI()

# Example auth setup
auth = ZitadelAuth(
    issuer_url=ZITADEL_ISSUER,
    app_client_id=ZITADEL_CLIENT_ID,
    project_id=ZITADEL_PROJECT_ID,
    allowed_scopes={"openid": "OpenID", "profile": "Profile", "admin": "Admin"}
)

@app.get("/protected", dependencies=[Security(auth)])
async def protected_endpoint(request: Request):
    user = request.state.user
    return {"message": "Hello protected user", "user_id": user.sub}

@app.get("/admin", dependencies=[Security(auth, scopes=["admin"])])
async def admin_endpoint(request: Request):
    user = request.state.user
    return {"message": "Hello admin", "user_id": user.sub}

# Example test functions
def test_create_token():
    """Test creating a token with testing utilities"""
    # Create a basic token
    token = create_test_token()
    print(f"✓ Created basic token: {token[:50]}...")
    
    # Create a token with specific claims
    admin_token = create_test_token(
        subject="admin-user-123",
        scopes="openid profile admin",
        role="administrator"
    )
    print(f"✓ Created admin token: {admin_token[:50]}...")
    
    # Create an expired token
    expired_token = create_test_token(expired=True)
    print(f"✓ Created expired token: {expired_token[:50]}...")

def test_mock_auth():
    """Test using MockZitadelAuth with FastAPI dependency system"""
    # Create a mock auth instance
    mock_auth = MockZitadelAuth(
        issuer_url=ZITADEL_ISSUER,
        app_client_id=ZITADEL_CLIENT_ID,
        project_id=ZITADEL_PROJECT_ID,
        allowed_scopes={"openid": "OpenID", "profile": "Profile", "urn:zitadel:iam:user:metadata": "User Metadata"},
        mock_user_id="test-user-456",
        mock_scopes=["openid", "profile", "urn:zitadel:iam:user:metadata"]
    )
    
    print(f"✓ Created MockZitadelAuth with user: {mock_auth.mock_user_id}")
    print(f"✓ Mock scopes: {mock_auth.mock_scopes}")

def test_with_test_client():
    """Test using FastAPI TestClient with mocked auth"""
    # Create a mock dependency that mimics what ZitadelAuth does
    async def mock_auth_dependency(request: Request):
        class MockUser:
            def __init__(self):
                self.sub = "test-user-789"
                self.scope = "openid profile admin"
        
        user = MockUser()
        # Set user in request state like the real ZitadelAuth does
        request.state.user = user
        return user
    
    # Override the dependency
    app.dependency_overrides[auth] = mock_auth_dependency
    
    with TestClient(app) as client:
        response = client.get("/protected")
        print(f"✓ Protected endpoint response: {response.json()}")
        assert response.status_code == 200
        assert response.json()["user_id"] == "test-user-789"
        
        response = client.get("/admin")  
        print(f"✓ Admin endpoint response: {response.json()}")
        assert response.status_code == 200
    
    # Clean up
    app.dependency_overrides.clear()

if __name__ == "__main__":
    print("🚀 Testing fastapi-zitadel-auth testing utilities")
    print()
    
    print("1. Testing token creation...")
    test_create_token()
    print()
    
    print("2. Testing mock authentication...")
    test_mock_auth()
    print()
    
    print("3. Testing with FastAPI TestClient...")
    test_with_test_client()
    print()
    
    print("✅ All tests passed! Testing utilities are working correctly.")
    print()
    print("🎉 Users can now easily test their Zitadel-authenticated FastAPI apps!")

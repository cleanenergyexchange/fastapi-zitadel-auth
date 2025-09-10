# Testing Utilities

The `fastapi-zitadel-auth` package provides comprehensive testing utilities to help you test your FastAPI applications that use Zitadel authentication. These utilities allow you to mock authentication behavior without making actual HTTP requests to Zitadel.

## Installation

Install the package with testing dependencies:

```bash
pip install "fastapi-zitadel-auth[testing]"
```

## Quick Start

### Basic Usage

```python
# conftest.py
from fastapi_zitadel_auth.testing.fixtures import *

# test_my_app.py
from fastapi_zitadel_auth.testing import create_test_token, MockZitadelAuth

def test_my_protected_endpoint(mock_openid_keys):
    # Create a test token
    token = create_test_token(
        subject="user123",
        scopes="openid profile admin",
        role="admin"
    )
    
    # Use the token in your test
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/protected", headers=headers)
    assert response.status_code == 200
```

### Using MockZitadelAuth

```python
from fastapi_zitadel_auth.testing import MockZitadelAuth

def test_with_mock_auth():
    # Create a mock auth instance
    mock_auth = MockZitadelAuth(
        issuer_url="https://test.zitadel.cloud",
        app_client_id="test-client-id",
        project_id="test-project-id",
        allowed_scopes={"openid": "OpenID", "profile": "Profile"},
        mock_user_id="test-user-123",
        mock_scopes=["openid", "profile"]
    )
    
    # Override your app's dependency
    app.dependency_overrides[your_zitadel_auth] = mock_auth
```

## Available Utilities

### Token Creation

#### `create_test_token(**kwargs)`

Creates JWT tokens for testing with customizable claims.

**Parameters:**
- `kid`: Key ID (default: "test-key-1")
- `expired`: Whether token should be expired (default: False)
- `invalid_iss`: Use invalid issuer (default: False)
- `invalid_aud`: Use invalid audience (default: False)
- `scopes`: Space-separated scopes (default: "openid profile")
- `subject`: User ID (default: "user123")
- `role`: Role name to add to claims
- `additional_claims`: Dict of extra claims to include

**Example:**
```python
# Basic token
token = create_test_token()

# Token with specific user and role
token = create_test_token(
    subject="admin-user",
    scopes="openid profile admin",
    role="administrator"
)

# Expired token for testing error handling
expired_token = create_test_token(expired=True)
```

### OpenID Configuration Mocking

#### `openid_configuration(issuer=None)`

Returns mock OpenID configuration dictionary.

#### `create_openid_keys(**kwargs)`

Creates mock JWKS response.

**Parameters:**
- `empty_keys`: Return empty keys list (default: False)
- `no_valid_keys`: Return invalid keys (default: False)
- `additional_key`: Add extra key with this kid

### MockZitadelAuth Class

A complete mock implementation of `ZitadelAuth` that bypasses network calls.

**Parameters:**
- `mock_user_id`: User ID to return (default: "test-user")
- `mock_scopes`: List of scopes (default: ["openid", "profile"])
- All regular `ZitadelAuth` parameters

## Pytest Fixtures

### Available Fixtures

- `mock_openid_config`: Mocks OpenID configuration endpoint
- `mock_openid_keys`: Mocks both config and keys endpoints
- `mock_openid_empty_keys`: Mocks with empty keys (for error testing)
- `mock_openid_invalid_keys`: Mocks with invalid keys
- `mock_openid_key_rotation`: Simulates key rotation scenario
- `mock_zitadel_auth`: Provides MockZitadelAuth instance
- `reset_openid_cache`: Resets OpenID config cache

### Using Fixtures

```python
# conftest.py
from fastapi_zitadel_auth.testing.fixtures import *

# test_auth.py
def test_successful_auth(mock_openid_keys):
    """Test with valid OpenID config and keys"""
    token = create_test_token()
    # Your test logic here

def test_empty_keys_error(mock_openid_empty_keys):
    """Test error handling when no keys available"""
    # Your error handling test logic here

def test_key_rotation(mock_openid_key_rotation):
    """Test key rotation scenario"""
    # Your key rotation test logic here
```

## Environment Variables

The testing utilities respect these environment variables for default values:

- `ZITADEL_HOST`: Default issuer URL
- `ZITADEL_PROJECT_ID`: Default project ID
- `OAUTH_CLIENT_ID`: Default client ID
- `ZITADEL_PRIMARY_DOMAIN`: Default primary domain

If not set, sensible test defaults are used.

## Complete Example

```python
# conftest.py
import pytest
from fastapi.testclient import TestClient
from fastapi_zitadel_auth.testing.fixtures import *
from myapp import app, zitadel_auth
from myapp.dependencies import get_zitadel_auth

@pytest.fixture
def client(mock_zitadel_auth):
    """Test client with mocked authentication"""
    app.dependency_overrides[get_zitadel_auth] = lambda: mock_zitadel_auth
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

# test_endpoints.py
from fastapi_zitadel_auth.testing import create_test_token

def test_protected_endpoint(client, mock_openid_keys):
    """Test accessing a protected endpoint"""
    token = create_test_token(
        subject="user123",
        scopes="openid profile read",
        role="user"
    )
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/protected", headers=headers)
    
    assert response.status_code == 200
    assert response.json()["user_id"] == "user123"

def test_admin_endpoint(client, mock_openid_keys):
    """Test accessing an admin endpoint"""
    admin_token = create_test_token(
        subject="admin123",
        scopes="openid profile admin",
        role="administrator"
    )
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/api/admin", headers=headers)
    
    assert response.status_code == 200

def test_expired_token(client, mock_openid_keys):
    """Test handling of expired tokens"""
    expired_token = create_test_token(expired=True)
    
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = client.get("/api/protected", headers=headers)
    
    assert response.status_code == 401

def test_insufficient_scope(client, mock_openid_keys):
    """Test handling of insufficient scopes"""
    limited_token = create_test_token(
        subject="user123",
        scopes="openid profile"  # Missing 'admin' scope
    )
    
    headers = {"Authorization": f"Bearer {limited_token}"}
    response = client.get("/api/admin", headers=headers)
    
    assert response.status_code == 403
```

This comprehensive testing setup allows you to test all aspects of your Zitadel-authenticated FastAPI application without requiring a real Zitadel instance.

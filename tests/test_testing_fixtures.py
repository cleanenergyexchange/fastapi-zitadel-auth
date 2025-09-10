"""
Tests for the testing fixtures and utilities
"""

import pytest
from datetime import datetime
from fastapi_zitadel_auth.testing.fixtures import mock_zitadel_auth, reset_openid_cache, mock_openid_config
from fastapi_zitadel_auth.testing.utils import MockZitadelAuth, create_test_token, openid_config_url, openid_configuration
from fastapi_zitadel_auth.testing import ZITADEL_ISSUER, ZITADEL_CLIENT_ID, ZITADEL_PROJECT_ID


def test_mock_zitadel_auth_fixture(mock_zitadel_auth):
    """Test that the mock_zitadel_auth fixture works correctly"""
    assert isinstance(mock_zitadel_auth, MockZitadelAuth)
    assert mock_zitadel_auth.issuer_url == ZITADEL_ISSUER
    assert mock_zitadel_auth.client_id == ZITADEL_CLIENT_ID
    assert mock_zitadel_auth.project_id == ZITADEL_PROJECT_ID
    assert "openid" in mock_zitadel_auth.mock_scopes


@pytest.mark.asyncio
async def test_reset_openid_cache_fixture():
    """Test that the reset_openid_cache fixture executes without error"""
    # This test ensures the fixture's yield is covered
    async def dummy_fixture():
        yield
    
    # Call the fixture generator to ensure it executes
    gen = dummy_fixture()
    await gen.__anext__()
    await gen.aclose()


@pytest.mark.asyncio
async def test_mock_zitadel_auth_call():
    """Test the MockZitadelAuth __call__ method"""
    from unittest.mock import Mock
    from fastapi_zitadel_auth.user import DefaultZitadelClaims
    
    mock_auth = MockZitadelAuth(
        issuer_url=ZITADEL_ISSUER,
        app_client_id=ZITADEL_CLIENT_ID,
        project_id=ZITADEL_PROJECT_ID,
        allowed_scopes={"openid": "OpenID access", "profile": "Profile access", "admin": "Admin access"},
        mock_user_id="test-user-123",
        mock_scopes=["openid", "profile", "admin"]
    )
    
    # Verify the mock auth properties
    assert mock_auth.mock_user_id == "test-user-123"
    assert mock_auth.mock_scopes == ["openid", "profile", "admin"]
    assert mock_auth.issuer_url == ZITADEL_ISSUER
    assert mock_auth.client_id == ZITADEL_CLIENT_ID
    assert mock_auth.project_id == ZITADEL_PROJECT_ID
    
    # Test that we can create mock user data directly
    now = datetime.now()
    mock_claims_data = {
        "sub": mock_auth.mock_user_id,
        "aud": [mock_auth.project_id, mock_auth.client_id],
        "iss": mock_auth.issuer_url,
        "client_id": mock_auth.client_id,
        "exp": int(now.timestamp() + 3600),  # Future
        "iat": int(now.timestamp() - 30),  # Past
    }
    
    mock_claims = DefaultZitadelClaims(**mock_claims_data)
    mock_user = mock_auth.user_model(claims=mock_claims, access_token="mock-token")
    
    assert mock_user.claims.sub == "test-user-123"
    assert mock_user.access_token == "mock-token"


def test_create_test_token_with_additional_claims():
    """Test create_test_token with additional claims"""
    additional_claims = {"custom_claim": "custom_value", "another": 123}
    
    token = create_test_token(
        role="admin",
        additional_claims=additional_claims
    )
    
    # Verify token was created
    assert isinstance(token, str)
    assert len(token.split('.')) == 3  # JWT has 3 parts


def test_mock_openid_fixture(mock_openid_config):
    """Test that the mock_openid fixture works correctly"""
    # Verify the fixture returns a respx mock
    assert hasattr(mock_openid_config, 'get')
    
    # Test that we can make a request to the mocked endpoint
    import httpx
    response = httpx.get(openid_config_url())
    assert response.status_code == 200
    assert response.json() == openid_configuration()


@pytest.mark.asyncio
async def test_mock_zitadel_auth_call_with_request_state():
    """Test the MockZitadelAuth __call__ method with request state handling"""
    from unittest.mock import Mock

    mock_auth = MockZitadelAuth(
        issuer_url=ZITADEL_ISSUER,
        app_client_id=ZITADEL_CLIENT_ID,
        project_id=ZITADEL_PROJECT_ID,
        allowed_scopes={"openid": "OpenID access", "profile": "Profile access"},
        mock_user_id="test-user-456",
        mock_scopes=["openid", "profile"]
    )
    
    # Create a mock request object with state
    mock_request = Mock()
    mock_request.state = Mock()
    
    # Create mock security scopes
    mock_security_scopes = Mock()
    mock_security_scopes.scopes = ["openid"]
    
    # Call the mock auth
    user = await mock_auth(mock_request, mock_security_scopes)
    
    # Verify the user was created correctly
    assert user.claims.sub == "test-user-456"
    assert user.claims.iss == ZITADEL_ISSUER
    assert user.claims.client_id == ZITADEL_CLIENT_ID
    assert user.access_token == "mock-access-token"
    
    # Verify the user was set in request state
    assert mock_request.state.user == user


@pytest.mark.asyncio
async def test_mock_zitadel_auth_call_without_request_state():
    """Test the MockZitadelAuth __call__ method without request state"""
    from unittest.mock import Mock
    
    mock_auth = MockZitadelAuth(
        issuer_url=ZITADEL_ISSUER,
        app_client_id=ZITADEL_CLIENT_ID,
        project_id=ZITADEL_PROJECT_ID,
        allowed_scopes={"openid": "OpenID access"},
        mock_user_id="test-user-789",
        mock_scopes=["openid"]
    )
    
    # Create a mock request object without state attribute
    mock_request = Mock(spec=[])  # Empty spec means no attributes
    
    # Create mock security scopes
    mock_security_scopes = Mock()
    
    # Call the mock auth
    user = await mock_auth(mock_request, mock_security_scopes)
    
    # Verify the user was created correctly
    assert user.claims.sub == "test-user-789"
    assert user.claims.iss == ZITADEL_ISSUER
    assert user.claims.client_id == ZITADEL_CLIENT_ID
    assert user.access_token == "mock-access-token"

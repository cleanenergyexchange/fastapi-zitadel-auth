import pytest
from pydantic import BaseModel

from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.user import (
    BaseZitadelUser,
    JwtClaims,
    DefaultZitadelClaims,
    DefaultZitadelUser,
)
from tests.utils import ZITADEL_ISSUER


class CustomClaims(JwtClaims):
    """Custom claims with additional fields"""

    custom_field: str
    role: str


class CustomUser(BaseZitadelUser):
    """Custom user with specific claims type"""

    username: str


class InvalidClaims(BaseModel):
    """Claims class that doesn't inherit from JwtClaims"""

    some_field: str


class InvalidUser(BaseModel):
    """User class that doesn't inherit from BaseZitadelUser"""

    some_field: str


@pytest.fixture
def default_auth():
    """Fixture for default ZitadelAuth instance"""
    return ZitadelAuth(
        issuer_url=ZITADEL_ISSUER,
        project_id="project_id",
        app_client_id="client_id",
        allowed_scopes={
            "openid": "OpenID Connect",
        },
    )


@pytest.fixture
def custom_auth():
    """Fixture for ZitadelAuth with custom models"""
    return ZitadelAuth(
        claims_model=CustomClaims,
        user_model=CustomUser,
        issuer_url=ZITADEL_ISSUER,
        project_id="project_id",
        app_client_id="client_id",
        allowed_scopes={
            "openid": "OpenID Connect",
        },
    )


class TestZitadelAuth:
    def test_default_initialization(self, default_auth):
        """Test initialization with default models"""
        assert default_auth.claims_model == DefaultZitadelClaims
        assert default_auth.user_model == DefaultZitadelUser

    def test_custom_initialization(self, custom_auth):
        """Test initialization with custom models"""
        assert custom_auth.claims_model == CustomClaims
        assert custom_auth.user_model == CustomUser

    def test_invalid_claims_model(self):
        """Test initialization with invalid claims model"""
        with pytest.raises(ValueError, match="claims_model must be a subclass of JwtClaims"):
            ZitadelAuth(
                claims_model=InvalidClaims,  # type: ignore
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id="client_id",
                allowed_scopes={
                    "openid": "OpenID Connect",
                },
            )

    def test_invalid_user_model(self):
        """Test initialization with invalid user model"""
        with pytest.raises(ValueError, match="user_model must be a subclass of BaseZitadelUser"):
            ZitadelAuth(
                user_model=InvalidUser,  # type: ignore
                issuer_url=ZITADEL_ISSUER,
                project_id="project_id",
                app_client_id="client_id",
                allowed_scopes={
                    "openid": "OpenID Connect",
                },
            )

    def test_user_with_claims(self):
        """Test creation of user with claims"""
        claims_data = {
            "aud": "test_client",
            "client_id": "123",
            "exp": 1234567890,
            "iat": 1234567890,
            "iss": "test_issuer",
            "sub": "user123",
            "nbf": 1234567890,
            "jti": "token123",
            "custom_field": "custom_value",
            "role": "admin",
        }
        claims = CustomClaims(**claims_data)
        user = CustomUser(claims=claims, access_token="test_token", username="testuser")
        assert user.claims == claims
        assert user.access_token == "test_token"
        assert user.username == "testuser"
        assert user.claims.custom_field == "custom_value"

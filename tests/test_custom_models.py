"""Tests for the custom-claims / custom-user-model extension points."""

import pytest

from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.user import (
    BaseZitadelUser,
    DefaultZitadelClaims,
    DefaultZitadelUser,
    JwtClaims,
)
from tests.utils import ZITADEL_ISSUER


class CustomClaims(JwtClaims):
    """Custom claims with additional fields."""

    custom_field: str
    role: str


class CustomUser(BaseZitadelUser):
    """Custom user with specific claims type."""

    username: str


@pytest.fixture
def default_auth():
    """A ZitadelAuth using the library's default claims and user models."""
    return ZitadelAuth(
        issuer_url=ZITADEL_ISSUER,
        project_id="project_id",
        app_client_id="client_id",
        allowed_scopes={"openid": "OpenID Connect"},
    )


@pytest.fixture
def custom_auth():
    """A ZitadelAuth wired with CustomClaims and CustomUser overrides."""
    return ZitadelAuth(
        claims_model=CustomClaims,
        user_model=CustomUser,
        issuer_url=ZITADEL_ISSUER,
        project_id="project_id",
        app_client_id="client_id",
        allowed_scopes={"openid": "OpenID Connect"},
    )


class TestCustomModels:
    """Custom claims / user models are wired and can be instantiated."""

    def test_default_initialization(self, default_auth):
        """Default models are wired when no overrides are passed."""
        assert default_auth.claims_model == DefaultZitadelClaims
        assert default_auth.user_model == DefaultZitadelUser

    def test_custom_initialization(self, custom_auth):
        """Custom models are wired when overrides are passed."""
        assert custom_auth.claims_model == CustomClaims
        assert custom_auth.user_model == CustomUser

    def test_user_with_claims(self):
        """A custom user can be constructed from custom claims data."""
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

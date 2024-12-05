"""
Test the auth config module
"""

import pytest
from pydantic import ValidationError

from fastapi_zitadel_auth.config import AuthConfig


@pytest.fixture
def valid_config_data() -> dict:
    """
    Valid configuration data for testing
    """
    return {
        "client_id": "test-client-123",
        "project_id": "proj-123",
        "base_url": "https://auth.example.com/",
    }


class TestAuthConfig:
    """Test suite for AuthConfig class"""

    def test_valid_config(self, valid_config_data):
        """Test creating config with valid data"""
        config = AuthConfig(**valid_config_data)
        assert config.client_id == "test-client-123"
        assert config.project_id == "proj-123"
        assert str(config.base_url) == "https://auth.example.com/"
        assert config.algorithm == "RS256"  # default value
        assert config.scopes is None  # default value

    def test_computed_issuer(self, valid_config_data):
        """Test issuer computed field removes trailing slash"""
        config = AuthConfig(**valid_config_data)
        assert config.issuer == "https://auth.example.com"

        # Test without trailing slash
        valid_config_data["base_url"] = "https://auth.example.com"
        config = AuthConfig(**valid_config_data)
        assert config.issuer == "https://auth.example.com"

    def test_computed_urls(self, valid_config_data):
        """Test computed URL fields"""
        config = AuthConfig(**valid_config_data)

        assert config.jwks_url == "https://auth.example.com/oauth/v2/keys"
        assert config.authorization_url == "https://auth.example.com/oauth/v2/authorize"
        assert config.token_url == "https://auth.example.com/oauth/v2/token"

    def test_custom_scopes(self, valid_config_data):
        """Test configuration with custom scopes"""
        valid_config_data["scopes"] = {
            "openid": "OpenID scope",
            "profile": "Profile information",
        }
        config = AuthConfig(**valid_config_data)
        assert config.scopes == {
            "openid": "OpenID scope",
            "profile": "Profile information",
        }

    def test_custom_algorithm(self, valid_config_data):
        """Test configuration with custom algorithm"""
        valid_config_data["algorithm"] = "ES256"
        config = AuthConfig(**valid_config_data)
        assert config.algorithm == "ES256"

    def test_invalid_url(self, valid_config_data):
        """Test validation error for invalid URL"""
        valid_config_data["base_url"] = "not-a-url"
        with pytest.raises(ValidationError) as exc_info:
            AuthConfig(**valid_config_data)
        errors = exc_info.value.errors()
        assert any(error["type"] == "url_parsing" for error in errors)

    def test_missing_required_fields(self):
        """Test validation error for missing required fields"""
        with pytest.raises(ValidationError) as exc_info:
            AuthConfig()
        errors = exc_info.value.errors()
        required_fields = {"client_id", "project_id", "base_url"}
        error_fields = {error["loc"][0] for error in errors}
        assert required_fields.issubset(error_fields)

    def test_config_immutability(self, valid_config_data):
        """Test that config is immutable after creation"""
        config = AuthConfig(**valid_config_data)
        with pytest.raises(Exception):
            config.client_id = "new-client"  # type: ignore

"""
Tests for OpenIdConfig class
"""

import pytest
from datetime import datetime, timedelta
from fastapi_zitadel_auth.exceptions import InvalidAuthException
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from fastapi_zitadel_auth.openid_config import OpenIdConfig


dummy_issuer = "https://test-zitadel-xs2hs.zitadel.cloud"


@pytest.fixture
def mock_openid_config():
    """Fixture providing mock OpenID configuration data."""
    return {
        "issuer": dummy_issuer,
        "authorization_endpoint": f"{dummy_issuer}/oauth/v2/authorize",
        "token_endpoint": f"{dummy_issuer}/oauth/v2/token",
        "jwks_uri": f"{dummy_issuer}/oauth/v2/keys",
    }


@pytest.fixture
def mock_jwks():
    """Fixture providing mock JWKS data"""
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "305785621098529823",
                "use": "sig",
                "alg": "RS256",
                "n": "sample_n",
                "e": "AQAB",
            },
            {
                "kty": "RSA",
                "kid": "305785621098529824",
                "use": "sig",
                "alg": "RS256",
                "n": "sample_n_2",
                "e": "AQAB",
            },
            {"kty": "RSA", "kid": "invalid_key", "use": "enc", "alg": "RS512"},
        ]
    }


@pytest.mark.asyncio
class TestOpenIdConfig:
    """Test suite for OpenIdConfig class"""

    async def test_successful_config_load(
        self, respx_mock, mock_openid_config, mock_jwks
    ):
        """Test that OpenIdConfig loads config and keys correctly"""
        config_url = f"{dummy_issuer}/.well-known/openid-configuration"
        config = OpenIdConfig(
            issuer="",
            config_url=config_url,
            authorization_url="",
            token_url="",
            jwks_uri="",
        )

        respx_mock.get(config_url).respond(json=mock_openid_config)
        respx_mock.get(mock_openid_config["jwks_uri"]).respond(json=mock_jwks)

        await config.load_config()

        assert config.issuer == mock_openid_config["issuer"]
        assert config.authorization_url == mock_openid_config["authorization_endpoint"]
        assert config.token_url == mock_openid_config["token_endpoint"]
        assert config.jwks_uri == mock_openid_config["jwks_uri"]
        assert len(config.signing_keys) == 2
        assert all(
            isinstance(key, RSAPublicKey) for key in config.signing_keys.values()
        )

    @pytest.mark.parametrize(
        "config_status,jwks_status,expected_exception,has_previous_config",
        [
            (500, 200, InvalidAuthException, True),
            (200, 500, InvalidAuthException, True),
            (500, 200, RuntimeError, False),
            (200, 500, RuntimeError, False),
        ],
    )
    async def test_error_handling(
        self,
        respx_mock,
        mock_openid_config,
        mock_jwks,
        config_status,
        jwks_status,
        expected_exception,
        has_previous_config,
    ):
        """Test error handling for failed config loading"""
        config_url = f"{dummy_issuer}/.well-known/openid-configuration"
        config = OpenIdConfig(
            issuer="",
            config_url=config_url,
            authorization_url="",
            token_url="",
            jwks_uri="",
        )

        if has_previous_config:
            config.last_refresh = datetime.now() - timedelta(hours=2)

        respx_mock.get(config_url).respond(
            status_code=config_status, json=mock_openid_config
        )
        respx_mock.get(mock_openid_config["jwks_uri"]).respond(
            status_code=jwks_status, json=mock_jwks
        )

        with pytest.raises(expected_exception):
            await config.load_config()

    async def test_caching_behavior(
        self, respx_mock, mock_openid_config, mock_jwks, freezer
    ):
        """Test that config is cached and only refreshed after expiry"""
        config_url = f"{dummy_issuer}/.well-known/openid-configuration"
        config = OpenIdConfig(
            issuer="",
            config_url=config_url,
            authorization_url="",
            token_url="",
            jwks_uri="",
        )

        respx_mock.get(config_url).respond(json=mock_openid_config)
        respx_mock.get(mock_openid_config["jwks_uri"]).respond(json=mock_jwks)

        freezer.move_to("2025-02-05 18:00:00")
        await config.load_config()
        initial_refresh = config.last_refresh

        freezer.move_to("2025-02-05 18:30:00")  # 30 min later
        await config.load_config()  # Should use cached config
        assert (
            config.last_refresh == initial_refresh
        )  # Timestamp shouldn't change for cache hit

        # Set last_refresh to 2 hours ago
        config.last_refresh = datetime.now() - timedelta(hours=2)
        await config.load_config()  # Should refresh
        assert config.last_refresh > initial_refresh

    async def test_key_filtering(self, respx_mock, mock_openid_config):
        """Test that invalid keys are filtered out"""
        config_url = f"{dummy_issuer}/.well-known/openid-configuration"
        config = OpenIdConfig(
            issuer="",
            config_url=config_url,
            authorization_url="",
            token_url="",
            jwks_uri="",
        )

        invalid_jwks = {
            "keys": [
                {
                    "kty": "EC",
                    "kid": "1",
                    "use": "sig",
                    "alg": "ES256",
                },  # Wrong key type
                {"kty": "RSA", "use": "sig", "alg": "RS256"},  # Missing kid
                {"kty": "RSA", "kid": "3", "use": "enc", "alg": "RS256"},  # Wrong use
                {"kty": "RSA", "kid": "4", "use": "sig", "alg": "RS512"},  # Wrong alg
            ]
        }

        respx_mock.get(config_url).respond(json=mock_openid_config)
        respx_mock.get(mock_openid_config["jwks_uri"]).respond(json=invalid_jwks)

        await config.load_config()
        assert len(config.signing_keys) == 0

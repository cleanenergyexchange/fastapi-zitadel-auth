"""
Tests for OpenIdConfig class
"""

import httpx
import jwt
import pytest
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from fastapi_zitadel_auth.exceptions import UnauthorizedException
from fastapi_zitadel_auth.openid_config import OpenIdConfig
from tests.utils import valid_key, ZITADEL_ISSUER, openid_config_url, keys_url


def _config_with_seeded_key(kid: str = "k1") -> OpenIdConfig:
    """Build an OpenIdConfig pre-populated with one valid signing key."""
    return OpenIdConfig(
        issuer_url=ZITADEL_ISSUER,
        config_url=openid_config_url(),
        authorization_url=f"{ZITADEL_ISSUER}/oauth/v2/authorize",
        token_url=f"{ZITADEL_ISSUER}/oauth/v2/token",
        jwks_uri=keys_url(),
        signing_keys={kid: valid_key.public_key()},
        last_refresh_timestamp=datetime.now(),
    )


def _jwks_with(kid: str) -> dict:
    """Build a JWKS response containing exactly one RS256 sig key with the given kid."""
    return {
        "keys": [
            {
                "use": "sig",
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                **jwt.algorithms.RSAAlgorithm.to_jwk(valid_key.public_key(), as_dict=True),
            }
        ]
    }


@pytest.fixture
def mock_openid_config():
    """Fixture providing mock OpenID configuration data."""
    return {
        "issuer": ZITADEL_ISSUER,
        "authorization_endpoint": f"{ZITADEL_ISSUER}/oauth/v2/authorize",
        "token_endpoint": f"{ZITADEL_ISSUER}/oauth/v2/token",
        "jwks_uri": f"{ZITADEL_ISSUER}/oauth/v2/keys",
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

    async def test_successful_config_load(self, respx_mock, mock_openid_config, mock_jwks):
        """Test that OpenIdConfig loads config and keys correctly"""
        config_url = openid_config_url()
        config = OpenIdConfig(
            issuer_url=ZITADEL_ISSUER,
            config_url=config_url,
            authorization_url=f"{ZITADEL_ISSUER}/oauth/v2/authorize",
            token_url=f"{ZITADEL_ISSUER}/oauth/v2/token",
            jwks_uri=keys_url(),
        )

        respx_mock.get(config_url).respond(json=mock_openid_config)
        respx_mock.get(mock_openid_config["jwks_uri"]).respond(json=mock_jwks)

        await config.load_config()

        # Configured URLs are preserved verbatim; discovery is used only to verify
        # the issuer and fetch signing keys (RFC 8414 §3.3, GH #152).
        assert config.issuer_url == ZITADEL_ISSUER
        assert config.authorization_url == f"{ZITADEL_ISSUER}/oauth/v2/authorize"
        assert config.token_url == f"{ZITADEL_ISSUER}/oauth/v2/token"
        assert config.jwks_uri == keys_url()
        assert isinstance(config.cache_ttl_seconds, int)
        assert len(config.signing_keys) == 2
        assert all(isinstance(key, RSAPublicKey) for key in config.signing_keys.values())

    @pytest.mark.parametrize("cache_ttl_seconds", [1, 30, 100, 300, 600, 3600])
    async def test_caching_behavior(self, cache_ttl_seconds, respx_mock, mock_openid_config, mock_jwks, freezer):
        """Test that config is cached and only refreshed after expiry"""
        config_url = openid_config_url()
        config = OpenIdConfig(
            issuer_url=ZITADEL_ISSUER,
            config_url=config_url,
            authorization_url=f"{ZITADEL_ISSUER}/oauth/v2/authorize",
            token_url=f"{ZITADEL_ISSUER}/oauth/v2/token",
            jwks_uri=keys_url(),
            cache_ttl_seconds=cache_ttl_seconds,
        )

        initial_config_request = respx_mock.get(config_url).respond(json=mock_openid_config)
        initial_jwks_request = respx_mock.get(mock_openid_config["jwks_uri"]).respond(json=mock_jwks)

        # Load config and keys at a fixed time
        start_datetime = datetime(2025, 2, 5, 18, 0, 0)
        freezer.move_to(start_datetime)
        await config.load_config()
        initial_refresh = config.last_refresh_timestamp
        assert initial_config_request.call_count == 1
        assert initial_jwks_request.call_count == 1

        # Move time forward by a second
        freezer.move_to(start_datetime + timedelta(seconds=1))
        await config.load_config()  # Should use cached config
        assert config.last_refresh_timestamp == initial_refresh  # Timestamp shouldn't change for cache hit
        assert initial_config_request.call_count == 1  # Should not have changed
        assert initial_jwks_request.call_count == 1  # Should not have changed

        # Move time forward past cache expiration
        freezer.move_to(start_datetime + timedelta(seconds=cache_ttl_seconds + 1))
        await config.load_config()  # Should refresh
        assert config.last_refresh_timestamp > initial_refresh
        assert initial_config_request.call_count == 2  # Should have refreshed
        assert initial_jwks_request.call_count == 2  # Should have refreshed

    async def test_key_filtering(self, respx_mock, mock_openid_config):
        """Test that invalid keys are filtered out"""
        config_url = openid_config_url()
        config = OpenIdConfig(
            issuer_url=ZITADEL_ISSUER,
            config_url=config_url,
            authorization_url=f"{ZITADEL_ISSUER}/oauth/v2/authorize",
            token_url=f"{ZITADEL_ISSUER}/oauth/v2/token",
            jwks_uri=keys_url(),
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

    @pytest.mark.parametrize(
        "last_refresh_timestamp, signing_key, expected",
        [
            (None, {}, True),  # No config -> refresh
            (datetime.now(), {}, True),  # No keys -> refresh
            (
                datetime.now(),
                valid_key.public_key(),
                False,
            ),  # Fresh config and keys -> no refresh
            (
                datetime.now() - timedelta(hours=2),
                valid_key.public_key(),
                True,
            ),  # Old config -> refresh
            (None, valid_key.public_key(), True),  # No config, but keys -> refresh
        ],
    )
    async def test_needs_refresh(self, last_refresh_timestamp, signing_key, expected):
        """Test that _needs_refresh method works as expected based on last_refresh_timestamp and signing_keys"""
        config_url = openid_config_url()
        config = OpenIdConfig(
            issuer_url="",
            config_url=config_url,
            authorization_url="",
            token_url="",
            jwks_uri="",
            last_refresh_timestamp=last_refresh_timestamp,
            signing_keys={"kid": signing_key} if signing_key else {},
        )
        assert config._needs_refresh() == expected

    async def test_issuer_mismatch_raises(self, respx_mock, mock_jwks):
        """Per RFC 8414 §3.3, a discovery response whose `issuer` differs from the
        configured issuer_url must be rejected and must not overwrite the configured
        value."""
        config_url = openid_config_url()
        config = OpenIdConfig(
            issuer_url=ZITADEL_ISSUER,
            config_url=config_url,
            authorization_url=f"{ZITADEL_ISSUER}/oauth/v2/authorize",
            token_url=f"{ZITADEL_ISSUER}/oauth/v2/token",
            jwks_uri=keys_url(),
        )
        bad_discovery = {
            "issuer": "https://attacker.example.com",
            "authorization_endpoint": f"{ZITADEL_ISSUER}/oauth/v2/authorize",
            "token_endpoint": f"{ZITADEL_ISSUER}/oauth/v2/token",
            "jwks_uri": f"{ZITADEL_ISSUER}/oauth/v2/keys",
        }
        respx_mock.get(config_url).respond(json=bad_discovery)
        respx_mock.get(keys_url()).respond(json=mock_jwks)

        with pytest.raises(UnauthorizedException) as exc_info:
            await config.load_config()

        assert exc_info.value.status_code == 401
        detail = exc_info.value.detail
        assert isinstance(detail, dict)
        assert detail["error"] == "invalid_token"
        assert "issuer mismatch" in detail["message"]
        assert config.issuer_url == ZITADEL_ISSUER
        assert config.signing_keys == {}


@pytest.mark.asyncio
class TestKidMissRefresh:
    """Regression suite for GH #149: unknown-kid path must not DoS the worker pool."""

    async def test_kid_in_cache_skips_refresh(self, respx_mock, mocker):
        """Cached kid returns immediately, no sleep, no JWKS fetch."""
        sleep_mock = mocker.patch("fastapi_zitadel_auth.openid_config.OpenIdConfig._sleep")
        keys_route = respx_mock.get(keys_url()).respond(json=_jwks_with("any"))

        config = _config_with_seeded_key("k1")
        result = await config.get_key("k1")

        assert isinstance(result, RSAPublicKey)
        assert sleep_mock.call_count == 0
        assert keys_route.call_count == 0
        assert config.last_refresh_attempt is None

    async def test_kid_miss_merges_keys(self, respx_mock, mocker):
        """Unknown kid: sleep once, fetch JWKS once, merge into existing keys."""
        sleep_mock = mocker.patch("fastapi_zitadel_auth.openid_config.OpenIdConfig._sleep")
        config_route = respx_mock.get(openid_config_url())
        keys_route = respx_mock.get(keys_url()).respond(json=_jwks_with("k2"))

        config = _config_with_seeded_key("k1")
        result = await config.get_key("k2")

        assert isinstance(result, RSAPublicKey)
        assert "k1" in config.signing_keys
        assert "k2" in config.signing_keys
        assert sleep_mock.call_count == 1
        assert keys_route.call_count == 1
        assert config_route.call_count == 0
        assert config.last_refresh_attempt is not None

    async def test_kid_miss_throttled_within_cooldown(self, respx_mock, mocker, freezer):
        """Second unknown-kid request within 10s short-circuits to 401 with no fetch/sleep."""
        sleep_mock = mocker.patch("fastapi_zitadel_auth.openid_config.OpenIdConfig._sleep")
        keys_route = respx_mock.get(keys_url()).respond(json=_jwks_with("k2"))

        t0 = datetime(2026, 1, 1, 12, 0, 0)
        freezer.move_to(t0)
        config = _config_with_seeded_key("k1")

        with pytest.raises(UnauthorizedException):
            await config.get_key("unknown1")  # fetches, fails, sets last_refresh_attempt

        freezer.move_to(t0 + timedelta(seconds=5))
        with pytest.raises(UnauthorizedException):
            await config.get_key("unknown2")

        assert keys_route.call_count == 1
        assert sleep_mock.call_count == 1

    async def test_kid_miss_refetches_after_cooldown(self, respx_mock, mocker, freezer):
        """After the cooldown elapses, a fresh unknown-kid miss triggers another fetch."""
        sleep_mock = mocker.patch("fastapi_zitadel_auth.openid_config.OpenIdConfig._sleep")
        keys_route = respx_mock.get(keys_url()).respond(json=_jwks_with("k2"))

        t0 = datetime(2026, 1, 1, 12, 0, 0)
        freezer.move_to(t0)
        config = _config_with_seeded_key("k1")

        with pytest.raises(UnauthorizedException):
            await config.get_key("unknown1")

        freezer.move_to(t0 + timedelta(seconds=11))
        with pytest.raises(UnauthorizedException):
            await config.get_key("unknown2")

        assert keys_route.call_count == 2
        assert sleep_mock.call_count == 2

    async def test_failed_refresh_still_updates_attempt(self, respx_mock, mocker, freezer):
        """A 5xx from the JWKS endpoint must still set last_refresh_attempt so we don't hot-loop."""
        sleep_mock = mocker.patch("fastapi_zitadel_auth.openid_config.OpenIdConfig._sleep")
        keys_route = respx_mock.get(keys_url()).respond(status_code=500)

        t0 = datetime(2026, 1, 1, 12, 0, 0)
        freezer.move_to(t0)
        config = _config_with_seeded_key("k1")

        with pytest.raises(UnauthorizedException):
            await config.get_key("unknown1")
        assert config.last_refresh_attempt == t0

        freezer.move_to(t0 + timedelta(seconds=5))
        with pytest.raises(UnauthorizedException):
            await config.get_key("unknown2")

        assert keys_route.call_count == 1  # second call throttled
        assert sleep_mock.call_count == 1

    async def test_kid_miss_does_not_evict_existing_keys(self, respx_mock, mocker):
        """Merge semantics: if JWKS returns a disjoint set, original keys remain."""
        mocker.patch("fastapi_zitadel_auth.openid_config.OpenIdConfig._sleep")
        respx_mock.get(keys_url()).respond(json=_jwks_with("k2"))

        config = _config_with_seeded_key("k1")
        original_key = config.signing_keys["k1"]

        with pytest.raises(UnauthorizedException):
            await config.get_key("still-unknown")

        assert "k1" in config.signing_keys
        assert config.signing_keys["k1"] is original_key
        assert "k2" in config.signing_keys

    async def test_kid_miss_does_not_refetch_openid_config(self, respx_mock, mocker):
        """Discovery endpoint URLs are stable; kid miss must only hit JWKS."""
        mocker.patch("fastapi_zitadel_auth.openid_config.OpenIdConfig._sleep")
        config_route = respx_mock.get(openid_config_url())
        respx_mock.get(keys_url()).respond(json=_jwks_with("k2"))

        config = _config_with_seeded_key("k1")
        await config.get_key("k2")

        assert config_route.call_count == 0

    async def test_kid_miss_network_error_raises_unauthorized(self, respx_mock, mocker):
        """A transport error during JWKS fetch surfaces as UnauthorizedException, not a 500."""
        mocker.patch("fastapi_zitadel_auth.openid_config.OpenIdConfig._sleep")
        respx_mock.get(keys_url()).mock(side_effect=httpx.ConnectError("boom"))

        config = _config_with_seeded_key("k1")
        with pytest.raises(UnauthorizedException):
            await config.get_key("unknown")
        assert config.last_refresh_attempt is not None

    async def test_concurrent_kid_miss_only_fetches_once(self, respx_mock, mocker):
        """Two coroutines racing on the same unknown kid: the lock + double-check
        ensures exactly one JWKS fetch happens and both get the merged key."""
        import asyncio

        async def yielding_sleep() -> None:
            await asyncio.sleep(0)

        mocker.patch(
            "fastapi_zitadel_auth.openid_config.OpenIdConfig._sleep",
            side_effect=yielding_sleep,
        )
        keys_route = respx_mock.get(keys_url()).respond(json=_jwks_with("k2"))

        config = _config_with_seeded_key("k1")

        results = await asyncio.gather(
            config.get_key("k2"),
            config.get_key("k2"),
        )

        assert all(isinstance(r, RSAPublicKey) for r in results)
        assert keys_route.call_count == 1  # second coroutine hit the double-check, not the fetch

    async def test_cancellation_during_sleep_engages_throttle(self, respx_mock, mocker, freezer):
        """Regression: cancellation during _sleep (e.g. attacker closes TCP mid-handler)
        must not bypass the cooldown throttle. The next attacker request within 10s must
        short-circuit instead of paying another sleep+fetch."""
        import asyncio

        async def raise_cancelled() -> None:
            raise asyncio.CancelledError()

        sleep_mock = mocker.patch(
            "fastapi_zitadel_auth.openid_config.OpenIdConfig._sleep",
            side_effect=raise_cancelled,
        )
        keys_route = respx_mock.get(keys_url()).respond(json=_jwks_with("k2"))

        t0 = datetime(2026, 1, 1, 12, 0, 0)
        freezer.move_to(t0)
        config = _config_with_seeded_key("k1")

        with pytest.raises(asyncio.CancelledError):
            await config.get_key("unknown1")
        assert config.last_refresh_attempt == t0
        assert keys_route.call_count == 0  # cancelled before reaching the fetch

        freezer.move_to(t0 + timedelta(seconds=5))
        with pytest.raises(UnauthorizedException):
            await config.get_key("unknown2")
        assert sleep_mock.call_count == 1  # second call short-circuited before any sleep
        assert keys_route.call_count == 0

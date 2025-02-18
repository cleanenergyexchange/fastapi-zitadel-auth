"""
Test the TokenValidator class
"""

import time

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fastapi_zitadel_auth.exceptions import UnauthorizedException, ForbiddenException
from fastapi_zitadel_auth.token import TokenValidator
from tests.utils import ZITADEL_ISSUER, ZITADEL_CLIENT_ID, ZITADEL_PROJECT_ID


@pytest.fixture(scope="module")
def rsa_keys() -> tuple:
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def token_validator() -> TokenValidator:
    """TokenValidator fixture"""
    return TokenValidator()


@pytest.fixture
def valid_token(rsa_keys) -> str:
    """Generate a valid JWT token"""
    private_key, _ = rsa_keys
    now = int(time.time())

    claims = {
        "sub": "user123",
        "iss": ZITADEL_ISSUER,
        "aud": [ZITADEL_CLIENT_ID, ZITADEL_PROJECT_ID],
        "exp": now + 3600,
        "iat": now,
        "nbf": now,
        "jti": "unique-token-id",
    }

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "test-key-1"})


class TestTokenValidator:
    """Test the TokenValidator class"""

    @pytest.mark.parametrize(
        "claims,required_scopes,expected",
        [
            ({"scope": "read:messages write:messages"}, None, True),
            ({"scope": "read:messages write:messages"}, ["read:messages"], True),
            (
                {"scope": "read:messages write:messages"},
                ["read:messages", "write:messages"],
                True,
            ),
            (
                {"scope": "read:messages"},
                ["write:messages"],
                pytest.raises(ForbiddenException),
            ),
            ({"scope": ""}, ["read:messages"], pytest.raises(ForbiddenException)),
            ({}, ["read:messages"], pytest.raises(ForbiddenException)),
            (
                {"scope": "read:messages write:messages"},
                ["read:messages", "delete:messages"],
                pytest.raises(ForbiddenException),
            ),
            # Test with multiple space-separated allowed_scopes
            ({"scope": "scope1 scope2 scope3"}, ["scope2"], True),
            # Test with empty required allowed_scopes list
            ({"scope": "read:messages"}, [], True),
            # Test with special characters in allowed_scopes
            (
                {"scope": "api:read user.profile system-admin"},
                ["api:read", "system-admin"],
                True,
            ),
        ],
    )
    def test_validate_scopes(self, claims, required_scopes, expected):
        """Test scope validation with various combinations of claims and required allowed_scopes"""
        if isinstance(expected, bool):
            assert TokenValidator.validate_scopes(claims, required_scopes) == expected
        else:
            with expected:
                TokenValidator.validate_scopes(claims, required_scopes)

    @pytest.mark.parametrize(
        "claims",
        [
            {"scope": None},
            {"scope": 123},
            {"scope": True},
            {"scope": {"invalid": "type"}},
        ],
    )
    def test_validate_scopes_invalid_type(self, claims):
        """Test scope validation with invalid scope types"""
        with pytest.raises(UnauthorizedException):
            TokenValidator.validate_scopes(claims, ["read:messages"])

    def test_validate_scopes_whitespace_handling(self):
        """Test handling of various whitespace patterns in scope strings"""
        claims = {"scope": "scope1    scope2\tscope3\n\rscope4"}
        assert TokenValidator.validate_scopes(claims, ["scope1", "scope4"]) is True

    @pytest.mark.parametrize(
        "scope_string,required_scope",
        [
            ("a" * 1000 + " valid:scope", "valid:scope"),  # Very long scope string
            ("scope1" + " " * 100 + "scope2", "scope2"),  # Multiple spaces
            ("\u3000scope1\u2000scope2", "scope1"),  # Unicode whitespace
        ],
    )
    def test_validate_scopes_edge_cases(self, scope_string, required_scope):
        """Test scope validation with edge cases"""
        claims = {"scope": scope_string}
        assert TokenValidator.validate_scopes(claims, [required_scope]) is True

    def test_parse_unverified_valid_token(self, token_validator, valid_token):
        """
        Test that the TokenValidator can parse an unverified token
        """
        header, claims = token_validator.parse_unverified_token(valid_token)

        assert isinstance(header, dict)
        assert isinstance(claims, dict)
        assert header["kid"] == "test-key-1"
        assert header["alg"] == "RS256"
        assert claims["sub"] == "user123"
        assert "exp" in claims
        assert "iat" in claims
        assert "iss" in claims
        assert "aud" in claims
        assert "nbf" in claims
        assert "jti" in claims

    def test_parse_unverified_none_token(self, token_validator):
        """Test that the TokenValidator raises an exception when parsing a None token"""
        with pytest.raises(UnauthorizedException, match="Invalid token format"):
            token_validator.parse_unverified_token(None)  # type: ignore

    @pytest.mark.parametrize(
        "invalid_token",
        [
            "not.a.token",
            "invalid.token.format",
            "eyJhbGciOiJIUzI1NiJ9",  # Only header
            "",
            "null",
            None,
        ],
        ids=[
            "random_string",
            "wrong_format",
            "header_only",
            "empty_string",
            "string_null",
            "none_value",
        ],
    )
    def test_parse_unverified_invalid_token(self, token_validator, invalid_token):
        """Test that the TokenValidator raises an exception when parsing an invalid token"""
        with pytest.raises(UnauthorizedException, match="Invalid token format"):
            token_validator.parse_unverified_token(invalid_token)

    def test_verify_valid_token(self, token_validator, valid_token, rsa_keys):
        """Test that the TokenValidator can verify a valid token"""
        _, public_key = rsa_keys

        claims = token_validator.verify(
            token=valid_token,
            key=public_key,
            audiences=[ZITADEL_CLIENT_ID, ZITADEL_PROJECT_ID],
            issuer=ZITADEL_ISSUER,
        )

        assert claims["sub"] == "user123"
        assert claims["iss"] == ZITADEL_ISSUER
        assert ZITADEL_CLIENT_ID in claims["aud"]

    def test_verify_expired_token(self, token_validator, rsa_keys):
        """Test that the TokenValidator raises an exception when verifying an expired token"""
        private_key, public_key = rsa_keys
        now = int(time.time())

        expired_claims = {
            "sub": "user123",
            "iss": ZITADEL_ISSUER,
            "aud": [ZITADEL_CLIENT_ID],
            "exp": now - 3600,  # Expired 1 hour ago
            "iat": now - 7200,
            "nbf": now - 7200,
            "jti": "unique-token-id",
        }

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        expired_token = jwt.encode(expired_claims, pem, algorithm="RS256")

        with pytest.raises(jwt.ExpiredSignatureError):
            token_validator.verify(
                token=expired_token,
                key=public_key,
                audiences=[ZITADEL_CLIENT_ID],
                issuer=ZITADEL_ISSUER,
            )

    def test_verify_invalid_audience(self, token_validator, valid_token, rsa_keys):
        """Test that the TokenValidator raises an exception when verifying a token with an invalid audience"""
        _, public_key = rsa_keys

        with pytest.raises(jwt.InvalidAudienceError):
            token_validator.verify(
                token=valid_token,
                key=public_key,
                audiences=["wrong_audience"],
                issuer=ZITADEL_ISSUER,
            )

    def test_verify_invalid_issuer(self, token_validator, valid_token, rsa_keys):
        """Test that the TokenValidator raises an exception when verifying a token with an invalid issuer_url"""
        _, public_key = rsa_keys

        with pytest.raises(jwt.InvalidIssuerError):
            token_validator.verify(
                token=valid_token,
                key=public_key,
                audiences=[ZITADEL_CLIENT_ID, ZITADEL_PROJECT_ID],
                issuer="https://wrong.issuer.com",
            )

    def test_verify_invalid_signature(self, token_validator, valid_token):
        """Test that the TokenValidator raises an exception when verifying a token with an invalid signature"""
        wrong_key = rsa.generate_private_key(
            backend=default_backend(), public_exponent=65537, key_size=2048
        ).public_key()

        with pytest.raises(jwt.InvalidSignatureError):
            token_validator.verify(
                token=valid_token,
                key=wrong_key,
                audiences=[ZITADEL_CLIENT_ID, ZITADEL_PROJECT_ID],
                issuer=ZITADEL_ISSUER,
            )

    def test_verify_not_yet_valid(self, token_validator, rsa_keys):
        """Raise Exception when verifying a token that is not yet valid"""
        private_key, public_key = rsa_keys
        now = int(time.time())

        future_claims = {
            "sub": "user123",
            "iss": ZITADEL_ISSUER,
            "aud": [ZITADEL_CLIENT_ID],
            "exp": now + 7200,
            "iat": now,
            "nbf": now + 3600,  # Not valid for another hour
            "jti": "unique-token-id",
        }

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        future_token = jwt.encode(future_claims, pem, algorithm="RS256")

        with pytest.raises(jwt.ImmatureSignatureError):
            token_validator.verify(
                token=future_token,
                key=public_key,
                audiences=[ZITADEL_CLIENT_ID],
                issuer=ZITADEL_ISSUER,
            )

    def test_verify_missing_claims(self, token_validator, rsa_keys):
        """Raise Exception when verifying a token with missing required claims"""
        private_key, public_key = rsa_keys
        now = int(time.time())

        incomplete_claims = {
            "iss": ZITADEL_ISSUER,
            "aud": [ZITADEL_CLIENT_ID],
            "exp": now + 3600,
            # Missing 'sub' claim
        }

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        incomplete_token = jwt.encode(incomplete_claims, pem, algorithm="RS256")

        with pytest.raises(jwt.MissingRequiredClaimError):
            token_validator.verify(
                token=incomplete_token,
                key=public_key,
                audiences=[ZITADEL_CLIENT_ID],
                issuer=ZITADEL_ISSUER,
            )

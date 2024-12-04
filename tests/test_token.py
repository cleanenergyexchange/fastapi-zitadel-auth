"""
Test the token module
"""

import time

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fastapi_zitadel_auth.exceptions import InvalidAuthException
from fastapi_zitadel_auth.token import TokenValidator


@pytest.fixture(scope="module")
def rsa_keys() -> tuple:
    """
    Generate RSA key pair
    """
    private_key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def token_validator() -> TokenValidator:
    """
    TokenValidator fixture
    """
    return TokenValidator(algorithm="RS256")


@pytest.fixture
def valid_token(rsa_keys) -> str:
    """
    Generate a valid JWT token
    """
    private_key, _ = rsa_keys
    now = int(time.time())

    claims = {
        "sub": "user123",
        "iss": "https://issuer.zitadel.cloud",
        "aud": ["client123", "project123"],
        "exp": now + 3600,
        "iat": now,
        "nbf": now,
    }

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "test-key-1"})


class TestTokenValidator:
    """
    Test the TokenValidator class
    """

    def test_init_with_default_algorithm(self):
        """
        Test that the TokenValidator initializes with the default algorithm
        """
        validator = TokenValidator()
        assert validator.algorithm == "RS256"

    def test_init_with_custom_algorithm(self):
        """
        Test that the TokenValidator initializes with a custom algorithm
        """
        validator = TokenValidator(algorithm="RS384")
        assert validator.algorithm == "RS384"

    def test_parse_unverified_valid_token(self, token_validator, valid_token):
        """
        Test that the TokenValidator can parse an unverified token
        """
        header, claims = token_validator.parse_unverified(valid_token)

        assert isinstance(header, dict)
        assert isinstance(claims, dict)
        assert header["kid"] == "test-key-1"
        assert header["alg"] == "RS256"
        assert claims["sub"] == "user123"
        assert "exp" in claims
        assert "iat" in claims

    def test_parse_unverified_none_token(self, token_validator):
        """
        Test that the TokenValidator raises an exception when parsing a None token
        """
        with pytest.raises(InvalidAuthException, match="Invalid token format"):
            token_validator.parse_unverified(None)

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
        """
        Test that the TokenValidator raises an exception when parsing an invalid token
        """
        with pytest.raises(InvalidAuthException, match="Invalid token format"):
            token_validator.parse_unverified(invalid_token)

    def test_verify_valid_token(self, token_validator, valid_token, rsa_keys):
        """
        Test that the TokenValidator can verify a valid token
        """
        _, public_key = rsa_keys

        claims = token_validator.verify(
            token=valid_token,
            key=public_key,
            audiences=["client123", "project123"],
            issuer="https://issuer.zitadel.cloud",
        )

        assert claims["sub"] == "user123"
        assert claims["iss"] == "https://issuer.zitadel.cloud"
        assert "client123" in claims["aud"]

    def test_verify_expired_token(self, token_validator, rsa_keys):
        """
        Test that the TokenValidator raises an exception when verifying an expired token
        """
        private_key, public_key = rsa_keys
        now = int(time.time())

        expired_claims = {
            "sub": "user123",
            "iss": "https://issuer.zitadel.cloud",
            "aud": ["client123"],
            "exp": now - 3600,  # Expired 1 hour ago
            "iat": now - 7200,
            "nbf": now - 7200,
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
                audiences=["client123"],
                issuer="https://issuer.zitadel.cloud",
            )

    def test_verify_invalid_audience(self, token_validator, valid_token, rsa_keys):
        """
        Test that the TokenValidator raises an exception when verifying a token with an invalid audience
        """
        _, public_key = rsa_keys

        with pytest.raises(jwt.InvalidAudienceError):
            token_validator.verify(
                token=valid_token,
                key=public_key,
                audiences=["wrong_audience"],
                issuer="https://issuer.zitadel.cloud",
            )

    def test_verify_invalid_issuer(self, token_validator, valid_token, rsa_keys):
        """
        Test that the TokenValidator raises an exception when verifying a token with an invalid issuer
        """
        _, public_key = rsa_keys

        with pytest.raises(jwt.InvalidIssuerError):
            token_validator.verify(
                token=valid_token,
                key=public_key,
                audiences=["client123", "project123"],
                issuer="https://wrong.issuer.com",
            )

    def test_verify_invalid_signature(self, token_validator, valid_token):
        """
        Test that the TokenValidator raises an exception when verifying a token with an invalid signature
        """
        wrong_key = rsa.generate_private_key(
            backend=default_backend(), public_exponent=65537, key_size=2048
        ).public_key()

        with pytest.raises(jwt.InvalidSignatureError):
            token_validator.verify(
                token=valid_token,
                key=wrong_key,
                audiences=["client123", "project123"],
                issuer="https://issuer.zitadel.cloud",
            )

    def test_verify_not_yet_valid(self, token_validator, rsa_keys):
        """
        Raise Exception when verifying a token that is not yet valid
        """
        private_key, public_key = rsa_keys
        now = int(time.time())

        future_claims = {
            "sub": "user123",
            "iss": "https://issuer.zitadel.cloud",
            "aud": ["client123"],
            "exp": now + 7200,
            "iat": now,
            "nbf": now + 3600,  # Not valid for another hour
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
                audiences=["client123"],
                issuer="https://issuer.zitadel.cloud",
            )

    def test_verify_missing_claims(self, token_validator, rsa_keys):
        """
        Raise Exception when verifying a token with missing required claims
        """
        private_key, public_key = rsa_keys
        now = int(time.time())

        incomplete_claims = {
            "iss": "https://issuer.zitadel.cloud",
            "aud": ["client123"],
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
                audiences=["client123"],
                issuer="https://issuer.zitadel.cloud",
            )

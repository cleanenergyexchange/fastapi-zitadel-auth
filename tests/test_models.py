"""
Test the models module
"""

import time

import pytest

from fastapi_zitadel_auth.models import ZitadelUser, JWTClaims, ZitadelClaims


@pytest.fixture
def valid_jwt_claims() -> dict:
    """
    Valid JWT claims for testing
    """
    now = int(time.time())
    return {
        "aud": "test-client",
        "exp": now + 3600,
        "iat": now,
        "iss": "https://issuer.zitadel.cloud",
        "nbf": now,
        "sub": "user123",
        "jti": "unique-token-id",
    }


@pytest.fixture
def valid_zitadel_claims(valid_jwt_claims) -> dict:
    """
    Valid Zitadel-specific claims for testing
    """
    return {
        **valid_jwt_claims,
        "email": "user@example.com",
        "email_verified": True,
        "name": "Test User",
        "preferred_username": "testuser",
        "urn:zitadel:iam:org:project:roles": {"system": True, "user": True},
        "urn:zitadel:iam:user:metadata": {
            "department": "Engineering",
            "location": "Remote",
        },
        "urn:zitadel:iam:user:resourceowner:id": "org123",
        "urn:zitadel:iam:user:resourceowner:name": "Test Organization",
        "urn:zitadel:iam:user:resourceowner:primary_domain": "example.com",
    }


class TestJWTClaims:
    """
    JWTClaims model tests
    """

    def test_valid_claims(self, valid_jwt_claims):
        """
        Test that the JWTClaims model can be instantiated with valid claims
        """
        claims = JWTClaims(**valid_jwt_claims)
        assert claims.sub == "user123"
        assert claims.jti == "unique-token-id"
        assert isinstance(claims.exp, int)

    def test_audience_string(self):
        """
        Test that the audience can be a string
        """
        claims = JWTClaims(
            aud="single-audience",
            exp=1234567890,
            iat=1234567890,
            iss="test",
            nbf=1234567890,
            sub="user123",
        )
        assert claims.aud == "single-audience"

    def test_audience_list(self):
        """
        Test that the audience can be a list of strings
        """
        claims = JWTClaims(
            aud=["aud1", "aud2"],
            exp=1234567890,
            iat=1234567890,
            iss="test",
            nbf=1234567890,
            sub="user123",
        )
        assert isinstance(claims.aud, list)
        assert "aud1" in claims.aud
        assert "aud2" in claims.aud

    def test_optional_jti(self):
        """
        Test that the jti claim is optional
        """
        claims = JWTClaims(
            aud="test",
            exp=1234567890,
            iat=1234567890,
            iss="test",
            nbf=1234567890,
            sub="user123",
        )
        assert claims.jti is None


class TestZitadelClaims:
    """
    ZitadelClaims model tests
    """

    def test_valid_claims(self, valid_zitadel_claims):
        """
        Test that the ZitadelClaims model can be instantiated with valid claims
        """
        claims = ZitadelClaims(**valid_zitadel_claims)
        assert claims.email == "user@example.com"
        assert claims.email_verified is True
        assert claims.name == "Test User"
        assert claims.project_roles == {"system": True, "user": True}
        assert claims.resource_owner_id == "org123"

    def test_minimal_claims(self, valid_jwt_claims):
        """
        Test with only required JWT claims
        """
        claims = ZitadelClaims(**valid_jwt_claims)
        assert claims.email is None
        assert claims.email_verified is None
        assert claims.project_roles == {}
        assert claims.user_metadata == {}
        assert claims.resource_owner_id is None

    def test_project_roles_alias(self):
        """
        Test the URN alias for project roles
        """
        claims = ZitadelClaims(
            **{
                "aud": "test",
                "exp": 1234567890,
                "iat": 1234567890,
                "iss": "test",
                "nbf": 1234567890,
                "sub": "user123",
                "urn:zitadel:iam:org:project:roles": {"role1": True},
            }
        )
        assert claims.project_roles == {"role1": True}

    def test_user_metadata_alias(self):
        """
        Test the URN alias for user metadata
        """
        metadata = {"key": "value"}
        claims = ZitadelClaims(
            **{
                "aud": "test",
                "exp": 1234567890,
                "iat": 1234567890,
                "iss": "test",
                "nbf": 1234567890,
                "sub": "user123",
                "urn:zitadel:iam:user:metadata": metadata,
            }
        )
        assert claims.user_metadata == metadata


class TestAuthenticatedUser:
    """
    ZitadelUser model tests
    """

    def test_valid_user(self, valid_zitadel_claims):
        """
        Test that the ZitadelUser model can be instantiated with valid claims
        """
        claims = ZitadelClaims(**valid_zitadel_claims)
        user = ZitadelUser(claims=claims, access_token="test-token")
        assert user.user_id == "user123"
        assert user.access_token == "test-token"
        assert user.claims == claims

    def test_user_string_representation(self, valid_zitadel_claims):
        """
        Test that the string representation redacts the token
        """
        claims = ZitadelClaims(**valid_zitadel_claims)
        user = ZitadelUser(claims=claims, access_token="secret-token")
        str_rep = str(user)
        assert "secret-token" not in str_rep
        assert "***" in str_rep
        assert str(claims) in str_rep

    @pytest.mark.parametrize(
        "field,value",
        [
            ("email", "new@example.com"),
            ("name", "New Name"),
            ("preferred_username", "newuser"),
            ("resource_owner_name", "New Org"),
        ],
    )
    def test_claim_updates(self, valid_zitadel_claims, field, value):
        """
        Test updating various claims fields
        """
        claims = ZitadelClaims(**valid_zitadel_claims)
        setattr(claims, field, value)
        user = ZitadelUser(claims=claims, access_token="token")
        assert getattr(user.claims, field) == value

    def test_nested_metadata_access(self, valid_zitadel_claims):
        """
        Test accessing nested metadata in claims
        """
        claims = ZitadelClaims(**valid_zitadel_claims)
        user = ZitadelUser(claims=claims, access_token="token")
        assert user.claims.user_metadata["department"] == "Engineering"
        assert user.claims.project_roles["system"] is True

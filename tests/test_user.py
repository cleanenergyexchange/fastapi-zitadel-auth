"""
Test suite for user module.
"""

import time

import pytest
from pydantic import ValidationError

from fastapi_zitadel_auth.user import (
    JwtClaims,
    DefaultZitadelClaims,
    DefaultZitadelUser,
)
from tests.utils import ZITADEL_ISSUER, ZITADEL_PRIMARY_DOMAIN, ZITADEL_CLIENT_ID, ZITADEL_PROJECT_ID

role_key = "role1"
role_id = "295621089671959405"
sub = "22222222222222222222"


@pytest.fixture
def valid_claims_data() -> dict:
    """Fixture providing valid JWT claims data."""
    now = int(time.time())
    return {
        "aud": [ZITADEL_PROJECT_ID],
        "client_id": ZITADEL_CLIENT_ID,
        "exp": now + 3600,
        "iat": now,
        "iss": ZITADEL_ISSUER,
        "sub": sub,
        "nbf": now,
        "jti": "unique-token-id",
    }


@pytest.fixture
def valid_claims_with_project_roles(valid_claims_data):
    """Fixture providing claims data with Zitadel project roles."""
    data = valid_claims_data.copy()
    data[f"urn:zitadel:iam:org:project:{ZITADEL_PROJECT_ID}:roles"] = {role_key: {role_id: ZITADEL_PRIMARY_DOMAIN}}
    return data


class TestBaseZitadelClaims:
    """Test suite for JwtClaims model."""

    @pytest.mark.parametrize("aud", [[ZITADEL_PROJECT_ID], ["audience1", "audience2"]])
    def test_valid_audience_formats(self, valid_claims_data, aud):
        """Test that list audience formats are accepted."""
        data = valid_claims_data.copy()
        data["aud"] = aud
        claims = JwtClaims(**data)
        assert claims.aud == aud

    def test_required_fields(self, valid_claims_data):
        """Test that required fields must be present."""
        required_fields = [
            "aud",
            "client_id",
            "exp",
            "iat",
            "iss",
            "sub",
            "nbf",
            "jti",
        ]

        for field in required_fields:
            invalid_data = valid_claims_data.copy()
            del invalid_data[field]

            with pytest.raises(
                ValidationError,
                match=f"1 validation error for JwtClaims\n{field}\n  Field required",
            ):
                JwtClaims(**invalid_data)


class TestDefaultZitadelClaims:
    """Test suite for DefaultZitadelClaims model."""

    def test_project_roles_extraction(self, valid_claims_with_project_roles):
        """Test extraction of project roles from Zitadel-specific claim."""
        claims = DefaultZitadelClaims(**valid_claims_with_project_roles)
        assert claims.project_roles == {role_key: {role_id: ZITADEL_PRIMARY_DOMAIN}}

    def test_missing_project_roles(self, valid_claims_data):
        """Test handling of missing project roles."""
        claims = DefaultZitadelClaims(**valid_claims_data)
        assert claims.project_roles == {}

    def test_different_project_roles(self, valid_claims_data):
        """Test extraction of project roles with different role values."""
        data = valid_claims_data.copy()
        data[f"urn:zitadel:iam:org:project:{ZITADEL_PROJECT_ID}:roles"] = {
            "role2": {"123456789": ZITADEL_PRIMARY_DOMAIN}
        }

        claims = DefaultZitadelClaims(**data)
        assert claims.project_roles == {"role2": {"123456789": ZITADEL_PRIMARY_DOMAIN}}


class TestDefaultZitadelUser:
    """Test suite for DefaultZitadelUser model."""

    def test_valid_user_creation(self, valid_claims_with_project_roles):
        """Test creation of valid DefaultZitadelUser instance."""
        claims = DefaultZitadelClaims(**valid_claims_with_project_roles)
        user = DefaultZitadelUser(claims=claims, access_token="test-token")

        assert isinstance(user.claims, DefaultZitadelClaims)
        assert user.access_token == "test-token"

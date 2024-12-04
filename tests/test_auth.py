"""
Test the auth module
"""

import time

import httpx
import pytest
import respx
from fastapi.exceptions import HTTPException
from fastapi.security import SecurityScopes
from starlette.requests import Request

from fastapi_zitadel_auth import AuthConfig, ZitadelAuth
from fastapi_zitadel_auth.exceptions import InvalidAuthException
from tests.utils import create_test_token


async def test_valid_token(auth_config, mock_jwks, test_keys):
    """
    Test with a valid token
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(auth_config.jwks_url).mock(
            return_value=httpx.Response(200, json=mock_jwks())
        )

        auth = ZitadelAuth(auth_config)
        token = create_test_token(test_keys)

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", f"Bearer {token}".encode())],
            }
        )
        scopes = SecurityScopes(scopes=["system"])

        user = await auth(request, scopes)
        assert user is not None
        assert user.claims.sub == "user123"
        assert user.claims.iss == "https://issuer.zitadel.cloud"
        assert user.claims.aud == ["123456789", "987654321"]
        assert user.claims.exp > int(time.time())
        assert user.claims.iat == user.claims.nbf
        assert user.access_token == token


async def test_expired_token(auth_config, mock_jwks, test_keys):
    """
    Test with an expired token
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(auth_config.jwks_url).mock(
            return_value=httpx.Response(200, json=mock_jwks())
        )

        auth = ZitadelAuth(auth_config)
        token = create_test_token(test_keys, expired=True)

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", f"Bearer {token}".encode())],
            }
        )
        scopes = SecurityScopes(scopes=["system"])

        with pytest.raises(InvalidAuthException, match="Token signature has expired"):
            await auth(request, scopes)


@pytest.mark.asyncio
async def test_invalid_scopes(auth_config, mock_jwks, test_keys):
    """
    Test with invalid scopes
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(auth_config.jwks_url).mock(
            return_value=httpx.Response(200, json=mock_jwks())
        )

        auth = ZitadelAuth(auth_config)
        token = create_test_token(test_keys, invalid_roles=True)

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", f"Bearer {token}".encode())],
            }
        )
        scopes = SecurityScopes(scopes=["system"])

        with pytest.raises(InvalidAuthException, match="Not enough permissions"):
            await auth(request, scopes)


@pytest.mark.asyncio
async def test_invalid_key_id(auth_config, mock_jwks, test_keys):
    """
    Test with an invalid key ID
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(auth_config.jwks_url).mock(
            return_value=httpx.Response(200, json=mock_jwks())
        )

        auth = ZitadelAuth(auth_config)
        token = create_test_token(test_keys, kid="wrong-kid")

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", f"Bearer {token}".encode())],
            }
        )
        scopes = SecurityScopes(scopes=["system"])

        with pytest.raises(InvalidAuthException, match="No valid signing key found"):
            await auth(request, scopes)


@pytest.mark.asyncio
async def test_invalid_claims(auth_config, mock_jwks, test_keys):
    """
    Test with invalid claims
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(auth_config.jwks_url).mock(
            return_value=httpx.Response(200, json=mock_jwks())
        )

        auth = ZitadelAuth(auth_config)
        token = create_test_token(test_keys, invalid_claims=True)

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", f"Bearer {token}".encode())],
            }
        )
        scopes = SecurityScopes(scopes=["system"])

        with pytest.raises(InvalidAuthException, match="Token contains invalid claims"):
            await auth(request, scopes)


@pytest.mark.asyncio
async def test_evil_token(auth_config, mock_jwks, test_keys):
    """
    Test with an 'evil' token
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(auth_config.jwks_url).mock(
            return_value=httpx.Response(200, json=mock_jwks())
        )

        auth = ZitadelAuth(auth_config)
        token = create_test_token(test_keys, kid="test-key-1", evil=True)

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", f"Bearer {token}".encode())],
            }
        )
        scopes = SecurityScopes(scopes=["system"])

        with pytest.raises(InvalidAuthException, match="Unable to validate token"):
            await auth(request, scopes)


@pytest.mark.parametrize(
    "claims,required_scopes,expected_error",
    [
        # Valid case - has all required scopes
        (
            {
                "urn:zitadel:iam:org:project:987654321:roles": {
                    "system": True,
                    "user": True,
                }
            },
            ["system", "user"],
            None,
        ),
        # Missing permission claim entirely
        ({"some_other_claim": "value"}, ["system"], "Invalid token structure"),
        # Permission claim is not a dict
        (
            {"urn:zitadel:iam:org:project:987654321:roles": "not_a_dict"},
            ["system"],
            "Invalid token structure",
        ),
        # Missing required scope
        (
            {"urn:zitadel:iam:org:project:987654321:roles": {"user": True}},
            ["system"],
            "Not enough permissions",
        ),
        # Empty roles dict
        (
            {"urn:zitadel:iam:org:project:987654321:roles": {}},
            ["system"],
            "Not enough permissions",
        ),
        # Multiple required scopes, missing one
        (
            {"urn:zitadel:iam:org:project:987654321:roles": {"system": True}},
            ["system", "superuser"],
            "Not enough permissions",
        ),
        # No required scopes - should pass
        ({"urn:zitadel:iam:org:project:987654321:roles": {"system": True}}, [], None),
    ],
    ids=[
        "valid_scopes",
        "missing_permission_claim",
        "invalid_claim_type",
        "missing_required_scope",
        "empty_roles",
        "missing_one_of_multiple_scopes",
        "no_required_scopes",
    ],
)
def test_validate_scopes(auth_config, claims, required_scopes, expected_error):
    """
    Test the _validate_scopes method
    """
    auth = ZitadelAuth(auth_config)

    if expected_error:
        with pytest.raises(InvalidAuthException, match=expected_error):
            auth._validate_scopes(claims, required_scopes)
    else:
        result = auth._validate_scopes(claims, required_scopes)
        assert result is True


# Test with different project IDs
@pytest.mark.parametrize(
    "project_id,claims,expected_error",
    [
        # Matching project ID
        (
            "987654321",
            {"urn:zitadel:iam:org:project:987654321:roles": {"system": True}},
            None,
        ),
        # Different project ID
        (
            "different_project",
            {"urn:zitadel:iam:org:project:987654321:roles": {"system": True}},
            "Invalid token structure",
        ),
    ],
    ids=["matching_project_id", "different_project_id"],
)
def test_validate_scopes_project_id(project_id, claims, expected_error):
    """
    Test the _validate_scopes method with different project IDs
    """
    config = AuthConfig(
        base_url="https://issuer.zitadel.cloud",
        client_id="123456789",
        project_id=project_id,
        algorithm="RS256",
        scopes={"system": "system scope"},
    )

    auth = ZitadelAuth(config)

    if expected_error:
        with pytest.raises(InvalidAuthException, match=expected_error):
            auth._validate_scopes(claims, ["system"])
    else:
        result = auth._validate_scopes(claims, ["system"])
        assert result is True


@pytest.mark.asyncio
async def test_missing_token(auth_config):
    """
    Test when the Authorization header is missing
    """
    auth = ZitadelAuth(auth_config)
    request = Request(
        scope={
            "type": "http",
            "headers": [],  # No Authorization header
        }
    )
    scopes = SecurityScopes(scopes=["system"])

    with pytest.raises(HTTPException, match="Not authenticated"):
        await auth(request, scopes)


@pytest.mark.asyncio
async def test_empty_token(auth_config):
    """
    Test when the Authorization header is empty
    """
    auth = ZitadelAuth(auth_config)
    request = Request(
        scope={
            "type": "http",
            "headers": [(b"authorization", b"Bearer ")],  # Empty token
        }
    )
    scopes = SecurityScopes(scopes=["system"])

    with pytest.raises(InvalidAuthException, match="Invalid token format"):
        await auth(request, scopes)


@pytest.mark.asyncio
async def test_unexpected_error(auth_config, mock_jwks, test_keys, mocker):
    """
    Test handling of unexpected errors
    """
    with respx.mock(assert_all_called=False) as mock:
        mock.get(auth_config.jwks_url).mock(
            return_value=httpx.Response(200, json=mock_jwks())
        )

        auth = ZitadelAuth(auth_config)
        token = create_test_token(test_keys)

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", f"Bearer {token}".encode())],
            }
        )
        scopes = SecurityScopes(scopes=["system"])

        # Mock the token validator to raise an unexpected error
        mocker.patch.object(
            auth.token_validator, "verify", side_effect=RuntimeError("Unexpected error")
        )

        with pytest.raises(InvalidAuthException, match="Unable to process token"):
            await auth(request, scopes)


@pytest.mark.asyncio
async def test_malformed_authorization_header(auth_config):
    """
    Test when the Authorization header is malformed
    """
    auth = ZitadelAuth(auth_config)
    request = Request(
        scope={
            "type": "http",
            "headers": [(b"authorization", b"Invalid Format")],  # Not Bearer format
        }
    )
    scopes = SecurityScopes(scopes=["system"])

    with pytest.raises(HTTPException, match="Not authenticated"):
        await auth(request, scopes)

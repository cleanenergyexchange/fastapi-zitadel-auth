"""
Pytest conftest.py file to define fixtures available to all tests
"""

import httpx
import pytest

from demo_project.dependencies import zitadel_auth
from demo_project.main import app
from fastapi_zitadel_auth import ZitadelAuth
from tests.utils import create_openid_keys


@pytest.fixture
def fastapi_app():
    """FastAPI app fixture"""
    zitadel_auth_overrides = ZitadelAuth(
        issuer="https://test-zitadel-xs2hs.zitadel.cloud",
        client_id="123456789",
        project_id="987654321",
        scopes={"scope1": "Some scope"},
    )
    app.dependency_overrides[zitadel_auth] = zitadel_auth_overrides
    yield


@pytest.fixture(autouse=True)
async def reset_openid_config():
    """Reset the OpenID configuration before each test"""
    zitadel_auth.openid_config.last_refresh = None
    zitadel_auth.openid_config.signing_keys = {}
    yield


def openid_configuration() -> dict:
    """OpenID configuration fixture"""
    zitadel_host = "https://test-zitadel-xs2hs.zitadel.cloud"
    return {
        "issuer": zitadel_host,
        "authorization_endpoint": f"{zitadel_host}/oauth/v2/authorize",
        "token_endpoint": f"{zitadel_host}/oauth/v2/token",
        "introspection_endpoint": f"{zitadel_host}/oauth/v2/introspect",
        "userinfo_endpoint": f"{zitadel_host}/oidc/v1/userinfo",
        "revocation_endpoint": f"{zitadel_host}/oauth/v2/revoke",
        "end_session_endpoint": f"{zitadel_host}/oidc/v1/end_session",
        "device_authorization_endpoint": f"{zitadel_host}/oauth/v2/device_authorization",
        "jwks_uri": f"{zitadel_host}/oauth/v2/keys",
        "scopes_supported": [
            "openid",
            "profile",
            "email",
            "phone",
            "address",
            "offline_access",
        ],
        "response_types_supported": ["code", "id_token", "id_token token"],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "request_object_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
        "revocation_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ],
        "revocation_endpoint_auth_signing_alg_values_supported": ["RS256"],
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "private_key_jwt",
        ],
        "introspection_endpoint_auth_signing_alg_values_supported": ["RS256"],
        "claims_supported": [
            "sub",
            "aud",
            "exp",
            "iat",
            "iss",
            "auth_time",
            "nonce",
            "acr",
            "amr",
            "c_hash",
            "at_hash",
            "act",
            "scopes",
            "client_id",
            "azp",
            "preferred_username",
            "name",
            "family_name",
            "given_name",
            "locale",
            "email",
            "email_verified",
            "phone_number",
            "phone_number_verified",
        ],
        "code_challenge_methods_supported": ["S256"],
        "ui_locales_supported": [
            "bg",
            "cs",
            "de",
            "en",
            "es",
            "fr",
            "hu",
            "id",
            "it",
            "ja",
            "ko",
            "mk",
            "nl",
            "pl",
            "pt",
            "ru",
            "sv",
            "zh",
        ],
        "request_parameter_supported": True,
        "request_uri_parameter_supported": False,
    }


def openid_config_url() -> str:
    """OpenID configuration URL fixture"""
    return "https://test-zitadel-xs2hs.zitadel.cloud/.well-known/openid-configuration"


def keys_url() -> str:
    """OpenID keys URL fixture"""
    return "https://test-zitadel-xs2hs.zitadel.cloud/oauth/v2/keys"


@pytest.fixture
def mock_openid(respx_mock):
    """Fixture to mock OpenID configuration"""
    respx_mock.get(openid_config_url()).respond(json=openid_configuration())
    yield


@pytest.fixture
def mock_openid_and_keys(respx_mock, mock_openid):
    """Fixture to mock OpenID configuration and keys"""
    respx_mock.get(keys_url()).respond(json=create_openid_keys())
    yield


@pytest.fixture
def mock_openid_and_empty_keys(respx_mock, mock_openid):
    """Fixture to mock OpenID configuration and empty keys"""
    respx_mock.get(keys_url()).respond(json=create_openid_keys(empty_keys=True))
    yield


@pytest.fixture
def mock_openid_ok_then_empty(respx_mock, mock_openid):
    """Fixture to mock OpenID configuration and keys, first empty then ok"""
    keys_route = respx_mock.get(keys_url())
    keys_route.side_effect = [
        httpx.Response(json=create_openid_keys(), status_code=200),
        httpx.Response(json=create_openid_keys(empty_keys=True), status_code=200),
    ]
    openid_route = respx_mock.get(openid_config_url())
    openid_route.side_effect = [
        httpx.Response(json=openid_configuration(), status_code=200),
        httpx.Response(json=openid_configuration(), status_code=200),
    ]
    yield


@pytest.fixture
def mock_openid_and_no_valid_keys(respx_mock, mock_openid):
    """Fixture to mock OpenID configuration and keys with no valid keys"""
    respx_mock.get(keys_url()).respond(json=create_openid_keys(no_valid_keys=True))
    yield

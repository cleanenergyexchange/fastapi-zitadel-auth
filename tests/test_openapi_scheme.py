"""
Test the OpenAPI schema.
"""

import openapi_spec_validator
from packaging import version

import fastapi
from fastapi_zitadel_auth import __version__

from demo_project.main import app
from tests.utils import ZITADEL_ISSUER

expected_scheme_name = "ZitadelAuth"
expected_description = "OAuth2 Authorization Code Flow with PKCE for Zitadel authentication"

# FastAPI 0.123.8+ changed how scopes are represented in OpenAPI schema
# https://github.com/fastapi/fastapi/pull/14455
# https://github.com/fastapi/fastapi/releases/tag/0.123.8
FASTAPI_VERSION = version.parse(fastapi.__version__)
SCOPES_IN_SECURITY = ["scope1"] if FASTAPI_VERSION >= version.parse("0.123.8") else []

openapi_schema = {
    "openapi": "3.1.0",
    "info": {"title": "fastapi-zitadel-auth demo", "version": __version__},
    "paths": {
        "/api/public": {
            "get": {
                "summary": "Public endpoint",
                "description": "Public endpoint",
                "operationId": "public_api_public_get",
                "responses": {
                    "200": {
                        "description": "Successful Response",
                        "content": {"application/json": {"schema": {}}},
                    }
                },
            }
        },
        "/api/protected/admin": {
            "get": {
                "summary": "Protected endpoint, requires admin role",
                "description": "Protected endpoint",
                "operationId": "protected_for_admin_api_protected_admin_get",
                "responses": {
                    "200": {
                        "description": "Successful Response",
                        "content": {"application/json": {"schema": {}}},
                    }
                },
                "security": [{expected_scheme_name: []}],
            }
        },
        "/api/protected/scope": {
            "get": {
                "summary": "Protected endpoint, requires a specific scope",
                "description": "Protected endpoint, requires a specific scope",
                "operationId": "protected_by_scope_api_protected_scope_get",
                "responses": {
                    "200": {
                        "description": "Successful Response",
                        "content": {"application/json": {"schema": {}}},
                    }
                },
                "security": [{expected_scheme_name: SCOPES_IN_SECURITY}],
            }
        },
    },
    "components": {
        "securitySchemes": {
            expected_scheme_name: {
                "type": "oauth2",
                "description": expected_description,
                "flows": {
                    "authorizationCode": {
                        "scopes": {
                            "openid": "OpenID Connect",
                            "email": "Email",
                            "profile": "Profile",
                            "urn:zitadel:iam:org:project:id:zitadel:aud": "Audience",
                            "urn:zitadel:iam:org:projects:roles": "Projects roles",
                        },
                        "authorizationUrl": f"{ZITADEL_ISSUER}/oauth/v2/authorize",
                        "tokenUrl": f"{ZITADEL_ISSUER}/oauth/v2/token",
                    }
                },
            }
        }
    },
}


def test_openapi_schema(public_client):
    """Test the OpenAPI schema matches to the expected schema"""
    response = public_client.get("/openapi.json")
    assert response.status_code == 200, response.text
    print(response.json())
    assert response.json() == openapi_schema


def test_validate_openapi_spec(public_client):
    """Validate the OpenAPI spec"""
    response = public_client.get("/openapi.json")
    assert response.status_code == 200, response.text
    openapi_spec_validator.validate(response.json())


def test_custom_scheme_name_and_description():
    """Test that custom scheme_name and description from demo app appear in OpenAPI schema"""

    openapi_schema_from_app = app.openapi()
    assert expected_scheme_name in openapi_schema_from_app["components"]["securitySchemes"]
    assert (
        openapi_schema_from_app["components"]["securitySchemes"][expected_scheme_name]["description"]
        == expected_description
    )

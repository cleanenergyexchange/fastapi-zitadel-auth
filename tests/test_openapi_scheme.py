"""
Test the OpenAPI schema.
"""

import openapi_spec_validator

from fastapi_zitadel_auth import __version__
from tests.utils import ZITADEL_ISSUER

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
                "security": [{"ZitadelAuthorizationCodeBearer": []}],
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
                "security": [{"ZitadelAuthorizationCodeBearer": []}],
            }
        },
    },
    "components": {
        "securitySchemes": {
            "ZitadelAuthorizationCodeBearer": {
                "type": "oauth2",
                "description": "Zitadel OAuth2 authentication using bearer token",
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

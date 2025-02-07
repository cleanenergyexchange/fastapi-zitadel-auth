"""
FastAPI dependencies
"""

from fastapi import Depends
from pydantic import Field, model_validator

from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.exceptions import InvalidAuthException
from fastapi_zitadel_auth.user import (
    DefaultZitadelUser,
    BaseZitadelClaims,
    BaseZitadelUser,
)

try:
    from demo_project.settings import get_settings
except ImportError:
    # ImportError handling since it's also used in tests
    from settings import get_settings


settings = get_settings()


class CustomZitadelClaims(BaseZitadelClaims):
    """Custom claims model with additional fields, inheriting from BaseZitadelClaims"""

    # Add your custom claims, e.g. organizations
    organizations: list[str] = Field(default_factory=list, alias="myfield:xyz:orgs")

    project_roles: dict[str, dict[str, str]] = Field(
        default_factory=dict,
    )

    @model_validator(mode="before")
    @classmethod
    def extract_project_roles(cls, values: dict) -> dict:
        """Extract project-specific role claim into project_roles field"""
        for key in values.keys():
            if key.startswith("urn:zitadel:iam:org:project:") and key.endswith(
                ":roles"
            ):
                values["project_roles"] = values[key]
                break
        return values


class CustomZitadelUser(BaseZitadelUser[CustomZitadelClaims]):
    """Custom user model implementation"""

    claims: CustomZitadelClaims

    # Add custom methods if needed
    def get_organizations(self) -> list[str]:
        return self.claims.organizations


zitadel_auth = ZitadelAuth(
    issuer_url=settings.ZITADEL_HOST,
    project_id=settings.ZITADEL_PROJECT_ID,
    app_client_id=settings.OAUTH_CLIENT_ID,
    claims_model=CustomZitadelClaims,
    user_model=CustomZitadelUser,
    allowed_scopes={
        "openid": "OpenID Connect",
        "email": "Email",
        "profile": "Profile",
        "urn:zitadel:iam:org:project:id:zitadel:aud": "Audience",
        "urn:zitadel:iam:org:projects:roles": "Projects roles",
    },
)


async def validate_is_admin_user(
    user: DefaultZitadelUser = Depends(zitadel_auth),
) -> None:
    """Validate that the authenticated user is a user with a specific role"""
    required_role = "user"
    if required_role not in user.claims.project_roles.keys():
        raise InvalidAuthException(f"User does not have role assigned: {required_role}")

"""
FastAPI dependencies
"""

from fastapi import Depends

from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.exceptions import InvalidAuthException
from fastapi_zitadel_auth.user import ZitadelUser

try:
    from demo_project.settings import get_settings
except ImportError:
    # ImportError handling since it's also used in tests
    from settings import get_settings


settings = get_settings()

zitadel_auth = ZitadelAuth(
    issuer=settings.ZITADEL_HOST,
    project_id=settings.ZITADEL_PROJECT_ID,
    client_id=settings.OAUTH_CLIENT_ID,
    scopes={
        "openid": "OpenID Connect",
        "email": "Email",
        "profile": "Profile",
        "urn:zitadel:iam:org:project:id:zitadel:aud": "Audience",
        "urn:zitadel:iam:org:projects:roles": "Projects roles",
    },
)


async def validate_is_system_user(user: ZitadelUser = Depends(zitadel_auth)) -> None:
    """
    Validate that the authenticated user is a user with the system role
    """
    required_role = "system"
    if required_role not in user.claims.project_roles.keys():
        raise InvalidAuthException(f"User does not have role assigned: {required_role}")

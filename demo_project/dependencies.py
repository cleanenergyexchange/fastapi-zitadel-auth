"""
FastAPI dependencies
"""

try:
    from demo_project.settings import get_settings
except ImportError:
    # ImportError handling since it's also used in tests
    from settings import get_settings

from fastapi_zitadel_auth import ZitadelAuth

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
        "urn:zitadel:iam:org:projects:roles": "Roles",
    },
)

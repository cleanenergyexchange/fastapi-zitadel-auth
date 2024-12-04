from settings import get_settings
from fastapi_zitadel_auth import ZitadelAuth, AuthConfig

settings = get_settings()

config = AuthConfig(
    client_id=settings.OAUTH_CLIENT_ID,
    project_id=settings.ZITADEL_PROJECT_ID,
    base_url=settings.ZITADEL_HOST,
    scopes={
        "openid": "OpenID Connect",
        "email": "Email",
        "profile": "Profile",
        "urn:zitadel:iam:org:project:id:zitadel:aud": "Audience",
        "urn:zitadel:iam:org:projects:roles": "Roles",
    },
)

auth = ZitadelAuth(config)

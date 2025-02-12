# FastAPI setup

This guide shows an example of setting up a FastAPI app with Zitadel authentication.


```python
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Security, Depends
from pydantic import HttpUrl
from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.user import DefaultZitadelUser
from fastapi_zitadel_auth.exceptions import ForbiddenException

# IDs from Zitadel console
CLIENT_ID = 'your-zitadel-client-id'
PROJECT_ID = 'your-zitadel-project-id'

# Create a ZitadelAuth object usable as a FastAPI dependency
zitadel_auth = ZitadelAuth(
    issuer_url=HttpUrl('https://your-instance-xyz.zitadel.cloud'),
    project_id=PROJECT_ID,
    app_client_id=CLIENT_ID,
    allowed_scopes={
        "openid": "OpenID Connect",
        "email": "Email",
        "profile": "Profile",
        "urn:zitadel:iam:org:project:id:zitadel:aud": "Audience",
        "urn:zitadel:iam:org:projects:roles": "Roles",
    }
)


# Create a dependency to validate that the user has the required role
async def validate_is_admin_user(user: DefaultZitadelUser = Depends(zitadel_auth)) -> None:
    required_role = "admin"
    if required_role not in user.claims.project_roles.keys():
        raise ForbiddenException(f"User does not have role assigned: {required_role}")


# Load OpenID configuration at startup
@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa
    await zitadel_auth.openid_config.load_config()
    yield


# Create a FastAPI app and configure Swagger UI
app = FastAPI(
    title="fastapi-zitadel-auth demo",
    lifespan=lifespan,
    swagger_ui_oauth2_redirect_url="/oauth2-redirect",
    swagger_ui_init_oauth={
        "usePkceWithAuthorizationCodeGrant": True,
        "clientId": CLIENT_ID,
        "scopes": " ".join(  # defining the pre-selected scope ticks in the Swagger UI
            [
                "openid",
                "profile",
                "email",
                "urn:zitadel:iam:org:projects:roles",
                "urn:zitadel:iam:org:project:id:zitadel:aud",
            ]
        ),
    },
)


# Endpoint that requires a user to be authenticated and have the admin role
@app.get(
    "/api/protected/admin",
    summary="Protected endpoint, requires admin role",
    dependencies=[Security(validate_is_admin_user)],
)
def protected_for_admin(request: Request):
    user = request.state.user
    return {"message": "Hello world!", "user": user}


# Endpoint that requires a user to be authenticated and have a specific scope
@app.get(
    "/api/protected/scope",
    summary="Protected endpoint, requires a specific scope",
    dependencies=[Security(zitadel_auth, scopes=["scope1"])],
)
def protected_by_scope(request: Request):
    user = request.state.user
    return {"message": "Hello world!", "user": user}

```


!!! note "CORS Middleware"

    For production you may need to add a [CORS middleware](https://fastapi.tiangolo.com/tutorial/cors/) to your FastAPI app.

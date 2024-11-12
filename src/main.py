from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Security, Request
import uvicorn
from loguru import logger

from auth import ZitadelAuthorizationCodeBearer
from settings import get_settings

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa
    yield


app = FastAPI(
    title="fastapi-zitadel-auth demo",
    lifespan=lifespan,
    swagger_ui_oauth2_redirect_url="/oauth2-redirect",
    swagger_ui_init_oauth={
        "usePkceWithAuthorizationCodeGrant": True,
        "clientId": settings.OAUTH_CLIENT_ID,
        "scopes": "openid email profile urn:zitadel:iam:org:project:id:zitadel:aud urn:zitadel:iam:org:projects:roles",
    },
)

oauth2_scheme = ZitadelAuthorizationCodeBearer(
    app_client_id=settings.OAUTH_CLIENT_ID,
    scopes={
        "openid": "OpenID Connect",
        "email": "Email",
        "profile": "Profile",
        "urn:zitadel:iam:org:project:id:zitadel:aud": "Audience",
        "urn:zitadel:iam:org:projects:roles": "Roles",
    },
    openapi_authorization_url=f"{settings.ZITADEL_DOMAIN}/oauth/v2/authorize",
    openapi_token_url=f"{settings.ZITADEL_DOMAIN}/oauth/v2/token",
    openapi_description="Zitadel OAuth2 authentication using bearer token",
)


@app.get("/protected", dependencies=[Security(oauth2_scheme, scopes=["user"])])
def protected(request: Request):
    logger.debug(f"User state: {request.state.user}")
    return {"message": "Hello, protected world!"}


if __name__ == "__main__":
    uvicorn.run("main:app", reload=True, port=8001)
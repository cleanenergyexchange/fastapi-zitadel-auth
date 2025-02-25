"""
Sample FastAPI app with Zitadel authentication
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI, Request, Security
from starlette.middleware.cors import CORSMiddleware

from fastapi_zitadel_auth import __version__


try:
    from demo_project.dependencies import zitadel_auth, validate_is_admin_user  # type: ignore[no-redef]
    from demo_project.settings import get_settings  # type: ignore[no-redef]
except ImportError:
    # ImportError handling since it's also used in tests
    from dependencies import zitadel_auth, validate_is_admin_user  # type: ignore[no-redef]
    from settings import get_settings  # type: ignore[no-redef]

settings = get_settings()

# setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=settings.LOG_LEVEL)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger.info(f"Settings: {settings.model_dump_json()}")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Load OpenID config on startup.
    """
    await zitadel_auth.openid_config.load_config()
    yield


app = FastAPI(
    title="fastapi-zitadel-auth demo",
    lifespan=lifespan,
    version=__version__,
    swagger_ui_oauth2_redirect_url="/oauth2-redirect",
    swagger_ui_init_oauth={
        "usePkceWithAuthorizationCodeGrant": True,
        "clientId": settings.OAUTH_CLIENT_ID,
        "scopes": " ".join(
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

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/public", summary="Public endpoint")
def public():
    """Public endpoint"""
    return {"message": "Hello world!"}


@app.get(
    "/api/protected/admin",
    summary="Protected endpoint, requires admin role",
    dependencies=[Security(validate_is_admin_user)],
)
def protected_for_admin(request: Request):
    """Protected endpoint"""
    user = request.state.user
    return {"message": "Hello world!", "user": user}


@app.get(
    "/api/protected/scope",
    summary="Protected endpoint, requires a specific scope",
    dependencies=[Security(zitadel_auth, scopes=["scope1"])],
)
def protected_by_scope(request: Request):
    """Protected endpoint, requires a specific scope"""
    user = request.state.user
    return {"message": "Hello world!", "user": user}


if __name__ == "__main__":
    uvicorn.run("main:app", reload=True, port=8001)

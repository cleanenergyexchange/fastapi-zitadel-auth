"""
Sample FastAPI app with Zitadel authentication
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI, Request, Security
from starlette.middleware.cors import CORSMiddleware

try:
    from demo_project.dependencies import zitadel_auth  # type: ignore[no-redef]
    from demo_project.settings import get_settings  # type: ignore[no-redef]
except ImportError:
    # ImportError handling since it's also used in tests
    from dependencies import zitadel_auth  # type: ignore[no-redef]
    from settings import get_settings  # type: ignore[no-redef]

settings = get_settings()

# setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
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
    swagger_ui_oauth2_redirect_url="/oauth2-redirect",
    swagger_ui_init_oauth={
        "usePkceWithAuthorizationCodeGrant": True,
        "clientId": settings.OAUTH_CLIENT_ID,
        "scopes": " ".join(
            [
                "openid",
                "email",
                "profile",
                "urn:zitadel:iam:org:project:id:zitadel:aud",
                "urn:zitadel:iam:org:projects:roles",
            ]
        ),
    },
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/public", summary="Public endpoint")
def public():
    return {"message": "Hello, public world!"}


@app.get(
    "/api/private",
    summary="Private endpoint, requiring a valid token with `system` scope",
    dependencies=[Security(zitadel_auth, scopes=["user"])],
)
def protected(request: Request):
    logger.debug(f"User object: {request.state.user}")
    logger.debug(f"User claims: {request.state.user.claims}")
    logger.debug(f"User roles: {request.state.user.claims.project_roles}")
    return {
        "message": f"Hello, protected world! Here is Zitadel user {request.state.user.user_id}"
    }


if __name__ == "__main__":
    uvicorn.run("main:app", reload=True, port=8001)

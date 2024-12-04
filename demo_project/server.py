import logging

from fastapi import FastAPI, Security, Request
import uvicorn

from dependencies import auth
from settings import get_settings

settings = get_settings()
print(f"Settings: {settings}")
logger = logging.getLogger("fastapi_zitadel_auth")
logging.basicConfig(level=logging.DEBUG)

app = FastAPI(
    title="fastapi-zitadel-auth demo",
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


@app.get("/api/public", summary="Public endpoint")
def public():
    return {"message": "Hello, public world!"}


@app.get(
    "/api/private",
    summary="Private endpoint, requiring a valid token with `user` scope",
    dependencies=[Security(auth, scopes=["system"])],
)
def protected(request: Request):
    logger.debug(f"User object: {request.state.user}")
    logger.debug(f"User claims: {request.state.user.claims}")
    logger.debug(f"User roles: {request.state.user.claims.project_roles}")
    return {
        "message": f"Hello, protected world! Here is Zitadel user {request.state.user.user_id}"
    }


if __name__ == "__main__":
    uvicorn.run("server:app", reload=True, port=8001)

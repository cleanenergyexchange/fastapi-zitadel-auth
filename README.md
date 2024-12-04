# FastAPI Zitadel Auth

Protect FastAPI endpoints using [Zitadel](https://zitadel.com/).

Features:

* Authorization Code Flow with PKCE
* JWT signature validation using JWKS obtained from Zitadel
* Service User authentication using JWT Profiles
* Swagger UI integration
* Zitadel roles as scopes


> [!WARNING]
> This repo is a work in progress and should not be used in production just yet.


## Installation

```bash
pip install fastapi-zitadel-auth
```


## Usage

### Configuration

#### Zitadel
Set up a new OAuth2 client in Zitadel according to the [docs/ZITADEL_SETUP.md](docs/ZITADEL_SETUP.md).

#### FastAPI

```python
from fastapi import FastAPI, Request, Security
from fastapi_zitadel_auth import ZitadelAuth, AuthConfig

# Your Zitadel configuration
CLIENT_ID = 'your-zitadel-client-id'
PROJECT_ID = 'your-zitadel-project-id'
BASE_URL = 'https://your-instance-xyz.zitadel.cloud'

# Create an AuthConfig object with your Zitadel configuration
config = AuthConfig(
    client_id=CLIENT_ID,
    project_id=PROJECT_ID,
    base_url=BASE_URL,
    scopes={
        "openid": "OpenID Connect",
        "email": "Email",
        "profile": "Profile",
        "urn:zitadel:iam:org:project:id:zitadel:aud": "Audience",
        "urn:zitadel:iam:org:projects:roles": "Roles",
    },
)

# Create a ZitadelAuth object with the AuthConfig usable as a FastAPI dependency
auth = ZitadelAuth(config)

# Create a FastAPI app and configure Swagger UI
app = FastAPI(
    title="fastapi-zitadel-auth demo",
    swagger_ui_oauth2_redirect_url="/oauth2-redirect",
    swagger_ui_init_oauth={
        "usePkceWithAuthorizationCodeGrant": True,
        "clientId": CLIENT_ID,
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

# Create an endpoint and protect it with the ZitadelAuth dependency
@app.get(
    "/api/private",
    summary="Private endpoint, requiring a valid token with `system` scope",
    dependencies=[Security(auth, scopes=["system"])],
)
def private(request: Request):
    return {
        "message": f"Hello, protected world! Here is Zitadel user {request.state.user.user_id}"
    }

```



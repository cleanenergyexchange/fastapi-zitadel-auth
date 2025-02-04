# FastAPI Zitadel Auth

Simplify OAuth2 authentication in FastAPI apps using [**Zitadel**](https://zitadel.com/) as the identity service, 
including token validation, role-based access control, and Swagger UI integration.


<a href="https://github.com/cleanenergyexchange/fastapi-zitadel-auth/actions/workflows/test.yml" target="_blank">
    <img src="https://github.com/cleanenergyexchange/fastapi-zitadel-auth/actions/workflows/test.yml/badge.svg" alt="Test status">
</a>
<a href="https://codecov.io/gh/cleanenergyexchange/fastapi-zitadel-auth">
    <img src="https://codecov.io/gh/cleanenergyexchange/fastapi-zitadel-auth/graph/badge.svg?token=A3TSXDVLQT" alt="Code coverage"/> 
</a>
<a href="https://pypi.org/pypi/fastapi-zitadel-auth">
    <img src="https://img.shields.io/pypi/v/fastapi-zitadel-auth.svg?logo=pypi&logoColor=white&label=pypi" alt="Package version">
</a>
<a href="https://pepy.tech/projects/fastapi-zitadel-auth">
    <img src="https://static.pepy.tech/badge/fastapi-zitadel-auth/month" alt="PyPI Downloads">
</a>
<a href="https://python.org">
    <img src="https://img.shields.io/badge/python-v3.10+-blue.svg?logo=python&logoColor=white&label=python" alt="Python versions">
</a>
<a href="https://github.com/cleanenergyexchange/fastapi-zitadel-auth/blob/main/LICENSE">
    <img src="https://badgen.net/github/license/cleanenergyexchange/fastapi-zitadel-auth/" alt="License"/>
</a>


## Features

* Authorization Code flow with PKCE
* JWT validation using Zitadel JWKS
* Role-based access control using Zitadel roles
* Service user authentication (JWT Profile)
* Swagger UI integration
* Type-safe token validation


> [!NOTE]
> This library implements JWT, locally validated using JWKS, as it prioritizes performance, 
> see [Zitadel docs on Opaque tokens vs JWT](https://zitadel.com/docs/concepts/knowledge/opaque-tokens#use-cases-and-trade-offs).
> If you need to validate opaque tokens using Introspection, please open an issue – PRs are welcome!


## Installation and quick start

```bash
pip install fastapi-zitadel-auth
```

## Usage

### Configuration

#### Zitadel

Set up a project in Zitadel according to [docs/ZITADEL_SETUP.md](docs/ZITADEL_SETUP.md).

#### FastAPI

```python
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Security
from pydantic import HttpUrl
from fastapi_zitadel_auth import ZitadelAuth

# define your Zitadel project ID, client ID and scopes
CLIENT_ID = 'your-zitadel-client-id'
PROJECT_ID = 'your-zitadel-project-id'
SCOPES = {
    "openid": "OpenID Connect",
    "email": "Email",
    "profile": "Profile",
    "urn:zitadel:iam:org:project:id:zitadel:aud": "Audience",
    "urn:zitadel:iam:org:projects:roles": "Roles",
}


# Create a ZitadelAuth object usable as a FastAPI dependency
zitadel_auth = ZitadelAuth(
    issuer=HttpUrl('https://your-instance-xyz.zitadel.cloud'),
    project_id=PROJECT_ID,
    client_id=CLIENT_ID,
    scopes=SCOPES,
)

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
        "scopes": list(SCOPES.keys()),
    },
)


# Create an endpoint and protect it with the ZitadelAuth dependency
@app.get(
    "/api/private",
    summary="Private endpoint, requiring a valid token with `user` scope",
    dependencies=[Security(zitadel_auth, scopes=["user"])],
)
def private(request: Request):
    return {
        "message": f"Hello, protected world! Here is Zitadel user {request.state.user.user_id}"
    }

```

## Demo app

See `demo_project` for a complete example, including service user login. To run the demo app:

```bash
uv run demo_project/main.py
```

Then navigate to `http://localhost:8001/docs` to see the Swagger UI.


### Service user

Service users are "machine users" in Zitadel.

To log in as a service user, change the config in `demo_project/service_user.py`, then

```bash
uv run demo_project/service_user.py
```

Make sure you have a running server at `http://localhost:8001`.

## Development

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for development instructions.
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

```python
from fastapi import FastAPI, Security
from fastapi_zitadel_auth import ZitadelAuth, AuthConfig

auth = ZitadelAuth(AuthConfig(
    client_id="your-client-id",
    project_id="your-project-id",
    zitadel_host="https://your-instance.zitadel.cloud"
))

app = FastAPI(
    swagger_ui_init_oauth={
        "usePkceWithAuthorizationCodeGrant": True,
        "clientId": 'your-client-id',
        "scopes": "openid profile email urn:zitadel:iam:org:project:id:zitadel:aud urn:zitadel:iam:org:projects:roles"
    }
)


@app.get("/protected", dependencies=[Security(auth)])
def protected_route():
    return {"message": "Access granted!"}
```

See the [Usage](#usage) section for more details.

## Usage

### Configuration

#### Zitadel

Set up a project in Zitadel according to [docs/ZITADEL_SETUP.md](docs/ZITADEL_SETUP.md).

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
    zitadel_host=BASE_URL,
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

## Demo app

See `demo_project` for a complete example, including service user login. To run the demo app:

```bash
uv run demo_project/server.py
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
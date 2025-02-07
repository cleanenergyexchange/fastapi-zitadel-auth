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
<a href="https://mypy-lang.org">
    <img src="https://www.mypy-lang.org/static/mypy_badge.svg" alt="mypy">
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
* Extensible claims and user models


> [!NOTE]
> This library implements JWT, locally validated using JWKS, as it prioritizes performance, 
> see [Zitadel docs on Opaque tokens vs JWT](https://zitadel.com/docs/concepts/knowledge/opaque-tokens#use-cases-and-trade-offs).
> If you need to validate opaque tokens using Introspection, please open an issue – PRs are welcome!


## Installation and quick start

```bash
pip install fastapi-zitadel-auth
```

> [!TIP]
> This library is in active development, so breaking changes can occur.
> We recommend **pinning the version** until a stable release is available.


## Usage

### Configuration

#### Zitadel

Set up a project in Zitadel according to [docs/zitadel_setup.md](docs/zitadel_setup.md).

#### FastAPI

```python
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Security, Depends
from pydantic import HttpUrl
from fastapi_zitadel_auth import ZitadelAuth
from fastapi_zitadel_auth.user import DefaultZitadelUser
from fastapi_zitadel_auth.exceptions import InvalidAuthException

# Define your Zitadel project ID, client ID
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
        raise InvalidAuthException(f"User does not have role assigned: {required_role}")


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
    """Protected endpoint, requires admin role"""
    user = request.state.user
    return {"message": "Hello world!", "user": user}


# Endpoint that requires a user to be authenticated
@app.get(
    "/api/protected/scope",
    summary="Protected endpoint, requires a specific scope",
    dependencies=[Security(zitadel_auth, scopes=["scope1"])],
)
def protected_by_scope(request: Request):
    """Protected endpoint, requires a specific scope"""
    user = request.state.user
    return {"message": "Hello world!", "user": user}

```

If you need to customize the claims or user model, see [docs/custom_claims_and_users.md](docs/custom_claims_and_users.md).

## Demo app

See `demo_project` for a complete example, including service user login. 

To run the demo app:

```bash
uv run demo_project/main.py
```

Then navigate to `http://localhost:8001/docs` to see the Swagger UI.


### Service user

Service users are "machine users" in Zitadel.

To log in as a service user, download the private key from Zitadel, change the config in `demo_project/service_user.py`, then

```bash
uv run demo_project/service_user.py
```

Make sure you have a running server at `http://localhost:8001`.

## Development

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for development instructions.

## License

This project is licensed under the terms of the MIT license.

## Acknowledgements

This package was heavily inspired by [`intility/fastapi-azure-auth`](https://github.com/intility/fastapi-azure-auth/).
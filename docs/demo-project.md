# Demo project

See **[demo_project](https://github.com/cleanenergyexchange/fastapi-zitadel-auth/tree/main/demo_project)** for a complete example.

The demo shows:

* Authentication with Zitadel OpenID Connect
* Role-based access control for protected endpoints
* Scope-based authorization for API endpoints
* Service user authentication via JWT
* Swagger UI with OAuth2 integration


## Starting the FastAPI server

* Install dev dependencies: `uv sync --group dev` (see [Contributing](./features-and-bugfixes.md)).
* Run the demo server:

```bash
uv run demo_project/main.py
```

* The server starts at [http://localhost:8001](http://localhost:8001).

## Login

!!! info "User types in Zitadel"

    Zitadel differentiates [two types of users](https://zitadel.com/docs/guides/manage/console/users):

    1. **Users** ("human users", i.e. people with a login)
    2. **Service users** ("machine users", i.e. integration bots).



### User login

1. Open [http://localhost:8001/docs](http://localhost:8001/docs).
2. Click **Authorize** in the top right corner.
3. Click **Authorize** in the modal. Zitadel's login page opens.
4. Log in with your Zitadel credentials. You are redirected back to the docs page.
5. Try out the endpoints.
6. If login fails, retry in a private browsing window.


### Service user login


1. Set up a service user as described in the [setup guide](zitadel-setup.md).
2. Download the private key from Zitadel.
3. Update the config in `demo_project/service_user.py`.
4. Run the script:

```bash
uv run demo_project/service_user.py
```

Expected response:

```json
{
  "message": "Hello world!",
  "user": {
    "claims": {
      "aud": [
        "..."
      ],
      "client_id": "...",
      "exp": 1739406574,
      "iat": 1739363374,
      "iss": "https://myinstance.zitadel.cloud",
      "sub": "...",
      "nbf": 1739363374,
      "jti": "...",
      "project_roles": {
        "admin": {
          "1234567": "hello.xyz.zitadel.cloud"
        }
      }
    },
    "access_token": "eyJhbGciO... (truncated)"
  }
}
```

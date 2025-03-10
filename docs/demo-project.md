# Demo project

Check out the **code folder under [demo_project](https://github.com/cleanenergyexchange/fastapi-zitadel-auth/tree/main/demo_project)** for a complete example.

The demo project will show:

* Authentication with Zitadel OpenID Connect
* Role-based access control for protected endpoints
* Scope-based authorization for API endpoints
* Service user authentication via JWT
* Swagger UI with OAuth2 integration


## Starting the FastAPI server

* Make sure to have `dev` dependencies installed: `uv sync --group dev` (see [Contributing](./features-and-bugfixes.md)).
* Run the demo server using `uv`:

```bash
uv run demo_project/main.py
```

* The server should start at [http://localhost:8001](http://localhost:8001).

## Login

!!! info "User types in Zitadel"

    Zitadel differentiates [two types of users](https://zitadel.com/docs/guides/manage/console/users):

    1. **Users** ("human users", i.e. people with a login)
    2. **Service users** ("machine users", i.e. integration bots).



### User login

1. Navigate to [http://localhost:8001/docs](http://localhost:8001/docs).
2. Click on the **Authorize** button in the top right corner.
3. Click on the **Authorize** button in the modal.
4. You should be **redirected** to the Zitadel login page.
5. **Log in** with your Zitadel credentials.
6. You should be **redirected back** to the FastAPI docs page.
7. You can now try out the endpoints in the docs page.
8. If you encounter issues, try again in a private browsing window.


### Service user login


1. **Set up a service user** as described in the [setup guide](zitadel-setup.md).
2. **Download the private key** from Zitadel.
3. Change the config in `demo_project/service_user.py`.
4. Run the service user script:

```bash
uv run demo_project/service_user.py
```

* You should get a response similar to this:

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

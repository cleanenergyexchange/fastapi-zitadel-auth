# Demo project

Check out the **code folder under [demo_project](https://github.com/cleanenergyexchange/fastapi-zitadel-auth/tree/main/demo_project)** for a complete example.


## Starting the FastAPI server

* Run the demo app using `uv`:

```bash
uv run demo_project/main.py
```

* Navigate to [http://localhost:8001/docs](http://localhost:8001/docs) to see the Swagger UI.


## Service user login

!!! note "Service Users"

    Service users are "machine users", see [Zitadel user types](https://zitadel.com/docs/guides/manage/console/users).

* Set up a service user as described in the [setup guide](zitadel-setup.md).
* Download the private key from Zitadel.
* Change the config in `demo_project/service_user.py`.
* Run the service user script:

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

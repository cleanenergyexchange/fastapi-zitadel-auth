# Demo project

Check out the **code folder under [demo_project](https://github.com/cleanenergyexchange/fastapi-zitadel-auth/tree/main/demo_project)** for a complete example.


## Starting the FastAPI server

* Run the demo server using `uv`:

```bash
uv run demo_project/main.py
```

## Login

!!! info "User types in Zitadel"

    Zitadel differentiates [two types of users](https://zitadel.com/docs/guides/manage/console/users):

    1. **Users** ("human users", i.e. people with a login)
    2. **Service users** ("machine users", i.e. integration bots).



### User login

* Navigate to [http://localhost:8001/docs](http://localhost:8001/docs).
* Click on the **Authorize** button in the top right corner.
* Click on the **Authorize** button in the modal.
* You should be redirected to the Zitadel login page.
* Log in with your Zitadel credentials.
* You should be redirected back to the FastAPI docs page.
* You can now try out the endpoints in the docs page.
* If you encounter issues, try again in a private browsing window.


### Service user login


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

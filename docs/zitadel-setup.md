# Zitadel setup guide

Set up Zitadel for your FastAPI application.

!!! warning "Set up as described"

    This is an opinionated demo setup.
    Follow the steps exactly first; adjust them after it works.


## Project configuration

In your Zitadel console:

1.  Create **New Project**, named `Demo project`

2.  After saving, in the project overview, under **General**, tick:

    1. **Assert Roles on Authentication**
    2. **Check authorization on Authentication**

3. Under **Roles**, create a **new role** (e.g., key = `admin`)

4. Record the **Project Id** ("Resource Id") from the project overview. You'll need this for the `ZitadelAuth` object's `project_id` parameter.

!!! info "Multiple apps in one project"

    The API accepts tokens issued to **any** app in this project. Zitadel
    puts the project ID in every token's
    [`aud` claim](https://zitadel.com/docs/apis/openidoauth/claims#standard-claims);
    the project is the trust boundary.

    To keep two apps apart, use separate projects —
    [roles are project-scoped](https://zitadel.com/docs/concepts/structure/projects).
    To limit an endpoint to one client app, check the `client_id` claim in a
    dependency (see the FastAPI configuration guide).

## Applications

The project requires (at least) two applications:

1.  An API application for service-to-service authentication
2.  A User Agent application for human authentication via Swagger UI


### Application 1: API

Create an API application for service authentication:

1.  In the project overview, create a **New Application**:
    1. Type: **API**
    2. Name: `Demo API` (or your preferred name)
    3. Authentication Method: **Private Key JWT**

2.  After saving, record the **Issuer URL** from the app overview under **URLs**
(e.g., `https://myinstance.zitadel.cloud`).
You'll need this for the `ZitadelAuth` object's `issuer_url` parameter.


### Application 2: User Agent

Create a User Agent application to enable Swagger UI authentication:

1.  In the project overview, create a **New Application**:
    1. Type: **User Agent**
    2. Name: `Swagger UI` (or your preferred name)
    3. Authentication Method: **PKCE**
    4. **Redirect URI:** `http://localhost:8001/oauth2-redirect` (or your FastAPI app URL + `/oauth2-redirect`)
    5. Toggle **Development Mode** for non-HTTPS redirects

2. After saving, go to the app's **Token Settings**:
    1. Set "Auth Token Type" to **JWT**
    2. Enable **Add user roles to access token**
    3. Enable **User roles inside ID token**

3. Record the **client Id** from the overview. You'll need this for the
  `ZitadelAuth` object's `app_client_id` parameter.


## Users

Create two user accounts with the `admin` role (or your chosen role):

1.  A human user for interactive access
2.  A service user for automated processes

For more information, see [Zitadel user types](https://zitadel.com/docs/guides/manage/console/users).

### User 1: Human User

1. Create a **New User**:
    1. Name: `Admin User` (or your preferred name)
    2. Enable **Email Verified** for testing

2. Under **Authorizations**:
    1. Create new authorization
    2. Select your project (e.g., "Demo Project")
    3. Assign your role (e.g., `admin`)

### User 2: Service User

1. Create a **New Service User**:
    1. Username: `Admin Bot` (or your preferred name)
    2. Access Token Type: **JWT**

2. Under **Authorizations**:
    1. Create new authorization
    2. Select your project (e.g., "Demo Project")
    3. Assign your role (e.g., `admin`)

3. Under **Keys**:
    1. Create a new **JSON** key
    2. Download and secure the key file
    3. Update the key file path in `demo_project/service_user.py`

!!! note "Service users and the token audience"

    Service user tokens carry the service user's own `client_id`, not your
    app's. The API accepts them when they request the
    [reserved scope](https://zitadel.com/docs/apis/openidoauth/scopes#reserved-scopes)
    `urn:zitadel:iam:org:project:id:{project_id}:aud`, which adds the
    project ID to `aud`. See `demo_project/service_user.py` and Zitadel's
    [Private Key JWT guide](https://zitadel.com/docs/guides/integrate/service-accounts/private-key-jwt).


!!! success "Configuration complete"

    You should now have:

     - Project Id (`project_id`)
     - Issuer URL (`issuer_url`)
     - User Agent application client Id (`app_client_id`)

    Use these values in the FastAPI configuration (next page).

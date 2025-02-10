# Zitadel setup guide

This guide walks you through setting up Zitadel authentication for your FastAPI application using `fastapi-zitadel-auth`. It covers configuring:
- OAuth2 project settings
- API application for service authentication
- User Agent application for Swagger UI integration
- User and service user permissions

> [!IMPORTANT]
> This guide is an opinionated setup for a demo application.
> It is recommended to run through it exactly as described.
> Only later adjust the settings to fit your use case.


## Project configuration

Head over to the Zitadel console for your instance and create a new project to host the demo application.

1. Create **new project**, name it e.g. `Demo project`
2. After saving, in the project overview, under **General**:
   - [x] **Assert Roles on Authentication**
   - [x] **Check authorization on Authentication**
3. Under **Roles**, create a **new role** (e.g., key = `admin`) and assign to project
4. In the project overview, record the **project ID** ("resource Id" in the portal). This will be the `ZitadelAuth` object's `project_id` in the FastAPI app.


## Applications

For the created project, we will create two applications:

### Application 1: API

Let's create the API application for service authentication.

1. In the project overview, create a **new application**:
   - Type: **API**
   - Name it e.g. `Demo API`
   - Authentication Method: **Private Key JWT**
2. After saving, in the app overview under **URLs**, record the **Issuer** (e.g., `https://myinstance.zitadel.cloud`).
This will be the `ZitadelAuth` object's `issuer_url` in the FastAPI app.


### Application 2: user agent

We will create a User Agent application so that Swagger UI can authenticate users.

1. In the project overview, create a **new application**:
   - Type: **User Agent**
   - Name it e.g. `Swagger UI`
   - Authentication Method: **PKCE**
   - **Redirect URI:** `http://localhost:8001/oauth2-redirect` (or your FastAPI app URL + `/oauth2-redirect`)
   - Toggle **Development Mode** (for non-HTTPS redirects)
2. After saving, go to the app's **Token Settings**:
   - Set "Auth Token Type" to **JWT**
   - [x] **Add user roles to access token**
   - [x] **User roles inside ID token**
3. In the app overview record the **client Id**. This will be the `ZitadelAuth` object's `app_client_id` in the FastAPI app.


## Users

In the Zitadel console, we'll create two users, both with the same role (e.g. `admin`) assigned.
A human user and a service user (machine account) will be created
(see here for [Zitadel user types](https://zitadel.com/docs/guides/manage/console/users)).




### User 1: human user

1. Under **Users**, create a new **User**
   - Name it e.g. `Admin User`.
   - [x] Toggle **Email Verified** for testing purposes.
2. After saving the user, under **Authorizations**:
   - Create new authorization
   - Search for project name, e.g. "Demo project"
   - Assign created role, e.g. `admin`

### User 2: service user

1. Under **Users**, create a new **Service User**
    - Name the "User Name" e.g. `Admin Bot`
    - Select "Access Token Type" to **JWT**
2. After saving the user, under **Authorizations**:
    - Create new authorization
    - Search for project name, e.g. "Demo project"
    - Assign created role, e.g. `admin`
3. Under **Keys**, create a new key with type: **JSON**
4. Download key file and keep it secure.
5. To use this key in the `demo_project`, update the path to the key file in `demo_project/service_user.py`.


Now you have set up the project, applications, and users for the demo application so you should
be able to authenticate with the Service User and within the API docs page using Swagger.

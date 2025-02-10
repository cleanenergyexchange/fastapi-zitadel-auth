# Zitadel setup guide

This guide walks you through setting up Zitadel authentication for your FastAPI application using `fastapi-zitadel-auth`. It covers:
- OAuth2 project configuration
- Service authentication via API application
- User authentication via Swagger UI
- User and service account permissions

> [!IMPORTANT]
> This is an opinionated setup for a demo application.
> Follow the steps exactly as described first.
> Adjust settings for your use case only after a successful implementation.


## Project Configuration

In your Zitadel console:

1. Create **New Project**, named `Demo project`
2. After saving, in the project overview, under **General**, enable:
   - **Assert Roles on Authentication**
   - **Check authorization on Authentication**
3. Under **Roles**, create a **new role** (e.g., key = `admin`)
4. Record the **Project Id** ("Resource Id") from the project overview. You'll need this for the `ZitadelAuth` object's `project_id` parameter.

## Applications

The project requires two applications:
1. An API application for service-to-service authentication
2. A User Agent application for human authentication via Swagger UI


### Application 1: API

Create an API application for service authentication:

1. In the project overview, create a **New Application**:
   - Type: **API**
   - Name: `Demo API` (or your preferred name)
   - Authentication Method: **Private Key JWT**

2. After saving, record the **Issuer URL** from the app overview under **URLs**
(e.g., `https://myinstance.zitadel.cloud`).
You'll need this for the `ZitadelAuth` object's `issuer_url` parameter.


### Application 2: User Agent

Create a User Agent application to enable Swagger UI authentication:

1. In the project overview, create a **New Application**:
   - Type: **User Agent**
   - Name: `Swagger UI` (or your preferred name)
   - Authentication Method: **PKCE**
   - **Redirect URI:** `http://localhost:8001/oauth2-redirect` (or your FastAPI app URL + `/oauth2-redirect`)
   - Toggle **Development Mode** for non-HTTPS redirects

2. After saving, go to the app's **Token Settings**:
   - Set "Auth Token Type" to **JWT**
   - Enable **Add user roles to access token**
   - Enable **User roles inside ID token**

3. Record the **client Id** from the overview. You'll need this for the
  `ZitadelAuth` object's `app_client_id` parameter.


## Users

Create two user accounts with the `admin` role (or your chosen role):
- A human user for interactive access
- A service user for automated processes

For more information, see [Zitadel user types](https://zitadel.com/docs/guides/manage/console/users).

### User 1: Human User

1. Create a **New User**:
   - Name: `Admin User` (or your preferred name)
   - Enable **Email Verified** for testing

2. Under **Authorizations**:
   - Create new authorization
   - Select your project (e.g., "Demo Project")
   - Assign your role (e.g., `admin`)

### User 2: service user

1. Create a **New Service User**:
   - Username: `Admin Bot` (or your preferred name)
   - Access Token Type: **JWT**

2. Under **Authorizations**:
   - Create new authorization
   - Select your project (e.g., "Demo Project")
   - Assign your role (e.g., `admin`)

3. Under **Keys**:
   - Create a new **JSON** key
   - Download and secure the key file
   - Update the key file path in `demo_project/service_user.py`

After completing these steps, you should be able to:
- Authenticate using the service user
- Access the API documentation via Swagger UI with human user authentication

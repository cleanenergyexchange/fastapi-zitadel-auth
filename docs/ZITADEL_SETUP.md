## Zitadel setup

### Project
* Create a new project.
* in the General settings, tick "Assert Roles on Authentication" and "Check authorization on Authentication"
* Note the project ID (also called "resource Id") as `ZITADEL_PROJECT_ID`
* Under Roles, create a new role with key: `user` and Display Name "user" and assign it to the project.

### App 1: API
* Create a new application in the project of type "API" and Authentication Method "JWT (Private Key JWT)"
* Create a key of type "JSON"

### App 2: User Agent
* Create a new application in the project of type "User Agent" and Authentication Method "PKCE".
* Toggle "Development Mode" to allow non-https redirect URIs
* Under "Redirect URIs", add:
  * `http://localhost:8001/`
  * `http://localhost:8001/oauth2-redirect`
* Token settings
  * Change "Auth Token Type" from "Bearer Token" to "JWT"
  * Tick "Add user roles to the access token"
  * Tick "User roles inside ID token"
* Note the Client Id (as `OAUTH_CLIENT_ID`)

### User creation
* Create a new User in the Zitadel instance.
* Under Authorizations, create new authorization by searching for the project name and assign the "user" role to the new user


### Service User creation
* Create a new Service User in the zitadel instance and select the Access Token Type to be "JWT".
* Under Authorizations, create new authorization by searching for the project name and assign the "user" role to the new service user
* Under Keys, create a new key of type "JSON" and note the key ID and download the key (JSON file).
* Update the config in `demo_project/service_user.py`

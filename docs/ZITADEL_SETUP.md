# Zitadel Setup Guide

This guide walks you through setting up Zitadel authentication for your FastAPI application using `fastapi-zitadel-auth`. It covers configuring:
- OAuth2 project settings
- API application for service authentication
- User Agent application for Swagger UI integration
- User and service user permissions

Follow these steps to enable secure authentication and API documentation through Swagger UI.

## Project Configuration
1. Create new project
2. Enable security features in General settings:
   - "Assert Roles on Authentication"
   - "Check authorization on Authentication"
3. Record the **project ID** (resource ID)
4. Create role (e.g., `user`) and assign to project

## API Application Setup
Create application with:
- Type: "API"
- Authentication: "JWT (Private Key JWT)"

## User Agent Application Setup
Create application with:
- Type: "User Agent"
- Authentication: "PKCE"

Configure token settings:
- Set "Auth Token Type" to "JWT"
- Enable "Add user roles to access token"
- Enable "User roles inside ID token"

Configure redirect URIs:
- Add `http://localhost:8001/oauth2-redirect` (or your FastAPI app URL + `/oauth2-redirect`)
- Development Mode: Enable for non-HTTPS redirects (development only)

Record the Client ID.

## User Setup
1. Create user account
2. Grant authorization:
   - Search project
   - Assign created role

## Service User Setup
1. Create service user with JWT access token type
2. Grant project authorization with required role
3. Generate JSON key:
   - Create new key (type: "JSON")
   - Download key file
4. Keep key file secure

To use this key in the demo app, update the path in `demo_project/service_user.py`.

# Aegis Controller API Documentation

This document outlines the API endpoints for the Aegis Controller.

## Role Hierarchy & Access Control

The system implements a hierarchical Role-Based Access Control (RBAC) model.

1.  **Root (`root`)**:
    * **Level**: Super Administrator.
    * **Access**: Full access to all endpoints.
    * **Exclusive Rights**: Only Root can create or delete Roles. Root users cannot be modified or deleted by Admins.

2.  **Admin (`admin`)**:
    * **Level**: Administrator.
    * **Access**: Can manage Services, Users, and view Roles.
    * **Restrictions**: Cannot create/delete Roles. Cannot modify, delete, or reset passwords for `root` users.

3.  **User (`user`)**:
    * **Level**: Standard Client.
    * **Access**: Can access the User Dashboard, view assigned services, and manage active sessions.

---

## API Routes

### 1. Authentication
**Base Access**: Public (Login) or Authenticated Users.

#### Login
* **Endpoint**: `POST /api/auth/login`
* **Description**: Authenticates a user and sets a secure session cookie.
* **Request Body**:
    ```json
    {
      "username": "jdoe",
      "password": "secret_password"
    }
    ```
* **Response**: `200 OK`
    ```json
    {
      "message": "Logged in successfully",
      "role": "admin"
    }
    ```

#### Logout
* **Endpoint**: `POST /api/auth/logout`
* **Description**: Invalidates the current session cookie.
* **Response**: `200 OK` ("Logged out successfully")

#### Update Password
* **Endpoint**: `POST /api/auth/password`
* **Description**: Updates the current user's password.
* **Request Body**:
    ```json
    {
      "old_password": "current_password",
      "new_password": "new_strong_password"
    }
    ```
* **Response**: `200 OK` ("Password updated successfully")

#### Get Current User
* **Endpoint**: `GET /api/auth/me`
* **Description**: Returns details about the currently logged-in user.
* **Response**: `200 OK`
    ```json
    {
      "username": "jdoe",
      "role": "admin",
      "role_id": 2
    }
    ```

---

### 2. Roles (RBAC)
**Base Access**: Admin or Root (Modification of Roles is **Root Only**).

#### Get Roles
* **Endpoint**: `GET /api/roles`
* **Access**: Admin, Root
* **Description**: Retrieves a list of all defined roles.
* **Response**: `200 OK`
    ```json
    [
      { "id": 1, "name": "root", "description": "Super Administrator..." }
    ]
    ```

#### Create Role
* **Endpoint**: `POST /api/roles`
* **Access**: **Root Only**
* **Description**: Creates a new role.
* **Request Body**:
    ```json
    {
      "name": "auditor",
      "description": "Read-only access"
    }
    ```
* **Response**: `201 Created`

#### Delete Role
* **Endpoint**: `DELETE /api/roles/{id}`
* **Access**: **Root Only**
* **Description**: Deletes a role by ID.
* **Response**: `200 OK`

#### Get Role Services
* **Endpoint**: `GET /api/roles/{id}/services`
* **Access**: Admin, Root
* **Description**: Gets all services assigned as base permissions to a specific role.
* **Response**: `200 OK` (List of Service objects)

#### Add Service to Role
* **Endpoint**: `POST /api/roles/{id}/services`
* **Access**: Admin, Root
* **Description**: Links a service to a role.
* **Request Body**:
    ```json
    { "service_id": 5 }
    ```
* **Response**: `200 OK`

#### Remove Service from Role
* **Endpoint**: `DELETE /api/roles/{id}/services/{svc_id}`
* **Access**: Admin, Root
* **Description**: Removes a service link from a role.
* **Response**: `200 OK`

---

### 3. Services (Global Management)
**Base Access**: Admin or Root.

#### Get All Services
* **Endpoint**: `GET /api/services`
* **Description**: Retrieves the global inventory of services.
* **Response**: `200 OK`
    ```json
    [
      {
        "id": 1,
        "name": "Database",
        "ip_port": "10.0.0.5:5432",
        "description": "Primary DB",
        "created_at": "..."
      }
    ]
    ```

#### Create Service
* **Endpoint**: `POST /api/services`
* **Description**: Registers a new service in the system.
* **Request Body**:
    ```json
    {
      "name": "Web Server",
      "ip_port": "192.168.1.50:80",
      "description": "Main public web server"
    }
    ```
* **Response**: `201 Created`

#### Update Service
* **Endpoint**: `PUT /api/services/{id}`
* **Description**: Updates an existing service configuration.
* **Request Body**: Same as Create Service.
* **Response**: `200 OK`

#### Delete Service
* **Endpoint**: `DELETE /api/services/{id}`
* **Description**: Deletes a service from the system.
* **Response**: `200 OK`

---

### 4. User Management (Admin Panel)
**Base Access**: Admin or Root.
*Note: Admins cannot modify, delete, or assign services to Root users.*

#### Get All Users
* **Endpoint**: `GET /api/users`
* **Description**: Retrieves a list of all users.
* **Response**: `200 OK`
    ```json
    [
      { "id": 1, "username": "admin", "role_id": 2, "is_active": true }
    ]
    ```

#### Create User
* **Endpoint**: `POST /api/users`
* **Description**: Creates a new user.
* **Request Body**:
    ```json
    {
      "credentials": {
        "username": "alice",
        "password": "TemporaryPassword123!"
      },
      "role_id": 3
    }
    ```
* **Response**: `201 Created`

#### Delete User
* **Endpoint**: `DELETE /api/users/{id}`
* **Description**: Deletes a user account.
* **Response**: `200 OK`

#### Update User Role
* **Endpoint**: `PUT /api/users/{id}/role`
* **Description**: Changes a user's assigned role.
* **Request Body**:
    ```json
    { "role_id": 2 }
    ```
* **Response**: `200 OK`

#### Reset User Password
* **Endpoint**: `POST /api/users/{id}/reset-password`
* **Description**: Administratively resets a user's password.
* **Request Body**:
    ```json
    { "password": "NewSecretPassword123!" }
    ```
* **Response**: `200 OK`

#### Get User Extra Services
* **Endpoint**: `GET /api/users/{id}/services`
* **Description**: Retrieves specific *extra* services assigned to a user (permissions beyond their role).
* **Response**: `200 OK` (List of Service objects)

#### Add User Extra Service
* **Endpoint**: `POST /api/users/{id}/services`
* **Description**: Grants a user access to a specific service.
* **Request Body**:
    ```json
    { "service_id": 5 }
    ```
* **Response**: `200 OK`

#### Remove User Extra Service
* **Endpoint**: `DELETE /api/users/{id}/services/{svc_id}`
* **Description**: Revokes a specific service permission from a user.
* **Response**: `200 OK`

---

### 5. User Dashboard (Client)
**Base Access**: Authenticated Users.

#### Get My Services
* **Endpoint**: `GET /api/me/services`
* **Description**: Returns all services available to the current user (union of Role-based services and Extra assigned services).
* **Response**: `200 OK` (List of Service objects)

#### Get My Active Services
* **Endpoint**: `GET /api/me/selected`
* **Description**: Returns the list of services currently "selected" (active) for the user.
* **Response**: `200 OK`
    ```json
    [
      {
        "id": 1,
        "name": "Database",
        "time_left": 60,
        "updated_at": "..."
      }
    ]
    ```

#### Select (Activate) Service
* **Endpoint**: `POST /api/me/selected`
* **Description**: Activates a session for a specific service. This triggers the underlying firewall/network rules.
* **Request Body**:
    ```json
    { "service_id": 1 }
    ```
* **Response**: `200 OK` ("Service set to active")

#### Deselect (Deactivate) Service
* **Endpoint**: `DELETE /api/me/selected/{svc_id}`
* **Description**: Deactivates a session for a specific service.
* **Response**: `200 OK` ("Service removed from active list")

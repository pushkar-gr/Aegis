# Aegis Controller Application Guide

This document explains the functional logic of the Aegis Controller, focusing on how Roles, Users, and Services interact to provide a secure, Role-Based Access Control (RBAC) system for network resources.

## Core Concepts

The application is built around three primary entities:

1.  **Services**: These are the protected network resources (e.g., a Database at `10.0.0.5:5432` or a Web Server).
2.  **Roles**: Defined groups of permissions (e.g., `admin`, `auditor`, `staff`). A Role contains a collection of Services.
3.  **Users**: The individuals accessing the system. Every user must have exactly one Role.

---

## 1. Setting Up the Environment (Admin Workflow)

### Initial Access
To begin configuration, log in with the default super-admin credentials:
* **Username**: `root`
* **Password**: `root`

> **Security Warning**: You should change this password immediately after the first login.

### Step 1: Create Services
First, the Administrator defines the "Services" that need protection. A service is simply a name and an IP:Port destination.

* **Action**: `POST /api/services`
* **Example**: Create a service named "Production DB" pointing to `192.168.1.50:5432`.
* **Logic**: This populates the global inventory of available resources.

### Step 2: Create Roles
Next, define the different job functions or access levels in your organization.

* **Action**: `POST /api/roles`
* **Example**: Create a role named "Developer".
* **Hierarchy Note**: The system has a built-in `root` role that cannot be modified by standard admins. `root` has exclusive rights to create or delete other roles.

### Step 3: Assign Services to Roles (Base Permissions)
This is the core of the RBAC model. You link Services to Roles to define the *baseline* access for anyone with that role.

* **Action**: `POST /api/roles/{id}/services`
* **Logic**: If you assign "Production DB" to the "Developer" role, *every* user with the "Developer" role automatically gets access to that database.

---

## 2. Managing Users

### Step 4: Create & Assign Users
When onboarding a user, you create their credentials and assign them a specific `role_id`.

* **Action**: `POST /api/users`
* **Input**: Username, Password, and Role ID.
* **Result**: The user is created and immediately inherits all services associated with their Role.

### Step 5: specific User Exceptions (Extra Permissions)
Sometimes a user needs access to a service *not* included in their standard Role. The system allows "Extra Service" assignments.

* **Action**: `POST /api/users/{id}/services`
* **Logic**: This adds a specific service to *only* that user's allowed list.
* **Net Access Calculation**:
    **User Access** = **{Services in User's Role}** ∪ **{User's Extra Services}**
   

---

## 3. The User Experience (Client Workflow)

Once configured, the end-user interacts with the system via the Dashboard.

### Step 1: Login
The user logs in with their credentials. The system verifies their identity and status (`is_active`).

### Step 2: View Dashboard
The user sees a list of all services they are allowed to access (the union of their Role permissions and Extra permissions).

### Step 3: Activate a Service ("Select")
Access is not "always on." To use a service, the user must explicitly "Select" (activate) it.

* **Action**: `POST /api/me/selected` with the `service_id`.
* **System Response**:
    1.  Verifies the user has permission to access this service.
    2.  Resolves the Service's destination IP and Port.
    3.  **Triggers the Agent**: The controller sends a signal to the network agent to open the firewall for the user's specific IP address.
    4.  **Timer Starts**: The service is marked as "Active" in the `user_active_services` table.

### Step 4: Deactivation
When finished, the user can deselect the service, or the session will eventually expire.

* **Action**: `DELETE /api/me/selected/{id}`
* **System Response**: The controller signals the agent to close the firewall connection for that specific user-service pair.

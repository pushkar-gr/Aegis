// API utility functions
const API = {
    baseURL: window.location.origin,

    // Make authenticated API call
    async request(method, endpoint, body = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        };

        if (body) {
            options.body = JSON.stringify(body);
        }

        try {
            const response = await fetch(`${this.baseURL}${endpoint}`, options);
            
            // Handle unauthorized - redirect to login
            if (response.status === 401) {
                // Clear ALL local state on 401
                localStorage.removeItem('currentUser');
                localStorage.removeItem('userRole');

                if (!endpoint.includes('/auth/login')) {
                    window.location.href = '/static/pages/login.html';
                    return null;
                }
            }

            // Handle other errors (including 401 from login)
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText || `HTTP ${response.status}`);
            }

            // Return response if it has content
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            }
            return await response.text();
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },

    // Auth endpoints
    async login(username, password) {
        const response = await this.request('POST', '/api/auth/login', { username, password });
        if (response) {
            if (response.role) localStorage.setItem('userRole', response.role);
            localStorage.setItem('currentUser', response.username || username); 
        }
        return response;
    },

    async logout() {
        localStorage.removeItem('userRole');
        localStorage.removeItem('currentUser');
        return this.request('POST', '/api/auth/logout');
    },

    async updatePassword(old_password, new_password) {
        return this.request('POST', '/api/auth/password', { old_password, new_password });
    },

    async getCurrentUser() {
        // This makes a network call to verify the HttpOnly cookie
        const user = await this.request('GET', '/api/auth/me');

        if (user && user.username) {
            localStorage.setItem('currentUser', user.username);
            if (user.role) localStorage.setItem('userRole', user.role);
        }
        return user;
    },

    // User dashboard endpoints
    async getMyServices() {
        return this.request('GET', '/api/me/services');
    },

    async getMySelectedServices() {
        return this.request('GET', '/api/me/selected');
    },

    async selectService(service_id) {
        return this.request('POST', '/api/me/selected', { service_id });
    },

    async deselectService(service_id) {
        return this.request('DELETE', `/api/me/selected/${service_id}`);
    },

    // Services endpoints
    async getServices() {
        return this.request('GET', '/api/services');
    },

    async createService(service) {
        return this.request('POST', '/api/services', service);
    },

    async updateService(id, service) {
        return this.request('PUT', `/api/services/${id}`, service);
    },

    async deleteService(id) {
        return this.request('DELETE', `/api/services/${id}`);
    },

    // Users endpoints
    async getUsers() {
        return this.request('GET', '/api/users');
    },

    async createUser(user) {
        return this.request('POST', '/api/users', user);
    },

    async deleteUser(id) {
        return this.request('DELETE', `/api/users/${id}`);
    },

    async updateUserRole(id, role_id) {
        return this.request('PUT', `/api/users/${id}/role`, { role_id });
    },

    async resetUserPassword(id, password) {
        return this.request('POST', `/api/users/${id}/reset-password`, { password });
    },

    async getUserServices(id) {
        return this.request('GET', `/api/users/${id}/services`);
    },

    async addUserService(id, service_id) {
        return this.request('POST', `/api/users/${id}/services`, { service_id });
    },

    async removeUserService(id, service_id) {
        return this.request('DELETE', `/api/users/${id}/services/${service_id}`);
    },

    // Roles endpoints
    async getRoles() {
        return this.request('GET', '/api/roles');
    },

    async createRole(role) {
        return this.request('POST', '/api/roles', role);
    },

    async deleteRole(id) {
        return this.request('DELETE', `/api/roles/${id}`);
    },

    async getRoleServices(id) {
        return this.request('GET', `/api/roles/${id}/services`);
    },

    async addRoleService(id, service_id) {
        return this.request('POST', `/api/roles/${id}/services`, { service_id });
    },

    async removeRoleService(id, service_id) {
        return this.request('DELETE', `/api/roles/${id}/services/${service_id}`);
    }
};

function getCurrentUser() {
    return localStorage.getItem('currentUser');
}

// Get user role from localStorage
function getUserRole() {
    return localStorage.getItem('userRole');
}

// Check if user is authenticated (Client-side check)
function requireAuth() {
    const user = getCurrentUser();
    if (!user) {
        window.location.href = '/static/pages/login.html';
        return false;
    }
    return true;
}

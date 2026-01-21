// Shared UI components

// Create profile dropdown in header
function createProfileDropdown() {
    const username = getCurrentUser();
    if (!username) return '';

    return `
        <div class="relative" id="profileDropdown">
            <button onclick="toggleProfileMenu()" class="flex items-center space-x-2 text-white hover:text-gray-300">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
                </svg>
                <span>${username}</span>
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                </svg>
            </button>
            <div id="profileMenu" class="hidden absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-10">
                <a href="/static/pages/reset-password.html" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">Reset Password</a>
                <button onclick="handleLogout()" class="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">Sign Out</button>
            </div>
        </div>
    `;
}

// Toggle profile menu visibility
function toggleProfileMenu() {
    const menu = document.getElementById('profileMenu');
    menu.classList.toggle('hidden');
}

// Close profile menu when clicking outside
document.addEventListener('click', function(event) {
    const dropdown = document.getElementById('profileDropdown');
    if (dropdown && !dropdown.contains(event.target)) {
        const menu = document.getElementById('profileMenu');
        if (menu) {
            menu.classList.add('hidden');
        }
    }
});

// Handle logout
async function handleLogout() {
    try {
        await API.logout();
        window.location.href = '/static/pages/login.html';
    } catch (error) {
        console.error('Logout failed:', error);
        // Redirect anyway
        window.location.href = '/static/pages/login.html';
    }
}

// Create navigation menu
function createNavigation(currentPage) {
    const username = getCurrentUser();
    if (!username) return '';

    const role = getUserRole();
    
    const navItems = [
        { name: 'Dashboard', page: 'dashboard.html', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6', roles: ['user', 'admin', 'root'] },
        { name: 'Users', page: 'users.html', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z', roles: ['admin', 'root'] },
        { name: 'Services', page: 'services.html', icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01', roles: ['admin', 'root'] },
        { name: 'Roles', page: 'roles.html', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', roles: ['admin', 'root'] }
    ];

    return navItems
        .filter(item => !role || item.roles.includes(role))
        .map(item => `
            <a href="/static/pages/${item.page}" class="${currentPage === item.page ? 'bg-gray-900 text-white' : 'text-gray-300 hover:bg-gray-700 hover:text-white'} px-3 py-2 rounded-md text-sm font-medium flex items-center space-x-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${item.icon}"></path>
                </svg>
                <span>${item.name}</span>
            </a>
        `).join('');
}

// Show toast notification
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer') || createToastContainer();
    const toast = document.createElement('div');
    
    const colors = {
        success: 'bg-green-500',
        error: 'bg-red-500',
        info: 'bg-blue-500',
        warning: 'bg-yellow-500'
    };
    
    toast.className = `${colors[type]} text-white px-6 py-3 rounded-lg shadow-lg mb-2`;
    toast.textContent = message;
    
    toastContainer.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'fixed top-4 right-4 z-50';
    document.body.appendChild(container);
    return container;
}

// Loading spinner
function showLoading() {
    const loading = document.getElementById('loadingSpinner') || createLoadingSpinner();
    loading.classList.remove('hidden');
}

function hideLoading() {
    const loading = document.getElementById('loadingSpinner');
    if (loading) {
        loading.classList.add('hidden');
    }
}

function createLoadingSpinner() {
    const spinner = document.createElement('div');
    spinner.id = 'loadingSpinner';
    spinner.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden';
    spinner.innerHTML = `
        <div class="animate-spin rounded-full h-32 w-32 border-b-2 border-white"></div>
    `;
    document.body.appendChild(spinner);
    return spinner;
}

// Confirm dialog
function confirmDialog(message) {
    return confirm(message);
}

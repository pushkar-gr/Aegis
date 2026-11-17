        let roles = [];
        let allServices = [];
        let roleServicesMap = {}; 

        document.addEventListener('DOMContentLoaded', async () => {
            if (!await requireAuth()) return;

            const user = getCurrentUser();
            const role = getUserRole();
            
             // RBAC
            const currentRole = role ? role.toLowerCase() : '';
            if (currentRole !== 'admin' && currentRole !== 'root') {
                window.location.href = '/static/pages/dashboard.html';
                return;
            } else {
                 const navUsers = document.getElementById('nav-users');
                 const navServices = document.getElementById('nav-services');
                 const navRoles = document.getElementById('nav-roles');
                 if (currentRole !== 'admin' && currentRole !== 'root') {
                   if(navUsers) navUsers.style.display = 'none';
                   if(navServices) navServices.style.display = 'none';
                   if(navRoles) navRoles.style.display = 'none';
                }
            }

            if (user) {
                document.getElementById('userNameDisplay').textContent = user;
                document.getElementById('userRoleDisplay').textContent = (role || 'User').toUpperCase() + ' ACCESS';
            }

            if (role === 'root') {
                document.getElementById('addRoleBtn').classList.remove('hidden');
            }
            
            await loadData();
        });

        async function loadData() {
            try {
                showLoading();
                [roles, allServices] = await Promise.all([
                    API.getRoles(),
                    API.getServices()
                ]);
                renderRoles();
            } catch (error) {
                showToast('Failed to load data', 'error');
            } finally {
                hideLoading();
            }
        }

        function renderRoles() {
            const container = document.getElementById('rolesContainer');
            const userRole = getUserRole();
            const isRoot = userRole === 'root';
            
            if (roles.length === 0) {
                container.innerHTML = `<div class="flex flex-col items-center justify-center py-12 opacity-50 border-2 border-dashed border-white/5 rounded-xl"><span class="material-symbols-outlined text-4xl text-text-muted mb-2">shield_lock</span><p class="text-sm text-text-muted">No roles defined.</p></div>`;
                return;
            }

            container.innerHTML = roles.map(role => {
                let icon = 'security';
                let iconColor = 'text-primary';
                let bgClass = 'bg-primary/10 border-primary/20';

                if (role.name.toLowerCase().includes('admin')) {
                    icon = 'admin_panel_settings';
                    iconColor = 'text-blue-500';
                    bgClass = 'bg-blue-500/10 border-blue-500/20';
                } else if (role.name.toLowerCase().includes('root')) {
                    icon = 'encrypted';
                    iconColor = 'text-red-500';
                    bgClass = 'bg-red-500/10 border-red-500/20';
                } else if (role.name.toLowerCase().includes('user')) {
                    icon = 'person';
                    iconColor = 'text-text-muted';
                    bgClass = 'bg-white/5 border-white/10';
                }

                return `
                <details class="group bg-surface-highlight/10 border border-surface-highlight rounded-xl overflow-hidden mb-4 transition-all hover:border-surface-highlight/80">
                    <summary data-click="loadRoleServicesIfNeeded" data-id="${role.id}" class="flex items-center justify-between p-4 cursor-pointer select-none bg-surface-dark/40 group-open:bg-surface-highlight/20 transition-colors">
                        <div class="flex items-center gap-4">
                            <div class="w-10 h-10 rounded-full ${bgClass} flex items-center justify-center ${iconColor} border">
                                <span class="material-symbols-outlined">${icon}</span>
                            </div>
                            <div>
                                <h3 class="text-white font-bold text-base">${escapeHtml(role.name)}</h3>
                                <p class="text-text-muted text-xs">${escapeHtml(role.description || 'No description provided')}</p>
                            </div>
                        </div>
                        <div class="flex items-center gap-4">
                            ${isRoot ? `
                            <button data-click="deleteRole" data-id="${role.id}" class="p-2 rounded-full hover:bg-red-500/10 text-text-muted hover:text-red-400 transition-colors" title="Delete Role">
                                <span class="material-symbols-outlined text-[20px]">delete</span>
                            </button>
                            ` : ''}
                            <span class="material-symbols-outlined text-text-muted transition-transform duration-300 group-open:rotate-180">expand_more</span>
                        </div>
                    </summary>
                    
                    <div class="p-6 bg-surface-dark/30 border-t border-surface-highlight">
                        <div class="mb-6">
                            <div class="flex items-center justify-between mb-4">
                                <h4 class="text-white text-sm font-bold flex items-center gap-2">
                                    <span class="material-symbols-outlined text-primary text-sm">lock_open</span>
                                    Assigned Services
                                </h4>
                            </div>
                            <div id="role-services-${role.id}" class="bg-surface-dark border border-surface-highlight rounded-lg overflow-hidden min-h-[60px]">
                                <div class="flex items-center justify-center p-4">
                                    <div class="animate-spin rounded-full h-5 w-5 border-b-2 border-primary"></div>
                                </div>
                            </div>
                        </div>

                        <div class="bg-surface-highlight/5 border border-surface-highlight border-dashed rounded-lg p-5">
                            <label class="block text-xs font-medium text-text-muted uppercase tracking-wider mb-3">Grant Access to Service</label>
                            <div class="flex flex-col md:flex-row gap-3">
                                <div class="relative flex-1 group">
                                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                        <span class="material-symbols-outlined text-text-muted group-focus-within:text-primary transition-colors text-lg">search</span>
                                    </div>
                                    <select id="available-services-${role.id}" class="w-full bg-surface-dark border border-surface-highlight rounded-lg text-white text-sm h-10 pl-10 pr-10 focus:ring-1 focus:ring-primary focus:border-primary outline-none appearance-none cursor-pointer transition-shadow">
                                        <option value="">Select Service...</option>
                                    </select>
                                    <span class="material-symbols-outlined absolute right-3 top-2.5 text-text-muted pointer-events-none text-lg">arrow_drop_down</span>
                                </div>
                                <button data-click="addRoleService" data-id="${role.id}" class="h-10 px-6 bg-surface-highlight hover:bg-primary hover:text-surface-dark text-white font-medium text-sm rounded-lg transition-all flex items-center justify-center gap-2 whitespace-nowrap">
                                    <span class="material-symbols-outlined text-lg">add_moderator</span>
                                    Grant Access
                                </button>
                            </div>
                        </div>
                    </div>
                </details>
                `;
            }).join('');
        }

        async function loadRoleServicesIfNeeded(roleId) {
            const container = document.getElementById(`role-services-${roleId}`);
            if (!container) return; 
            
            try {
                const services = await API.getRoleServices(roleId) || [];
                roleServicesMap[roleId] = services;
                renderRoleServices(roleId);
            } catch (error) {
                container.innerHTML = '<p class="p-4 text-red-400 text-xs">Failed to load services.</p>';
            }
        }

        function renderRoleServices(roleId) {
            const container = document.getElementById(`role-services-${roleId}`);
            const availableSelect = document.getElementById(`available-services-${roleId}`);
            
            const roleServices = roleServicesMap[roleId] || [];
            const assignedIds = roleServices.map(s => s.id);
            
            if (roleServices.length === 0) {
                container.innerHTML = `<div class="p-4 text-center text-text-muted text-xs italic">No services assigned to this role.</div>`;
            } else {
                container.innerHTML = `
                    <div class="grid grid-cols-12 gap-4 px-4 py-2 bg-surface-highlight/20 text-[11px] uppercase tracking-wider font-semibold text-text-muted border-b border-surface-highlight">
                        <div class="col-span-8">Service Name</div>
                        <div class="col-span-4 text-right">Action</div>
                    </div>
                ` + roleServices.map(service => `
                    <div class="grid grid-cols-12 gap-4 px-4 py-3 items-center border-b border-surface-highlight/50 hover:bg-surface-highlight/10 transition-colors group/item">
                        <div class="col-span-8 flex items-center gap-3">
                            <div class="w-8 h-8 rounded bg-surface-highlight/30 flex items-center justify-center text-primary">
                                <span class="material-symbols-outlined text-sm">dns</span>
                            </div>
                            <div>
                                <p class="text-white text-sm font-medium">${escapeHtml(service.name)}</p>
                                <p class="text-text-muted text-[10px] font-mono">${escapeHtml(service.hostname)}</p>
                            </div>
                        </div>
                        <div class="col-span-4 text-right">
                            <button data-click="removeRoleService" data-role-id="${roleId}" data-service-id="${service.id}" class="text-text-muted hover:text-red-400 hover:bg-red-400/10 px-2 py-1 rounded transition-colors text-xs font-medium">Remove</button>
                        </div>
                    </div>
                `).join('');
            }

            const availableServices = allServices.filter(s => !assignedIds.includes(s.id));
            availableSelect.innerHTML = '<option value="">Select Service...</option>' + 
                availableServices.map(s => `<option value="${s.id}">${escapeHtml(s.name)} (${escapeHtml(s.hostname)})</option>`).join('');
        }

        function openAddModal() {
            document.getElementById('roleForm').reset();
            document.getElementById('roleModal').classList.remove('hidden');
        }

        function closeRoleModal() { document.getElementById('roleModal').classList.add('hidden'); }

        document.getElementById('roleForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const roleData = {
                name: document.getElementById('roleName').value,
                description: document.getElementById('roleDescription').value
            };
            try {
                showLoading();
                await API.createRole(roleData);
                showToast('Role created', 'success');
                closeRoleModal();
                await loadData();
            } catch (error) { showToast('Error: ' + error.message, 'error'); } finally { hideLoading(); }
        });

        async function deleteRole(roleId) {
            if (!confirmDialog('Delete this role?')) return;
            try { showLoading(); await API.deleteRole(roleId); showToast('Role deleted', 'success'); await loadData(); } catch (error) { showToast('Error: ' + error.message, 'error'); } finally { hideLoading(); }
        }

        async function addRoleService(roleId) {
            const select = document.getElementById(`available-services-${roleId}`);
            if (!select.value) { showToast('Select a service', 'warning'); return; }
            try { await API.addRoleService(roleId, parseInt(select.value)); showToast('Assigned', 'success'); await loadRoleServicesIfNeeded(roleId); } catch (error) { showToast(error.message, 'error'); }
        }

        async function removeRoleService(roleId, serviceId) {
            try { await API.removeRoleService(roleId, serviceId); showToast('Removed', 'success'); await loadRoleServicesIfNeeded(roleId); } catch (error) { showToast(error.message, 'error'); }
        }
    

Object.assign(Actions, {
    openAddModal: () => openAddModal(),
    closeRoleModal: () => closeRoleModal(),
    loadRoleServicesIfNeeded: (el) => loadRoleServicesIfNeeded(Number(el.dataset.id)),
    deleteRole: (el, e) => { e.preventDefault(); deleteRole(Number(el.dataset.id)); },
    addRoleService: (el) => addRoleService(Number(el.dataset.id)),
    removeRoleService: (el) => removeRoleService(Number(el.dataset.roleId), Number(el.dataset.serviceId)),
});

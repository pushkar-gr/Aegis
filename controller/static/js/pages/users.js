        let users = [], roles = [], allServices = [], currentUserServices = [];
        let currentTab = 'list';

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
                 // Even if on this page, hide navigation links for consistency if logic changes
                const navUsers = document.getElementById('nav-users');
                const navServices = document.getElementById('nav-services');
                const navRoles = document.getElementById('nav-roles');
                // Admins see everything, so no hiding needed if logic is strict, but for safety:
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
            
            await loadData();
            switchTab('list');

            document.getElementById('userSearch').addEventListener('input', (e) => {
                const query = e.target.value.toLowerCase();
                const filtered = users.filter(u => u.username.toLowerCase().includes(query));
                renderUsers(filtered);
            });

            document.getElementById('username').addEventListener('input', (e) => {
                checkUserExists();
            });

            document.getElementById('usersTableBody').addEventListener('click', (e) => {
                const button = e.target.closest('button[data-action]');
                if (!button) return;
                
                const userId = parseInt(button.dataset.userId);
                const action = button.dataset.action;
                
                if (action === 'edit') editUser(userId);
                else if (action === 'delete') deleteUser(userId);
            });
        });

        async function loadData() {
            try {
                showLoading();
                [users, roles, allServices] = await Promise.all([
                    API.getUsers(),
                    API.getRoles(),
                    API.getServices()
                ]);
                
                const roleSelect = document.getElementById('roleId');
                roleSelect.innerHTML = '<option value="">Select a role</option>' +
                roles.map(role => `<option value="${role.id}">${escapeHtml(role.name)}</option>`).join('');
                
                renderUsers(users);
            } catch (error) {
                showToast('Failed to load data', 'error');
            } finally {
                hideLoading();
            }
        }

        function switchTab(tab) {
            currentTab = tab;
            const tabList = document.getElementById('tabList');
            const tabEdit = document.getElementById('tabEdit');
            
            const activeClass = "cursor-pointer px-4 flex items-center justify-center rounded-md transition-all bg-background-dark shadow-sm text-white border border-white/5";
            const inactiveClass = "cursor-pointer px-4 flex items-center justify-center rounded-md transition-all text-text-muted hover:text-white hover:bg-white/5";
            
            if (tab === 'list') {
                document.getElementById('listView').classList.remove('hidden');
                document.getElementById('editView').classList.add('hidden');
                document.getElementById('searchContainer').classList.remove('invisible');
                tabList.className = activeClass;
                tabEdit.className = inactiveClass;
            } else {
                document.getElementById('listView').classList.add('hidden');
                document.getElementById('editView').classList.remove('hidden');
                document.getElementById('searchContainer').classList.add('invisible'); // Hide search in edit
                tabList.className = inactiveClass;
                tabEdit.className = activeClass;
            }
        }

        function getRoleName(roleId) {
            const role = roles.find(r => r.id === roleId);
            return role ? escapeHtml(role.name) : `ID: ${roleId}`;
        }

        function renderUsers(userList) {
            const tbody = document.getElementById('usersTableBody');
            
            if (userList.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" class="px-6 py-8 text-center text-text-muted"><p>No users found.</p></td></tr>`;
                return;
            }

            tbody.innerHTML = userList.map(user => `
                <tr class="hover:bg-surface-highlight/20 transition-colors group border-b border-surface-highlight/50">
                    <td class="px-6 py-4 font-mono text-text-muted text-xs">#${user.id}</td>
                    <td class="px-6 py-4">
                        <div class="flex items-center gap-3">
                            <div class="w-8 h-8 rounded-full bg-surface-highlight flex items-center justify-center text-primary font-bold text-xs border border-white/5 uppercase">
                                ${escapeHtml(user.username.substring(0, 2))}
                            </div>
                            <p class="font-medium text-white text-sm">${escapeHtml(user.username)}</p>
                        </div>
                    </td>
                    <td class="px-6 py-4 text-text-muted text-sm">
                        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-surface-highlight border border-white/10 text-gray-300 text-xs font-medium">
                            ${getRoleName(user.role_id)}
                        </span>
                    </td>
                    <td class="px-6 py-4">
                        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full ${user.is_active ? 'bg-green-500/10 border border-green-500/20 text-green-400' : 'bg-red-500/10 border border-red-500/20 text-red-400'} text-xs font-medium">
                            <span class="w-1.5 h-1.5 rounded-full ${user.is_active ? 'bg-green-400 animate-pulse' : 'bg-red-400'}"></span>
                            ${user.is_active ? 'Active' : 'Inactive'}
                        </span>
                    </td>
                    <td class="px-6 py-4 text-right">
                        <div class="flex items-center justify-end gap-2 opacity-60 group-hover:opacity-100 transition-opacity">
                            <button data-action="edit" data-user-id="${user.id}" class="p-1.5 rounded-md hover:bg-surface-highlight text-text-muted hover:text-white transition-colors"><span class="material-symbols-outlined text-[20px]">edit</span></button>
                            <button data-action="delete" data-user-id="${user.id}" class="p-1.5 rounded-md hover:bg-red-900/20 text-text-muted hover:text-red-400 transition-colors"><span class="material-symbols-outlined text-[20px]">delete</span></button>
                        </div>
                    </td>
                </tr>
            `).join('');
        }

        async function checkUserExists() {
            const username = document.getElementById('username').value.trim();
            const currentMode = document.getElementById('isEditMode').value;
            
            if (!username) {
               if(currentMode === 'true') clearForm(true); 
               return;
            }

            const existingUser = users.find(u => u.username === username);
            if (existingUser) {
                const currentId = document.getElementById('userId').value;
                if (currentId != existingUser.id) await switchToEditMode(existingUser);
            } else if (currentMode === 'true') {
                const enteredName = document.getElementById('username').value;
                clearForm(true);
                document.getElementById('username').value = enteredName;
            }
        }
        
        async function switchToEditMode(user) {
            document.getElementById('isEditMode').value = 'true';
            document.getElementById('userId').value = user.id;
            document.getElementById('roleId').value = user.role_id;
            document.getElementById('passwordSection').classList.add('hidden');
            document.getElementById('resetPasswordBtn').classList.remove('hidden');
            document.getElementById('saveUserBtn').textContent = 'Update User';
            await loadUserServices(user.id);
        }

        function clearForm(keepUsername = false) {
            const usernameField = document.getElementById('username');
            const currentUsername = usernameField.value;
            document.getElementById('userForm').reset();
            if (keepUsername) usernameField.value = currentUsername;
            document.getElementById('userId').value = '';
            document.getElementById('isEditMode').value = 'false';
            document.getElementById('passwordSection').classList.remove('hidden');
            document.getElementById('resetPasswordBtn').classList.add('hidden');
            document.getElementById('password').required = true;
            document.getElementById('saveUserBtn').textContent = 'Create User';
            document.getElementById('userServicesContainer').innerHTML = `
                <div class="flex flex-col items-center justify-center py-12 opacity-50 border-2 border-dashed border-white/5 rounded-xl">
                    <span class="material-symbols-outlined text-4xl text-text-muted mb-2">person_add</span>
                    <p class="text-sm text-text-muted">Save the user first to manage services.</p>
                </div>`;
            currentUserServices = [];
        }

        document.getElementById('userForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const isEdit = document.getElementById('isEditMode').value === 'true';
            const userId = document.getElementById('userId').value;
            const username = document.getElementById('username').value;
            const roleId = parseInt(document.getElementById('roleId').value);
            const password = document.getElementById('password').value;

            try {
                showLoading();
                if (isEdit) {
                    await API.updateUserRole(userId, roleId);
                    showToast('User updated successfully', 'success');
                } else {
                    await API.createUser({ credentials: { username, password }, role_id: roleId });
                    showToast('User created successfully', 'success');
                    await loadData(); 
                    const newUser = users.find(u => u.username === username);
                    if(newUser) { await switchToEditMode(newUser); return; }
                    clearForm();
                }
                await loadData();
            } catch (error) {
                showToast('Failed to save user: ' + error.message, 'error');
            } finally {
                hideLoading();
            }
        });

        async function editUser(userId) {
            const user = users.find(u => u.id === userId);
            if (!user) return;
            switchTab('edit');
            document.getElementById('username').value = user.username;
            await switchToEditMode(user);
        }

        async function deleteUser(userId) {
            if (!confirmDialog('Delete user?')) return;
            try {
                showLoading();
                await API.deleteUser(userId);
                showToast('User deleted', 'success');
                await loadData();
            } catch (error) { showToast('Error: ' + error.message, 'error'); } finally { hideLoading(); }
        }

        async function loadUserServices(userId) {
            try {
                currentUserServices = await API.getUserServices(userId) || [];
                renderUserServices(userId);
            } catch (error) { console.error(error); }
        }

        function renderUserServices(userId) {
            const container = document.getElementById('userServicesContainer');
            const assignedIds = currentUserServices.map(s => s.id);
            const available = allServices.filter(s => !assignedIds.includes(s.id));
            
            container.innerHTML = `
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 h-full">
                    <div class="flex flex-col h-full">
                        <div class="flex items-center justify-between mb-2 px-1"><h3 class="font-bold text-white text-sm">Assigned Services <span class="ml-2 px-2 py-0.5 rounded-full bg-green-500/10 text-green-400 text-xs">${currentUserServices.length}</span></h3></div>
                        <div id="assignedUserServices" class="bg-black/20 rounded-xl p-3 border border-white/5 flex-1 min-h-[250px] overflow-y-auto custom-scroll space-y-2">
                            ${currentUserServices.length === 0 ? '<div class="text-text-muted text-xs italic">No services</div>' : currentUserServices.map(s => `
                                <div class="flex justify-between items-center p-3 bg-surface-highlight/30 hover:bg-surface-highlight/50 border border-white/5 rounded-lg group transition-all">
                                    <div class="flex items-center gap-3">
                                        <div class="p-1.5 rounded bg-primary/10 text-primary"><span class="material-symbols-outlined text-[16px]">check_circle</span></div>
                                        <div><p class="font-medium text-white text-sm">${escapeHtml(s.name)}</p><p class="text-xs text-text-muted font-mono">${escapeHtml(s.hostname)}</p></div>
                                    </div>
                                    <button data-action="remove-user-service" data-user-id="${userId}" data-service-id="${s.id}" class="p-1.5 rounded bg-surface-dark border border-white/10 text-red-400 opacity-0 group-hover:opacity-100 hover:bg-red-500/10"><span class="material-symbols-outlined text-[16px]">remove</span></button>
                                </div>`).join('')}
                        </div>
                    </div>
                    <div class="flex flex-col h-full">
                        <div class="flex items-center justify-between mb-2 px-1"><h3 class="font-bold text-white text-sm">Available Services <span class="ml-2 px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 text-xs">${available.length}</span></h3></div>
                        <div id="availableUserServices" class="bg-black/20 rounded-xl p-3 border border-white/5 flex-1 min-h-[250px] overflow-y-auto custom-scroll space-y-2">
                            ${available.length === 0 ? '<div class="text-text-muted text-xs italic">No services available</div>' : available.map(s => `
                                <div class="flex justify-between items-center p-3 bg-surface-highlight/10 hover:bg-surface-highlight/30 border border-white/5 rounded-lg group transition-all">
                                    <div class="flex items-center gap-3 opacity-60 group-hover:opacity-100">
                                        <div class="p-1.5 rounded bg-white/5 text-text-muted"><span class="material-symbols-outlined text-[16px]">dns</span></div>
                                        <div><p class="font-medium text-white text-sm">${escapeHtml(s.name)}</p><p class="text-xs text-text-muted font-mono">${escapeHtml(s.hostname)}</p></div>
                                    </div>
                                    <button data-action="add-user-service" data-user-id="${userId}" data-service-id="${s.id}" class="p-1.5 rounded bg-surface-dark border border-white/10 text-primary opacity-0 group-hover:opacity-100 hover:bg-primary/10"><span class="material-symbols-outlined text-[16px]">add</span></button>
                                </div>`).join('')}
                        </div>
                    </div>
                </div>`;
            
            document.getElementById('assignedUserServices').onclick = (e) => {
                const b = e.target.closest('button[data-action="remove-user-service"]');
                if (b) { e.preventDefault(); removeUserService(parseInt(b.dataset.userId), parseInt(b.dataset.serviceId)); }
            };
            document.getElementById('availableUserServices').onclick = (e) => {
                const b = e.target.closest('button[data-action="add-user-service"]');
                if (b) { e.preventDefault(); addUserService(parseInt(b.dataset.userId), parseInt(b.dataset.serviceId)); }
            };
        }

        async function addUserService(userId, sId) { try { await API.addUserService(userId, sId); showToast('Added', 'success'); await loadUserServices(userId); } catch(e){ showToast(e.message, 'error'); }}
        async function removeUserService(userId, sId) { try { await API.removeUserService(userId, sId); showToast('Removed', 'success'); await loadUserServices(userId); } catch(e){ showToast(e.message, 'error'); }}

        function openResetPasswordModal() { document.getElementById('resetPasswordModal').classList.remove('hidden'); }
        function closeResetPasswordModal() { document.getElementById('resetPasswordModal').classList.add('hidden'); document.getElementById('resetPasswordForm').reset(); }
        document.getElementById('resetPasswordForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            try { showLoading(); await API.resetUserPassword(document.getElementById('userId').value, document.getElementById('newPassword').value); showToast('Password reset', 'success'); closeResetPasswordModal(); } catch(e){ showToast(e.message, 'error'); } finally { hideLoading(); }
        });
    

Object.assign(Actions, {
    switchTab: (el) => switchTab(el.value),
    openResetPasswordModal: () => openResetPasswordModal(),
    closeResetPasswordModal: () => closeResetPasswordModal(),
    clearForm: () => clearForm(),
});

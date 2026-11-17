        let services = [];

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
            
            await loadServices();

            document.getElementById('serviceSearch').addEventListener('input', (e) => {
                const query = e.target.value.toLowerCase();
                renderServices(services.filter(s => 
                    s.name.toLowerCase().includes(query) || 
                    s.hostname.toLowerCase().includes(query) ||
                    (s.description && s.description.toLowerCase().includes(query))
                ));
            });

            document.getElementById('servicesTableBody').addEventListener('click', (e) => {
                const button = e.target.closest('button[data-action]');
                if (!button) return;
                
                const serviceId = parseInt(button.dataset.serviceId);
                const action = button.dataset.action;
                
                if (action === 'edit') openEditModal(serviceId);
                else if (action === 'delete') deleteService(serviceId);
            });
        });

        async function loadServices() {
            try {
                showLoading();
                services = await API.getServices() || [];
                renderServices(services);
            } catch (error) {
                showToast('Failed to load services', 'error');
            } finally {
                hideLoading();
            }
        }

        function renderServices(list) {
            const tbody = document.getElementById('servicesTableBody');
            
            if (list.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" class="px-6 py-8 text-center text-text-muted"><div class="flex flex-col items-center"><span class="material-symbols-outlined text-4xl mb-2 opacity-50">dns</span><p>No services found.</p></div></td></tr>`;
                return;
            }

            tbody.innerHTML = list.map(service => `
                <tr class="group hover:bg-surface-highlight/20 transition-colors border-b border-surface-highlight/50">
                     <td class="px-6 py-4 font-mono text-xs text-text-muted group-hover:text-primary transition-colors">#${service.id}</td>
                    <td class="px-6 py-4">
                        <div class="flex items-center gap-3">
                            <div class="w-2 h-2 rounded-full bg-primary shadow-[0_0_8px_rgba(19,236,91,0.6)]"></div>
                            <span class="font-medium text-white text-sm">${escapeHtml(service.name)}</span>
                        </div>
                    </td>
                    <td class="px-6 py-4 font-mono text-xs text-gray-400">${escapeHtml(service.hostname)}</td>
                    <td class="px-6 py-4 text-gray-400 text-sm max-w-xs truncate" title="${escapeHtml(service.description || '')}">${escapeHtml(service.description || '-')}</td>
                    <td class="px-6 py-4 text-right whitespace-nowrap text-sm font-medium">
                        <div class="flex items-center justify-end gap-2 opacity-60 group-hover:opacity-100 transition-opacity">
                            <button data-action="edit" data-service-id="${service.id}" class="p-1.5 rounded-md hover:bg-surface-highlight text-text-muted hover:text-white transition-colors"><span class="material-symbols-outlined text-[18px]">edit</span></button>
                            <button data-action="delete" data-service-id="${service.id}" class="p-1.5 rounded-md hover:bg-red-500/10 text-text-muted hover:text-red-400 transition-colors"><span class="material-symbols-outlined text-[18px]">delete</span></button>
                        </div>
                    </td>
                </tr>
            `).join('');
        }

        function openAddModal() {
            document.getElementById('modalTitle').textContent = 'Add Service';
            document.getElementById('serviceForm').reset();
            document.getElementById('serviceId').value = '';
            document.getElementById('serviceModal').classList.remove('hidden');
        }

        function openEditModal(serviceId) {
            const service = services.find(s => s.id === serviceId);
            if (!service) return;
            document.getElementById('modalTitle').textContent = 'Edit Service';
            document.getElementById('serviceId').value = service.id;
            document.getElementById('serviceName').value = service.name;
            document.getElementById('serviceHostname').value = service.hostname;
            document.getElementById('serviceDescription').value = service.description || '';
            document.getElementById('serviceModal').classList.remove('hidden');
        }

        function closeModal() { document.getElementById('serviceModal').classList.add('hidden'); }

        document.getElementById('serviceForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const serviceId = document.getElementById('serviceId').value;
            const serviceData = {
                name: document.getElementById('serviceName').value,
                hostname: document.getElementById('serviceHostname').value,
                description: document.getElementById('serviceDescription').value
            };
            try {
                showLoading();
                if (serviceId) { await API.updateService(serviceId, serviceData); showToast('Updated', 'success'); } 
                else { await API.createService(serviceData); showToast('Created', 'success'); }
                closeModal();
                await loadServices();
            } catch (error) { showToast('Error: ' + error.message, 'error'); } finally { hideLoading(); }
        });

        async function deleteService(serviceId) {
            if (!confirmDialog('Delete this service?')) return;
            try { showLoading(); await API.deleteService(serviceId); showToast('Deleted', 'success'); await loadServices(); } 
            catch (error) { showToast('Error: ' + error.message, 'error'); } finally { hideLoading(); }
        }
    

Object.assign(Actions, {
    loadServices: () => loadServices(),
    openAddModal: () => openAddModal(),
    closeModal: () => closeModal(),
});

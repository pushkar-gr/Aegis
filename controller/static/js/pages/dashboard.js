        let currentTab = 'all';
        let allServices = [];
        let selectedServices = [];
        let searchQuery = '';

        document.addEventListener('DOMContentLoaded', async () => {
            if (!await requireAuth()) return;

            const user = getCurrentUser();
            const role = getUserRole();
            
            // RBAC: Hide Restricted Menu Items for non-admin/root
            const currentRole = role ? role.toLowerCase() : '';
            if (currentRole !== 'admin' && currentRole !== 'root') {
                const navUsers = document.getElementById('nav-users');
                const navServices = document.getElementById('nav-services');
                const navRoles = document.getElementById('nav-roles');
                if(navUsers) navUsers.style.display = 'none';
                if(navServices) navServices.style.display = 'none';
                if(navRoles) navRoles.style.display = 'none';
            }

            if (user) {
                document.getElementById('userNameDisplay').textContent = user;
                document.getElementById('userRoleDisplay').textContent = (role || 'User').toUpperCase() + ' ACCESS';
            }
            
            await loadServices();
            updateTabStyles();

            document.getElementById('searchBox').addEventListener('input', (e) => {
                searchQuery = e.target.value.toLowerCase();
                renderServices();
            });

            document.getElementById('servicesList').addEventListener('click', (e) => {
                const button = e.target.closest('button[data-action]');
                if (!button) return;
                
                const serviceId = parseInt(button.dataset.serviceId);
                const action = button.dataset.action;
                
                if (action === 'toggle') {
                    const isSelected = button.dataset.isSelected === 'true';
                    toggleService(serviceId, isSelected);
                } else if (action === 'deselect') {
                    deselectService(serviceId);
                }
            });

            setInterval(async () => {
                if (currentTab === 'selected') {
                    await loadSelectedServices();
                    renderServices();
                }
            }, 10000);

            setInterval(() => {
                updateCountdowns();
            }, 1000);
        });

        async function loadServices() {
            try {
                showLoading();
                allServices = await API.getMyServices() || [];
                await loadSelectedServices();
                renderServices();
            } catch (error) {
                showToast('Failed to load services', 'error');
            } finally {
                hideLoading();
            }
        }

        async function loadSelectedServices() {
            try {
                const services = await API.getMySelectedServices() || [];
                selectedServices = services.map(service => {
                    const updatedAt = new Date(service.updated_at);
                    const now = new Date();
                    const elapsedSeconds = Math.floor((now - updatedAt) / 1000);
                    const actualTimeLeft = Math.max(0, service.time_left - elapsedSeconds);
                    return {
                        ...service,
                        calculated_time_left: actualTimeLeft,
                        last_update_time: now
                    };
                });
            } catch (error) {
                console.error('Failed to load selected services:', error);
            }
        }

        function switchTab(tab) {
            currentTab = tab;
            updateTabStyles();
            renderServices();
        }

        function updateTabStyles() {
            const labelAll = document.getElementById('labelAll');
            const labelSelected = document.getElementById('labelSelected');
            
            const activeClass = "bg-background-dark shadow-sm text-white";
            const inactiveClass = "text-text-muted hover:text-white hover:bg-white/5";
            
            if (currentTab === 'all') {
                labelAll.className = `cursor-pointer px-4 flex items-center justify-center rounded-md transition-all ${activeClass}`;
                labelSelected.className = `cursor-pointer px-4 flex items-center justify-center rounded-md transition-all ${inactiveClass}`;
            } else {
                labelAll.className = `cursor-pointer px-4 flex items-center justify-center rounded-md transition-all ${inactiveClass}`;
                labelSelected.className = `cursor-pointer px-4 flex items-center justify-center rounded-md transition-all ${activeClass}`;
            }
        }

        function renderServices() {
            const container = document.getElementById('servicesList');
            const emptyState = document.getElementById('emptyState');
            
            let services = currentTab === 'all' ? allServices : selectedServices;
            
            if (searchQuery) {
                services = services.filter(s => 
                    s.name.toLowerCase().includes(searchQuery) ||
                    (s.description && s.description.toLowerCase().includes(searchQuery)) ||
                    s.hostname.toLowerCase().includes(searchQuery)
                );
            }
            
            if (services.length === 0) {
                container.innerHTML = '';
                emptyState.classList.remove('hidden');
                return;
            }
            
            emptyState.classList.add('hidden');
            
            container.innerHTML = services.map(service => {
                const isSelected = selectedServices.some(s => s.id === service.id);
                const selectedService = selectedServices.find(s => s.id === service.id);
                
                if (isSelected) {
                    const timeLeft = selectedService ? selectedService.calculated_time_left : 60;
                    const dashOffset = 100 - ((timeLeft / 60) * 100);
                    
                    return `
                    <div class="bg-surface-highlight/40 border border-surface-highlight rounded-xl p-4 flex flex-col gap-3 hover:border-primary/30 transition-all group relative overflow-hidden">
                        <div class="absolute top-0 left-0 w-1 h-full bg-primary/20 group-hover:bg-primary transition-colors"></div>
                        <div class="flex justify-between items-start pl-2">
                            <div>
                                <div class="flex items-center gap-2 mb-1">
                                    <div class="relative flex h-2.5 w-2.5">
                                        <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                                        <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-primary"></span>
                                    </div>
                                    <h3 class="text-white font-bold text-base truncate">${escapeHtml(service.name)}</h3>
                                </div>
                                <p class="text-text-muted text-[10px] font-mono bg-black/20 px-1.5 py-0.5 rounded w-fit">${escapeHtml(service.hostname)}</p>
                            </div>
                            <div class="relative h-10 w-10 flex items-center justify-center">
                                <svg class="transform -rotate-90 w-full h-full" viewBox="0 0 36 36">
                                    <path class="text-surface-highlight" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" stroke-width="3"></path>
                                    <path id="circle-${service.id}" class="text-primary timer-circle" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" stroke-dasharray="100, 100" stroke-dashoffset="${dashOffset}" stroke-linecap="round" stroke-width="3"></path>
                                </svg>
                                <div id="timer-text-${service.id}" class="absolute inset-0 flex items-center justify-center text-[8px] font-mono font-bold text-primary">
                                    ${timeLeft}s
                                </div>
                            </div>
                        </div>
                        <p class="text-xs text-gray-400 leading-relaxed pl-2 line-clamp-2">${escapeHtml(service.description || 'No description provided.')}</p>
                        <div class="mt-auto flex items-center justify-end pt-3 border-t border-white/5 pl-2">
                            <button data-service-id="${service.id}" data-action="deselect" class="px-3 py-1.5 rounded-md border border-white/10 text-white text-[10px] font-medium hover:bg-white/5 hover:border-white/20 transition-all uppercase tracking-wider">
                                Deselect
                            </button>
                        </div>
                    </div>
                    `;
                }
                
                return `
                <div class="bg-surface-highlight/10 border border-surface-highlight rounded-xl p-4 flex flex-col gap-3 hover:border-white/10 transition-all group relative overflow-hidden opacity-80 hover:opacity-100">
                    <div class="absolute top-0 left-0 w-1 h-full bg-gray-600 transition-colors"></div>
                    <div class="flex justify-between items-start pl-2">
                        <div>
                            <div class="flex items-center gap-2 mb-1">
                                <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-gray-600"></span>
                                <h3 class="text-gray-300 font-bold text-base truncate">${escapeHtml(service.name)}</h3>
                            </div>
                            <p class="text-gray-500 text-[10px] font-mono bg-black/20 px-1.5 py-0.5 rounded w-fit">${escapeHtml(service.hostname)}</p>
                        </div>
                        <div class="w-10 h-10 rounded-full bg-surface-highlight/30 flex items-center justify-center text-gray-500 border border-white/5">
                            <span class="material-symbols-outlined text-[20px]">dns</span>
                        </div>
                    </div>
                    <p class="text-xs text-gray-500 leading-relaxed pl-2 line-clamp-2">${escapeHtml(service.description || 'No description provided.')}</p>
                    <div class="mt-auto flex items-center justify-end pt-3 border-t border-white/5 pl-2">
                        <button data-service-id="${service.id}" data-is-selected="false" data-action="toggle" class="w-full px-3 py-1.5 rounded-md bg-primary text-surface-dark text-[10px] font-bold hover:bg-primary-hover shadow-[0_0_10px_rgba(19,236,91,0.1)] hover:shadow-[0_0_15px_rgba(19,236,91,0.3)] transition-all flex items-center justify-center gap-1 uppercase tracking-wider">
                            <span class="material-symbols-outlined text-[14px]">bolt</span> Activate
                        </button>
                    </div>
                </div>
                `;
            }).join('');
        }

        function updateCountdowns() {
            selectedServices.forEach(service => {
                const timerText = document.getElementById(`timer-text-${service.id}`);
                const circle = document.getElementById(`circle-${service.id}`);
                
                if (timerText && service.calculated_time_left > 0) {
                    service.calculated_time_left--;
                    timerText.textContent = `${service.calculated_time_left}s`;
                    const percentage = (service.calculated_time_left / 60) * 100;
                    const offset = 100 - percentage;
                    if(circle) circle.style.strokeDashoffset = offset;
                    if (service.calculated_time_left <= 0) {
                        deselectService(service.id);
                    }
                }
            });
        }

        async function toggleService(serviceId, isSelected) {
            try {
                if (isSelected) {
                    await API.deselectService(serviceId);
                    showToast('Service deselected', 'success');
                } else {
                    await API.selectService(serviceId);
                    showToast('Service selected', 'success');
                }
                await loadSelectedServices();
                renderServices();
            } catch (error) {
                showToast('Failed to update service', 'error');
            }
        }

        async function deselectService(serviceId) {
            try {
                await API.deselectService(serviceId);
                showToast('Service removed', 'success');
                await loadSelectedServices();
                renderServices();
            } catch (error) {
                showToast('Failed to remove service', 'error');
            }
        }
    

Object.assign(Actions, {
    switchTab: (el) => switchTab(el.value),
    loadServices: () => loadServices(),
});

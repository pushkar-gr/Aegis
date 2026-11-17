        (async () => {
            if (!await requireAuth()) return;
        })();

        document.getElementById('resetPasswordForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const oldPassword = document.getElementById('oldPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const msgContainer = document.getElementById('messageContainer');
            
            // Basic validation
            if (newPassword !== confirmPassword) {
                showMessage('New passwords do not match.', 'error');
                return;
            }
            if (newPassword.length < 6) {
                showMessage('Password must be at least 6 characters.', 'error');
                return;
            }

            try {
                showLoading(); // Assuming showLoading is in components.js or defined inline
                await API.updatePassword(oldPassword, newPassword);
                
                showMessage('Password updated successfully! Redirecting...', 'success');
                document.getElementById('resetPasswordForm').reset();
                
                setTimeout(() => {
                    window.location.href = '/static/pages/dashboard.html';
                }, 2000);
                
            } catch (error) {
                showMessage(error.message || 'Failed to update password.', 'error');
            } finally {
                hideLoading();
            }
        });

        function showMessage(msg, type) {
            const container = document.getElementById('messageContainer');
            container.textContent = msg;
            container.classList.remove('hidden', 'bg-red-900/20', 'border-red-500/20', 'text-red-400', 'bg-green-900/20', 'border-green-500/20', 'text-green-400');
            
            if (type === 'error') {
                container.classList.add('bg-red-900/20', 'border-red-500/20', 'text-red-400');
            } else {
                container.classList.add('bg-green-900/20', 'border-green-500/20', 'text-green-400');
            }
            container.classList.remove('hidden');
        }
    

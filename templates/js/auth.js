document.addEventListener('DOMContentLoaded', () => {
    const changePasswordForm = document.getElementById('change-password-form');
    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', handleChangePassword);
    }
});

async function handleChangePassword(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    const messagePlaceholder = document.getElementById('message-placeholder');
    messagePlaceholder.textContent = '';

    const newPassword = formData.get('new_password');
    const confirmNewPassword = formData.get('confirm_new_password');

    if (newPassword !== confirmNewPassword) {
        messagePlaceholder.className = 'error';
        messagePlaceholder.textContent = 'New passwords do not match.';
        return;
    }

    try {
        const response = await fetch(form.action, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams(formData)
        });

        const data = await response.json();

        if (!response.ok) {
            messagePlaceholder.className = 'error';
            messagePlaceholder.textContent = data.error || `Error: ${response.statusText}`;
        } else {
            messagePlaceholder.className = 'success';
            messagePlaceholder.textContent = data.message || 'Password updated successfully.';
        }

    } catch (error) {
        console.error('Password change failed:', error);
        messagePlaceholder.className = 'error';
        messagePlaceholder.textContent = 'An unexpected error occurred.';
    }
}
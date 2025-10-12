/**
 * A wrapper for the fetch API that standardizes API calls.
 * It automatically sets the Content-Type for POST requests
 * and handles non-OK responses.
 * @param {string} url The URL to fetch.
 * @param {object} options The options for the fetch call.
 * @returns {Promise<Response>}
 */
async function fetchApi(url, options = {}) {
    const xsrfToken = document.querySelector('meta[name="xsrf-token"]').getAttribute('content');

    options.headers = {
        ...options.headers,
        'X-XSRF-Token': xsrfToken
    };

    // Set content type for methods that have a body.
    if (options.method === 'POST' || options.method === 'PUT') {
        options.headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(url, options);

    // Redirect to login if unauthorized.
    if (response.status === 401) {
        window.location.href = LOGIN_PATH;
        // Throw an error to stop further processing
        throw new Error('Unauthorized');
    }

    return response;
}

function updateRole(userId) {
    const role = document.getElementById(`role-${userId}`).value;
    fetchApi(`${API_BASE_PATH}/${userId}/role`, {
        method: 'POST',
        body: JSON.stringify({ role })
    }).then(handleResponse);
}

function deleteUser(userId) {
    if (confirm('Are you sure you want to permanently delete this user?')) {
        fetchApi(`${API_BASE_PATH}/${userId}`, {
            method: 'DELETE'
        }).then(handleResponse);
    }
}

function toggleActive(userId, isActive) {
    const action = isActive ? 'activate' : 'deactivate';
    if (confirm(`Are you sure you want to ${action} this user?`)) {
        fetchApi(`${API_BASE_PATH}/${userId}/status`, {
            method: 'POST',
            body: JSON.stringify({ is_active: isActive })
        }).then(handleResponse);
    }
}

function handleResponse(response) {
    if (response.ok) {
        location.reload();
    } else {
        alert('Operation failed.');
    }
}

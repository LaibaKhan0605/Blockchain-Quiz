// --- Helper Functions for UI ---

function showStatus(elementId, message, type = 'info') {
    const statusElement = document.getElementById(elementId);
    statusElement.textContent = message;
    statusElement.className = `status-message show ${type}`; // Add show and type class
    setTimeout(() => {
        statusElement.classList.remove('show');
    }, 5000); // Hide after 5 seconds
}

function addLog(message) {
    const logList = document.getElementById('transactionLog');
    const newItem = document.createElement('li');
    newItem.textContent = message; // Log message already contains timestamp from backend
    logList.prepend(newItem); // Add to the top
    // The backend limits log size, so no need for frontend to limit here
}

function updateCommitmentList(commitments) {
    const commitmentList = document.getElementById('commitmentList');
    commitmentList.innerHTML = ''; // Clear existing list
    if (commitments && commitments.length > 0) {
        commitments.forEach(commitment => {
            const newItem = document.createElement('li');
            newItem.textContent = commitment;
            commitmentList.appendChild(newItem);
        });
    } else {
        const newItem = document.createElement('li');
        newItem.textContent = "No commitments in the pool yet.";
        commitmentList.appendChild(newItem);
    }
    document.getElementById('anonymitySetCount').textContent = commitments ? commitments.length : 0;
}

function updateSystemStatus(statusData) {
    document.getElementById('merkleRootDisplay').textContent = statusData.merkle_root || 'N/A';
    document.getElementById('nullifierCountDisplay').textContent = statusData.used_nullifiers_count;
    updateCommitmentList(statusData.commitments_sample); // Update commitments with the sample from status
    const logList = document.getElementById('transactionLog');
    logList.innerHTML = ''; // Clear current log
    statusData.transaction_log.reverse().forEach(logEntry => addLog(logEntry)); // Add all logs from backend (reversed to show newest first)
}


// --- Interaction with Python Backend ---

// Since Flask is served from the same domain/port, no need for full URL like 'http://localhost:5000'
const API_BASE_URL = ''; // Relative path, Flask will handle it

async function generateSecret() {
    // This is a client-side generation for convenience in the UI.
    // In a real system, the secret might be generated on the backend or more securely.
    const secret = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    document.getElementById('depositSecret').value = secret;
    showStatus('depositStatus', 'New secret generated!', 'info');
    // addLog('Secret generated locally.'); (Backend now logs for consistency)
}

async function depositFunds() {
    const secret = document.getElementById('depositSecret').value;
    if (!secret) {
        showStatus('depositStatus', 'Please generate or enter a secret!', 'error');
        return;
    }

    // addLog(`Attempting to deposit for secret: ${secret.substring(0, 5)}...`); (Backend now logs)
    try {
        const response = await fetch(`${API_BASE_URL}/deposit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ secret: secret }),
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showStatus('depositStatus', data.message, 'success');
            // Clear the secret input after successful deposit (optional, for security)
            document.getElementById('depositSecret').value = '';
            // Refresh system status
            fetchSystemStatus();
        } else {
            showStatus('depositStatus', data.message || 'Deposit failed.', 'error');
        }
    } catch (error) {
        console.error('Error during deposit:', error);
        showStatus('depositStatus', 'Network error or server unavailable.', 'error');
    }
}

async function withdrawFunds() {
    const secret = document.getElementById('withdrawSecret').value;
    if (!secret) {
        showStatus('withdrawStatus', 'Please enter your secret key!', 'error');
        return;
    }

    // addLog(`Attempting to withdraw for secret: ${secret.substring(0, 5)}...`); (Backend now logs)
    try {
        const response = await fetch(`${API_BASE_URL}/withdraw`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ secret: secret }),
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showStatus('withdrawStatus', data.message, 'success');
            // Clear the secret input after successful withdrawal
            document.getElementById('withdrawSecret').value = '';
            // Refresh system status
            fetchSystemStatus();
        } else {
            showStatus('withdrawStatus', data.message || 'Withdrawal failed.', 'error');
        }
    } catch (error) {
        console.error('Error during withdrawal:', error);
        showStatus('withdrawStatus', 'Network error or server unavailable.', 'error');
    }
}

async function fetchSystemStatus() {
    try {
        const response = await fetch(`${API_BASE_URL}/status`);
        const data = await response.json();
        if (response.ok) {
            updateSystemStatus(data);
        } else {
            console.error('Failed to fetch system status:', data.error);
        }
    } catch (error) {
        console.error('Error fetching system status:', error);
    }
}


// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    fetchSystemStatus();
    // Use setInterval to periodically refresh status (e.g., every 5 seconds)
    setInterval(fetchSystemStatus, 5000); // Refresh every 5 seconds
});
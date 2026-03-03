// billing.js

window.API_BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:3000'
    : 'https://fastfood-api-v2-2025-44464ec83c8a.herokuapp.com';

document.addEventListener('DOMContentLoaded', async () => {
    console.log('Billing page loaded');
    const token = localStorage.getItem('fastfoodinsight_token');
    if (!token) {
        window.location.href = 'FastFoodInsight-AI.html?requiresLogin=true';
        return;
    }

    try {
        const userRes = await fetch('/api/auth/verify', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const userData = await userRes.json();
        if (!userData.success) throw new Error('Invalid token');
        window.currentUser = userData.user;
        displayUserInfo(userData.user);
    } catch (error) {
        console.error('Auth error:', error);
        showNotification('Session expired. Please login again.', 'error');
        localStorage.removeItem('fastfoodinsight_token');
        setTimeout(() => {
            window.location.href = 'FastFoodInsight-AI.html';
        }, 2000);
        return;
    }

    await subscriptionManager.init();
    renderSubscription();
});

function displayUserInfo(user) {
    document.getElementById('accountEmail').textContent = user.email;
    document.getElementById('accountName').textContent = user.name || 'Not set';
}

function renderSubscription() {
    const sub = subscriptionManager.currentSubscription;
    if (!sub) return;

    const statusEl = document.getElementById('planStatus');
    const planEl = document.getElementById('planName');
    const expiryEl = document.getElementById('planExpiry');
    const daysEl = document.getElementById('daysLeft');
    const cancelSection = document.getElementById('cancelSection');

    let statusText = '', planText = '', expiryText = '', daysText = '';
    let showCancel = false;

    const daysRemaining = sub.days_remaining !== undefined ? sub.days_remaining :
        (sub.subscription_expiry ? calculateDaysRemaining(sub.subscription_expiry) : 30);

    switch (sub.subscription_status) {
        case 'active':
            statusText = '✅ Active';
            planText = sub.subscription_plan === 'premium' ? 'Premium' : 'Basic';
            expiryText = sub.subscription_expiry ? new Date(sub.subscription_expiry).toLocaleDateString() : 'N/A';
            daysText = `${daysRemaining} days`;
            showCancel = true;
            break;
        case 'free_trial':
            statusText = '🎁 Free Trial';
            planText = 'Trial';
            expiryText = sub.subscription_expiry ? new Date(sub.subscription_expiry).toLocaleDateString() : '30 days from signup';
            daysText = `${daysRemaining} days`;
            showCancel = false;
            break;
        case 'cancelled':
            statusText = '⚠️ Cancelled';
            planText = sub.subscription_plan ? (sub.subscription_plan === 'premium' ? 'Premium' : 'Basic') : 'None';
            expiryText = sub.subscription_expiry ? new Date(sub.subscription_expiry).toLocaleDateString() : 'N/A';
            daysText = 'Expired';
            showCancel = false;
            break;
        case 'expired':
            statusText = '⏰ Expired';
            planText = sub.subscription_plan ? (sub.subscription_plan === 'premium' ? 'Premium' : 'Basic') : 'None';
            expiryText = sub.subscription_expiry ? new Date(sub.subscription_expiry).toLocaleDateString() : 'N/A';
            daysText = '0 days';
            showCancel = false;
            break;
        default:
            statusText = 'Free';
            planText = 'Trial';
            expiryText = 'N/A';
            daysText = '30 days';
    }

    statusEl.textContent = statusText;
    planEl.textContent = planText;
    expiryEl.textContent = expiryText;
    daysEl.textContent = daysText;
    cancelSection.style.display = showCancel ? 'block' : 'none';

    updatePricingButtons();
}

function calculateDaysRemaining(expiry) {
    if (!expiry) return 30;
    const diff = new Date(expiry) - new Date();
    return Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24)));
}

function updatePricingButtons() {
    const sub = subscriptionManager.currentSubscription;
    if (!sub) return;

    const basicBtn = document.querySelector('.subscribe-btn.basic');
    const premiumBtn = document.querySelector('.subscribe-btn.premium');
    if (!basicBtn || !premiumBtn) return;

    // Reset classes and text
    basicBtn.classList.remove('current-plan');
    premiumBtn.classList.remove('current-plan');
    basicBtn.disabled = false;
    premiumBtn.disabled = false;
    basicBtn.textContent = 'Subscribe';
    premiumBtn.textContent = 'Subscribe';

    if (sub.subscription_status === 'active') {
        if (sub.subscription_plan === 'basic') {
            // Basic user: disable basic, enable premium
            basicBtn.textContent = 'Current Plan';
            basicBtn.classList.add('current-plan');
            basicBtn.disabled = true;
            // premium stays enabled
        } else if (sub.subscription_plan === 'premium') {
            // Premium user: disable both buttons
            basicBtn.textContent = 'Basic (Not Available)';
            basicBtn.classList.add('current-plan');
            basicBtn.disabled = true;
            premiumBtn.textContent = 'Current Plan';
            premiumBtn.classList.add('current-plan');
            premiumBtn.disabled = true;
        }
    }
    // Free trial or no active plan: both enabled
}

async function handlePlanClick(planName) {
    const sub = subscriptionManager.currentSubscription;
    if (!sub) {
        window.location.href = 'FastFoodInsight-AI.html?requiresLogin=true';
        return;
    }

    // If already on Premium, block any plan (should be disabled, but just in case)
    if (sub.subscription_status === 'active' && sub.subscription_plan === 'premium') {
        showNotification('You are already on the Premium plan.', 'info');
        return;
    }

    // If trying to subscribe to the same plan they already have
    if (sub.subscription_status === 'active' && sub.subscription_plan === planName) {
        showNotification(`You are already on the ${planName === 'basic' ? 'Basic' : 'Premium'} plan.`, 'info');
        return;
    }

    // Proceed to checkout (upgrade/downgrade)
    await subscriptionManager.createSubscription(planName);
}

// Name editing
let originalName = '';

function editName() {
    const nameSpan = document.getElementById('accountName');
    originalName = nameSpan.textContent;
    document.getElementById('editNameInput').value = originalName;
    document.getElementById('nameEditContainer').style.display = 'block';
    nameSpan.style.display = 'none';
}

function cancelNameEdit() {
    document.getElementById('nameEditContainer').style.display = 'none';
    document.getElementById('accountName').style.display = 'inline';
}

async function saveName() {
    const newName = document.getElementById('editNameInput').value.trim();
    if (!newName || newName.length < 2) {
        showNotification('Name must be at least 2 characters.', 'error');
        return;
    }
    try {
        const token = localStorage.getItem('fastfoodinsight_token');
        const response = await fetch('/api/auth/update-name', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ name: newName })
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('accountName').textContent = newName;
            cancelNameEdit();
            showNotification('Name updated successfully.', 'success');
        } else {
            showNotification(data.error || 'Failed to update name.', 'error');
        }
    } catch (error) {
        console.error('Name update error:', error);
        showNotification('Error updating name.', 'error');
    }
}

// Cancel subscription
async function cancelSubscription() {
    const cancelBtn = document.querySelector('.cancel-btn');
    if (!cancelBtn) return;

    const originalHTML = cancelBtn.innerHTML;
    cancelBtn.disabled = true;
    cancelBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cancelling...';

    const result = await subscriptionManager.cancelSubscription();

    if (result.success) {
        showNotification('Subscription cancelled. You will have access until the end of the billing period.', 'success');
        await subscriptionManager.loadUserSubscription();
        renderSubscription();
    } else if (!result.cancelled) {
        showNotification(result.error || 'Failed to cancel.', 'error');
    }

    cancelBtn.disabled = false;
    cancelBtn.innerHTML = originalHTML;
}

// Notification helper
function showNotification(message, type = 'info') {
    const existing = document.querySelector('.notification');
    if (existing) existing.remove();

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    setTimeout(() => notification.classList.add('show'), 10);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

// Mobile sidebar toggle
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const isMobile = window.innerWidth <= 1200;
    if (isMobile) {
        sidebar.classList.toggle('mobile-visible');
        document.body.style.overflow = sidebar.classList.contains('mobile-visible') ? 'hidden' : 'auto';
    }
}

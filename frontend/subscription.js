// ===================== SUBSCRIPTION MANAGER =====================

class SubscriptionManager {
    constructor() {
        this.currentSubscription = null;
    }

    async init() {
        await this.loadUserSubscription();
    }

    async loadUserSubscription() {
        const token = localStorage.getItem('fastfoodinsight_token');

        if (!token) {
            this.currentSubscription = { subscription_status: 'anonymous' };
            return;
        }

        try {
            const response = await fetch('/api/subscriptions/status', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await response.json();
            this.currentSubscription = data.success ? data.subscription : { subscription_status: 'free_trial' };
        } catch (error) {
            console.error('Error loading subscription:', error);
            this.currentSubscription = { subscription_status: 'free_trial' };
        }
    }

    async createSubscription(planName) {
        const token = localStorage.getItem('fastfoodinsight_token');
        if (!token) {
            alert('❌ Please sign in first to subscribe.');
            return;
        }

        try {
            const response = await fetch(`${window.API_BASE_URL}/api/subscriptions/create`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ planName })
            });

            const text = await response.text();
            const data = JSON.parse(text);
            if (data.success && data.checkoutUrl) {
                window.location.href = data.checkoutUrl;
            } else {
                alert('❌ Failed to start subscription.');
            }
        } catch (error) {
            console.error('Subscription error:', error);
            alert('❌ Something went wrong.');
        }
    }

    async cancelSubscription() {
        const token = localStorage.getItem('fastfoodinsight_token');
        if (!token) return { success: false, error: 'Not authenticated' };

        if (!confirm('Cancel your subscription?')) return { success: false, cancelled: true };

        try {
            const response = await fetch('/api/subscriptions/cancel', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await response.json();

            if (data.success) {
                await this.loadUserSubscription();
                return { success: true };
            } else {
                return { success: false, error: data.error || 'Failed to cancel' };
            }
        } catch (error) {
            console.error(error);
            return { success: false, error: error.message };
        }
    }

    getStatusBadgeHTML() {
        const sub = this.currentSubscription;
        if (!sub) return '';
        const status = sub.subscription_status;
        const plan = sub.subscription_plan;
        if (status === 'active') {
            return `<span class="badge badge-success">👑 ${plan === 'premium' ? 'Premium' : 'Basic'} Active</span>`;
        }
        if (status === 'cancelled') return `<span class="badge badge-warning">⚠ Cancelled</span>`;
        if (status === 'expired') return `<span class="badge badge-danger">⏰ Expired</span>`;
        if (status === 'free_trial') return `<span class="badge badge-info">🎁 Free Trial</span>`;
        return `<span class="badge badge-secondary">Free</span>`;
    }
}

// Global instance
const subscriptionManager = new SubscriptionManager();

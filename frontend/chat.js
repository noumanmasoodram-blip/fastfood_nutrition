let googleSignInRetryCount = 0;
let googleOAuthInitialized = false;
let currentState = {
    goal: 'basic',
    isProcessing: false,
    messageHistory: [],
    user: null,
    anonymousId: null,
    chatHistory: [],
    usage: {
        totalMessages: 0,
        remainingMessages: 10,
        maxMessages: 10,
        blocked: false
    },
    currentChatSession: null,
    chatSessions: []
};

function safeSetElementHTML(element, html) {
    if (!html) {
        element.textContent = '';
        return;
    }
    if (typeof DOMPurify !== 'undefined') {
        element.innerHTML = DOMPurify.sanitize(html);
    } else {
        const cleanHTML = html
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+="[^"]*"/gi, '')
            .replace(/on\w+='[^']*'/gi, '')
            .replace(/on\w+=\w+/gi, '');
        element.innerHTML = cleanHTML;
    }
}

function handleVerificationPopup(data) {
    if (data.requiresVerification && data.showVerificationPopup) {
        showVerificationModal(data.email || '');
        showNotification(data.message || 'Please verify your email to continue.', 'warning');
    }
}

function showLoginForm() {
    document.getElementById('emailPasswordForm').style.display = 'block';
    document.getElementById('signupForm').style.display = 'none';
    clearErrors();
}

function showSignupForm() {
    document.getElementById('emailPasswordForm').style.display = 'none';
    document.getElementById('signupForm').style.display = 'block';
    clearErrors();
}

function showForgotPassword() {
    document.getElementById('emailPasswordForm').style.display = 'none';
    document.getElementById('signupForm').style.display = 'none';
    document.getElementById('forgotPasswordForm').style.display = 'block';
    clearErrors();
}

function setAuthToken(token) {
    localStorage.setItem('fastfoodinsight_token', token);
    document.cookie = `fastfoodinsight_token=${token}; path=/; max-age=${7 * 24 * 60 * 60}; samesite=strict`;
    if (token) {
        const originalFetch = window.fetch;
        window.fetch = function(url, options = {}) {
            if (typeof url === 'string' && url.startsWith('/api/')) {
                options.headers = options.headers || {};
                if (!options.headers['Authorization'] && token) {
                    options.headers['Authorization'] = `Bearer ${token}`;
                }
            }
            return originalFetch.call(this, url, options);
        };
    }
    console.log('🔐 Token set in localStorage and cookies');
}

async function handleEmailPasswordLogin() {
    const emailInput = document.getElementById('loginEmail');
    const passwordInput = document.getElementById('loginPassword');
    const emailError = document.getElementById('emailError');
    const passwordError = document.getElementById('passwordError');

    const email = (emailInput?.value || '').trim();
    const password = (passwordInput?.value || '');

    if (emailError) { emailError.textContent = ''; emailError.classList.remove('active'); }
    if (passwordError) { passwordError.textContent = ''; passwordError.classList.remove('active'); }

    if (!email || !email.includes('@')) {
        if (emailError) {
            emailError.textContent = 'Please enter a valid email address';
            emailError.classList.add('active');
        }
        return;
    }
    if (!password || password.length < 6) {
        if (passwordError) {
            passwordError.textContent = 'Password must be at least 6 characters';
            passwordError.classList.add('active');
        }
        return;
    }

    const submitButton = document.querySelector('#emailPasswordForm .btn-primary');
    const originalText = submitButton?.innerHTML || 'Signing in...';
    if (submitButton) {
        submitButton.disabled = true;
        submitButton.innerHTML = '<div class="loading"></div> Signing in...';
    }

    try {
        console.log('🔐 Sending login request');
        const resp = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await resp.json();
        console.log('📨 Login response:', data);
        if (data.success && data.token) {
            setAuthToken(data.token);
            currentState.user = data.user || null;
            hideLoginModal();
            updateAuthUI(true);
            showNotification(`✅ Welcome back, ${data.user?.name || 'User'}!`, 'success');
            await createNewChatSession();
            await loadChatSessions();
            checkUsage();
            await testAuthToken();
            return;
        }
        if (data.requiresVerification || data.showVerificationPopup) {
            console.log('⚠️ User needs verification');
            const loginModal = document.getElementById('loginModal');
            if (loginModal) {
                loginModal.classList.remove('active');
                loginModal.style.display = 'none';
            }
            document.body.style.overflow = 'auto';
            const verificationModal = document.getElementById('verificationModal');
            const verifyEmailInput = document.getElementById('verifyEmail');
            const verifyCodeInput = document.getElementById('verifyCode');
            if (verifyEmailInput) verifyEmailInput.value = email;
            if (verifyCodeInput) verifyCodeInput.value = '';
            if (verificationModal) {
                verificationModal.classList.add('active');
                verificationModal.style.display = 'flex';
                document.body.style.overflow = 'hidden';
                setTimeout(() => verifyCodeInput?.focus(), 100);
            }
            showNotification('📧 Check your email for verification code!', 'warning');
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.innerHTML = originalText;
            }
            return;
        }
        if (resp.ok && data.success && data.token) {
            localStorage.setItem('fastfoodinsight_token', data.token);
            currentState.user = data.user || null;
            const loginModal = document.getElementById('loginModal');
            if (loginModal) {
                loginModal.classList.remove('active');
                loginModal.style.display = 'none';
            }
            document.body.style.overflow = 'auto';
            updateAuthUI(true);
            showNotification(`✅ Welcome back, ${data.user?.name || 'User'}!`, 'success');
            if (typeof createNewChatSession === 'function') await createNewChatSession();
            if (typeof loadChatSessions === 'function') await loadChatSessions();
            if (typeof checkUsage === 'function') checkUsage();
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.innerHTML = originalText;
            }
            return;
        }
        const errMsg = data.error || data.message || 'Invalid email or password';
        if (passwordError) {
            passwordError.textContent = errMsg;
            passwordError.classList.add('active');
        }
    } catch (err) {
        console.error('❌ Login error:', err);
        if (passwordError) {
            passwordError.textContent = 'Login failed. Please try again.';
            passwordError.classList.add('active');
        }
    } finally {
        if (submitButton) {
            submitButton.disabled = false;
            submitButton.innerHTML = originalText;
        }
    }
}

async function testAuthToken() {
    const token = localStorage.getItem('fastfoodinsight_token');
    if (!token) return false;
    try {
        const response = await fetch('/api/auth/verify', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        console.log('🔐 Token test result:', data);
        return data.success;
    } catch (error) {
        console.error('❌ Token test failed:', error);
        return false;
    }
}

async function handleEmailSignup() {
    const nameInput = document.getElementById('signupName');
    const emailInput = document.getElementById('signupEmail');
    const passwordInput = document.getElementById('signupPassword');
    const confirmInput = document.getElementById('signupConfirmPassword');

    const name = nameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const confirmPassword = confirmInput.value;

    document.querySelectorAll('#signupForm .form-error').forEach(el => {
        el.textContent = '';
        el.classList.remove('active');
    });

    if (!name || name.length < 2) {
        document.getElementById('signupNameError').textContent = 'Name must be at least 2 characters';
        document.getElementById('signupNameError').classList.add('active');
        return;
    }
    if (!email || !email.includes('@')) {
        document.getElementById('signupEmailError').textContent = 'Please enter a valid email';
        document.getElementById('signupEmailError').classList.add('active');
        return;
    }
    if (!password || password.length < 8) {
        document.getElementById('signupPasswordError').textContent = 'Password must be at least 8 characters';
        document.getElementById('signupPasswordError').classList.add('active');
        return;
    }
    if (password !== confirmPassword) {
        document.getElementById('signupConfirmError').textContent = 'Passwords do not match';
        document.getElementById('signupConfirmError').classList.add('active');
        return;
    }

    const submitButton = document.querySelector('#signupForm .btn-primary');
    const originalText = submitButton.innerHTML;
    submitButton.disabled = true;
    submitButton.innerHTML = '<div class="loading"></div> Creating account...';

    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password })
        });
        const data = await response.json();
        if (data.requiresVerification || data.showVerificationPopup) {
            const loginModal = document.getElementById('loginModal');
            if (loginModal) {
                loginModal.classList.remove('active');
                loginModal.style.display = 'none';
            }
            document.body.style.overflow = 'auto';
            showVerificationModal(email);
            showNotification('✅ Account created! Check your email for verification code.', 'success');
            return;
        }
        if (data.success) {
            localStorage.setItem('fastfoodinsight_token', data.token);
            currentState.user = data.user;
            updateAuthUI(true);
            hideLoginModal();
            showNotification(`Welcome ${data.user.name}!`, 'success');
            await createNewChatSession();
            await loadChatSessions();
            checkUsage();
        } else {
            document.getElementById('signupEmailError').textContent = data.error || 'Registration failed';
            document.getElementById('signupEmailError').classList.add('active');
        }
    } catch (error) {
        console.error('Signup error:', error);
        document.getElementById('signupEmailError').textContent = 'Registration failed. Please try again.';
        document.getElementById('signupEmailError').classList.add('active');
    } finally {
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
    }
}

async function handleVerifyCode() {
    const email = document.getElementById('verifyEmail').value.trim();
    const code = document.getElementById('verifyCode').value.trim();
    const errorEl = document.getElementById('verifyError');

    errorEl.textContent = '';
    if (!email || !code) {
        errorEl.textContent = 'Email and code are required';
        return;
    }
    if (code.length !== 6) {
        errorEl.textContent = 'Please enter a 6-digit code';
        return;
    }

    const verifyButton = document.querySelector('#verificationModal .btn-primary');
    const originalText = verifyButton.innerHTML;
    verifyButton.disabled = true;
    verifyButton.innerHTML = '<div class="loading"></div> Verifying...';

    try {
        const res = await fetch('/api/auth/verify-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, code })
        });
        const data = await res.json();
        if (data.success && data.token) {
            localStorage.setItem('fastfoodinsight_token', data.token);
            currentState.user = data.user;
            updateAuthUI(true);
            hideVerificationModal();
            showNotification('✅ Email verified and logged in!', 'success');
            await createNewChatSession();
            await loadChatSessions();
            checkUsage();
        } else {
            errorEl.textContent = data.error || 'Invalid code';
        }
    } catch (err) {
        console.error('Verify error:', err);
        errorEl.textContent = 'Verification failed';
    } finally {
        verifyButton.disabled = false;
        verifyButton.innerHTML = originalText;
    }
}

async function resendVerificationCode() {
    const email = document.getElementById('verifyEmail').value.trim();
    if (!email) {
        showNotification('No email to resend to', 'warning');
        return;
    }
    const resendButton = document.querySelector('#verificationModal .btn-secondary');
    const originalText = resendButton.innerHTML;
    resendButton.disabled = true;
    resendButton.innerHTML = '<div class="loading"></div> Sending...';
    try {
        const res = await fetch('/api/auth/resend-verification', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();
        if (data.success) {
            showNotification('✅ New code sent to your email', 'success');
        } else {
            showNotification(data.error || 'Failed to resend', 'error');
        }
    } catch (err) {
        console.error('Resend error:', err);
        showNotification('Failed to resend code', 'error');
    } finally {
        resendButton.disabled = false;
        resendButton.innerHTML = originalText;
    }
}

async function handleForgotPassword() {
    const emailInput = document.getElementById('forgotEmail');
    const emailError = document.getElementById('forgotEmailError');
    const email = emailInput.value.trim();
    emailError.textContent = '';
    emailError.classList.remove('active');
    if (!email || !email.includes('@')) {
        emailError.textContent = 'Please enter a valid email address';
        emailError.classList.add('active');
        return;
    }
    const submitButton = document.querySelector('#forgotPasswordForm .btn-primary');
    const originalText = submitButton.innerHTML;
    submitButton.disabled = true;
    submitButton.innerHTML = '<div class="loading"></div> Sending...';
    try {
        const response = await fetch('/api/auth/forgot-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await response.json();
        if (data.success) {
            showNotification('Password reset link sent to your email', 'success');
            showLoginForm();
        } else {
            emailError.textContent = data.error || 'Failed to send reset link';
            emailError.classList.add('active');
        }
    } catch (error) {
        console.error('Forgot password error:', error);
        emailError.textContent = 'Failed to send reset link. Please try again.';
        emailError.classList.add('active');
    } finally {
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
    }
}

function hideVerificationModal() {
    const modal = document.getElementById("verificationModal");
    if (modal) {
        modal.classList.remove("active");
        modal.style.display = "none";
    }
    document.body.style.overflow = "auto";
}

function hideLoginModal() {
    const modal = document.getElementById('loginModal');
    if (modal) {
        modal.classList.remove('active');
    }
    document.body.style.overflow = 'auto';
    showLoginForm();
    document.querySelectorAll('#loginModal input').forEach(input => {
        input.value = '';
    });
    clearErrors();
}

function generateSessionId() {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

async function handleEmailAuth() {
    const emailInput = document.getElementById('loginEmail');
    const errorElement = document.getElementById('emailError');
    const email = emailInput.value.trim();
    if (errorElement) {
        errorElement.textContent = '';
        errorElement.classList.remove('active');
    }
    if (!email || !email.includes('@')) {
        if (errorElement) {
            errorElement.textContent = 'Please enter a valid email address';
            errorElement.classList.add('active');
        }
        return;
    }
    const submitButton = document.querySelector('.btn-primary');
    const originalText = submitButton.innerHTML;
    submitButton.disabled = true;
    submitButton.innerHTML = '<div class="loading"></div> Sending...';
    try {
        const response = await fetch('/api/auth/email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await response.json();
        if (data.requiresVerification || data.showVerificationPopup) {
            hideLoginModal();
            showVerificationModal(email);
            showNotification('Please check your email for the verification code.', 'warning');
            return;
        }
        if (data.success) {
            localStorage.setItem('fastfoodinsight_token', data.token);
            currentState.user = data.user;
            updateAuthUI(true);
            hideLoginModal();
            showNotification(`Welcome ${data.user.name || 'User'}!`, 'success');
            await createNewChatSession();
            await loadChatSessions();
            checkUsage();
        } else {
            if (errorElement) {
                errorElement.textContent = data.error || 'Authentication failed';
                errorElement.classList.add('active');
            }
        }
    } catch (error) {
        console.error('Email auth error:', error);
        if (errorElement) {
            errorElement.textContent = 'Authentication failed. Please try again.';
            errorElement.classList.add('active');
        }
    } finally {
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
    }
}

function toggleAuthMode() {
    currentState.isLoginMode = false;
    clearErrors();
}

async function createNewChat() {
    const newSessionId = generateSessionId();
    const sessionName = prompt('Enter chat name (optional):', 'New Chat');
    currentState.currentChatSession = newSessionId;
    currentState.currentSessionName = sessionName || 'New Chat';
    document.getElementById('messages').innerHTML = '';
    showWelcomeMessage();
    if (currentState.user) {
        try {
            await fetch('/api/chat/session', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('fastfoodinsight_token')}`
                },
                body: JSON.stringify({
                    session_id: newSessionId,
                    session_name: sessionName || 'New Chat'
                })
            });
        } catch (error) {
            console.error('Error creating session:', error);
        }
    }
    showNotification('New chat created!', 'success');
}

function safeSetElementHTML(element, html) {
    if (!html.includes('<')) {
        element.textContent = html;
        return;
    }
    if (typeof DOMPurify !== 'undefined') {
        element.innerHTML = DOMPurify.sanitize(html);
    } else {
        const cleanHTML = html
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+="[^"]*"/gi, '')
            .replace(/on\w+='[^']*'/gi, '')
            .replace(/on\w+=\w+/gi, '');
        element.innerHTML = cleanHTML;
    }
}

async function createNewChatSession() {
    if (!currentState.user) {
        document.getElementById('messages').innerHTML = '';
        showWelcomeMessage();
        currentState.currentChatSession = 'anonymous_' + Date.now();
        currentState.currentSessionName = 'Guest Chat';
        return;
    }
    const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    const sessionName = prompt('Enter chat name (optional):', 'New Chat');
    currentState.currentChatSession = sessionId;
    currentState.currentSessionName = sessionName || 'New Chat';
    document.getElementById('messages').innerHTML = '';
    showWelcomeMessage();
    try {
        await fetch('/api/chat/session', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('fastfoodinsight_token')}`
            },
            body: JSON.stringify({
                session_id: sessionId,
                session_name: currentState.currentSessionName
            })
        });
        await loadChatSessions();
        showNotification('New chat created!', 'success');
    } catch (error) {
        console.error('Error creating session:', error);
        showNotification('Note: Chat created locally', 'info');
    }
}

function renderChatHistory() {
    const historyList = document.getElementById('historyList');
    const noHistory = document.getElementById('noHistory');
    console.log('Rendering history/sessions:', {
        sessionsCount: currentState.chatSessions?.length || 0,
        historyCount: currentState.chatHistory?.length || 0,
        user: currentState.user?.name || 'anonymous'
    });
    historyList.innerHTML = '';
    if (currentState.user) {
        if (!currentState.chatSessions || currentState.chatSessions.length === 0) {
            if (noHistory) noHistory.style.display = 'block';
            return;
        }
        if (noHistory) noHistory.style.display = 'none';
        const sortedSessions = [...currentState.chatSessions].sort((a, b) =>
            new Date(b.updated_at || b.created_at) - new Date(a.updated_at || a.created_at)
        );
        sortedSessions.forEach(session => {
            const sessionItem = document.createElement('div');
            sessionItem.className = `history-item ${session.session_id === currentState.currentChatSession ? 'active' : ''}`;
            sessionItem.onclick = () => loadChatSession(session.session_id);
            const date = new Date(session.updated_at || session.created_at);
            const timeAgo = getTimeAgo(date);
            sessionItem.innerHTML = `
                <div class="history-item-header">
                    <span class="history-restaurant">${session.session_name || 'Chat'}</span>
                    <span class="history-date">${timeAgo}</span>
                </div>
                <div class="history-preview">
                    ${session.message_count || 0} messages
                </div>
            `;
            historyList.appendChild(sessionItem);
        });
        console.log(`Rendered ${sortedSessions.length} sessions`);
    } else {
        if (!currentState.chatHistory || currentState.chatHistory.length === 0) {
            if (noHistory) noHistory.style.display = 'block';
            return;
        }
        if (noHistory) noHistory.style.display = 'none';
        const sortedHistory = [...currentState.chatHistory].sort((a, b) =>
            (b.timestamp * 1000 || 0) - (a.timestamp * 1000 || 0)
        );
        sortedHistory.forEach(item => {
            const historyItem = document.createElement('div');
            historyItem.className = 'history-item';
            historyItem.onclick = () => loadHistoryItem(item);
            const date = new Date(item.timestamp * 1000 || Date.now());
            const timeAgo = getTimeAgo(date);
            const restaurant = item.restaurant || item.entities?.branch || 'Unknown';
            const previewText = item.user_message || 'No message preview';
            historyItem.innerHTML = `
                <div class="history-item-header">
                    <span class="history-restaurant">${restaurant}</span>
                    <span class="history-date">${timeAgo}</span>
                </div>
                <div class="history-preview">${truncateText(previewText, 50)}</div>
            `;
            historyList.appendChild(historyItem);
        });
        console.log(`Rendered ${sortedHistory.length} history items for anonymous user`);
    }
}

function showVerificationModal(email, code) {
    const modal = document.getElementById('verificationModal');
    const emailInput = document.getElementById('verifyEmail');
    const codeInput = document.getElementById('verifyCode');
    if (emailInput) emailInput.value = email || '';
    if (codeInput) codeInput.value = '';
    if (modal) {
        modal.classList.add('active');
        modal.style.display = 'flex';
    }
    document.body.style.overflow = 'hidden';
    if (code) {
        setTimeout(() => {
            if (codeInput) {
                codeInput.value = String(code);
                codeInput.focus();
            }
        }, 100);
    } else {
        setTimeout(() => codeInput?.focus(), 100);
    }
}

async function loadChatSessions() {
    try {
        if (!currentState.user) {
            currentState.chatSessions = [];
            renderChatHistory();
            return;
        }
        console.log('Loading chat sessions for user:', currentState.user.id);
        const response = await fetch('/api/chat/sessions', {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('fastfoodinsight_token')}`
            }
        });
        const data = await response.json();
        console.log('Chat sessions response:', data);
        if (data.success && data.sessions) {
            currentState.chatSessions = data.sessions;
            console.log(`✅ Loaded ${currentState.chatSessions.length} chat sessions`);
        } else {
            currentState.chatSessions = [];
            console.log('No sessions found or API returned no data');
        }
        renderChatHistory();
    } catch (error) {
        console.error('Failed to load chat sessions:', error);
        currentState.chatSessions = [];
        renderChatHistory();
    }
}

async function switchChatSession(sessionId) {
    currentState.currentChatSession = sessionId;
    try {
        const response = await fetch(`/api/chat/history?session_id=${sessionId}`, {
            headers: currentState.user ? {
                'Authorization': `Bearer ${localStorage.getItem('fastfoodinsight_token')}`
            } : {}
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('messages').innerHTML = '';
            data.history.forEach(item => {
                showMessage(item.user_message, 'user');
                showMessage(item.ai_response, 'ai', true);
            });
        }
    } catch (error) {
        console.error('Error switching session:', error);
    }
}

async function initializeAnonymousId() {
    let anonymousId = localStorage.getItem('fastfoodinsight_anonymous_id');
    if (!anonymousId) {
        anonymousId = 'anon_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('fastfoodinsight_anonymous_id', anonymousId);
    }
    currentState.anonymousId = anonymousId;
    console.log('Anonymous ID:', anonymousId);
}

function hideVerificationModal() {
    const modal = document.getElementById("verificationModal");
    if (modal) {
        modal.classList.remove("active");
        modal.style.display = "none";
    }
    document.body.style.overflow = "auto";
}

function hideLoginModal() {
    const modal = document.getElementById('loginModal');
    if (modal) {
        modal.classList.remove('active');
    }
    document.body.style.overflow = 'auto';
    const emailInput = document.getElementById('loginEmail');
    if (emailInput) {
        emailInput.value = '';
    }
    const errorElement = document.getElementById('emailError');
    if (errorElement) {
        errorElement.textContent = '';
        errorElement.classList.remove('active');
    }
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const isMobile = window.innerWidth <= 1200;
    if (isMobile) {
        sidebar.classList.toggle('mobile-visible');
        document.body.style.overflow = sidebar.classList.contains('mobile-visible') ? 'hidden' : 'auto';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.query-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (window.innerWidth <= 1200) {
                toggleSidebar();
            }
        });
    });
    document.querySelectorAll('.goal-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (window.innerWidth <= 1200) {
                toggleSidebar();
            }
        });
    });
});

async function initializeGoogleOAuth() {
    try {
        console.log('🔧 Initializing Google OAuth...');
        const configResponse = await fetch('/api/auth/google/config');
        const config = await configResponse.json();
        if (!config.clientId) {
            throw new Error('No Google Client ID found');
        }
        console.log('Using Google Client ID:', config.clientId.substring(0, 20) + '...');
        await waitForGoogleLibrary();
        google.accounts.id.initialize({
            client_id: config.clientId,
            callback: handleGoogleAuthResponse,
            auto_select: false,
            cancel_on_tap_outside: false,
            ux_mode: 'popup'
        });
        googleOAuthInitialized = true;
        console.log('✅ Google OAuth initialized successfully');
        renderGoogleButton();
    } catch (error) {
        console.error('❌ Google OAuth initialization failed:', error.message);
        showNotification('Google Sign-In will be available shortly. Please use email/password for now.', 'warning');
    }
}

function renderGoogleButton() {
    const googleButton = document.getElementById('googleSignInButton');
    if (googleButton && typeof google !== 'undefined' && google.accounts && google.accounts.id) {
        google.accounts.id.renderButton(googleButton, {
            type: 'standard',
            theme: 'outline',
            size: 'large',
            text: 'continue_with',
            shape: 'rectangular',
            width: googleButton.offsetWidth || 300
        });
        console.log('✅ Google button rendered');
    }
}

function waitForGoogleLibrary() {
    return new Promise((resolve, reject) => {
        if (typeof google !== 'undefined') {
            resolve();
            return;
        }
        let attempts = 0;
        const maxAttempts = 50;
        const check = () => {
            attempts++;
            if (typeof google !== 'undefined') {
                resolve();
            } else if (attempts >= maxAttempts) {
                reject(new Error('Google library timeout'));
            } else {
                setTimeout(check, 100);
            }
        };
        check();
    });
}

async function initializeGoogleWithClientId(clientId) {
    await waitForGoogleLibrary();
    google.accounts.id.initialize({
        client_id: clientId,
        callback: handleGoogleAuthResponse,
        auto_select: false,
        cancel_on_tap_outside: false,
        ux_mode: 'popup'
    });
    googleOAuthInitialized = true;
    console.log('✅ Google OAuth initialized with client ID:', clientId.substring(0, 20) + '...');
    const googleButton = document.getElementById('googleSignInButton');
    if (googleButton && !googleButton.hasChildNodes()) {
        google.accounts.id.renderButton(googleButton, {
            theme: 'outline',
            size: 'large',
            width: googleButton.offsetWidth || 300
        });
    }
}

async function handleGoogleAuthResponse(response) {
    try {
        console.log('🎯 Google auth response received');
        if (!response.credential) {
            throw new Error('No credential received');
        }
        showNotification('Verifying with Google...', 'info');
        const res = await fetch('/api/auth/google', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: response.credential })
        });
        const data = await res.json();
        console.log('Google auth response from server:', data);
        if (data.success && data.token) {
            localStorage.setItem('fastfoodinsight_token', data.token);
            currentState.user = data.user;
            updateAuthUI(true);
            hideLoginModal();
            showNotification(`🎉 Welcome ${data.user.name}!`, 'success');
            await createNewChatSession();
            await loadChatSessions();
            checkUsage();
        } else {
            showNotification(data.error || 'Google authentication failed', 'error');
        }
    } catch (error) {
        console.error('❌ Google auth error:', error);
        showNotification('Google authentication failed. Please try again.', 'error');
    }
}

async function handleSendMessage() {
    console.log('🚀 Send message triggered');
    const userInput = document.getElementById('userInput');
    const sendButton = document.getElementById('sendButton');
    const message = userInput.value.trim();
    if (!message || currentState.isProcessing) {
        return;
    }
    if (!currentState.user && currentState.usage.blocked) {
        showNotification('Free limit reached. Please sign up for unlimited access.', 'warning');
        showLoginModal();
        return;
    }
    currentState.isProcessing = true;
    userInput.disabled = true;
    sendButton.disabled = true;
    showMessage(message, 'user');
    userInput.value = '';
    autoResize(userInput);
    showTyping();
    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                message: message,
                goal: currentState.goal,
                anonymous_id: currentState.anonymousId,
                chat_session_id: currentState.currentChatSession
            })
        });
        if (!response.ok) {
            if (response.status === 403) {
                const data = await response.json();
                if (data.requiresLogin) {
                    showNotification('Free limit reached. Please sign up to continue.', 'warning');
                    showLoginModal();
                    hideTyping();
                    currentState.isProcessing = false;
                    userInput.disabled = false;
                    sendButton.disabled = false;
                    return;
                }
            }
            throw new Error('Network response was not ok');
        }
        const data = await response.json();
        hideTyping();
        if (data.text) {
            showMessage(data.text, 'ai', true);
            if (data.usage) {
                currentState.usage = {
                    ...currentState.usage,
                    totalMessages: data.usage.totalMessages,
                    remainingMessages: data.usage.remainingMessages,
                    blocked: data.usage.blocked || data.usage.isBlocked
                };
                updateUsageUI();
                if (data.usageWarning && !currentState.user) {
                    document.getElementById('usageWarning').classList.add('active');
                }
            }
            if (currentState.user) {
                await loadChatSessions();
            } else {
                await loadChatHistory();
            }
        }
    } catch (error) {
        console.error('Chat error:', error);
        hideTyping();
        showMessage(`I apologize, but I'm having trouble processing your request. Please try again.`, 'ai');
    } finally {
        currentState.isProcessing = false;
        userInput.disabled = false;
        sendButton.disabled = false;
        userInput.focus();
    }
}

async function testAuthentication() {
    console.log('=== AUTHENTICATION TEST ===');
    console.log('Local storage token:', localStorage.getItem('fastfoodinsight_token'));
    console.log('Current state user:', currentState.user);
    if (currentState.user) {
        const token = localStorage.getItem('fastfoodinsight_token');
        if (token) {
            try {
                const response = await fetch('/api/auth/verify', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const data = await response.json();
                console.log('Token verification result:', data);
                return data.success;
            } catch (error) {
                console.error('Token verification failed:', error);
                return false;
            }
        }
    }
    console.log('❌ No user or token found');
    return false;
}

async function completeGoogleLogin(token, user) {
    localStorage.setItem('fastfoodinsight_token', token);
    currentState.user = user;
    updateAuthUI(true);
    hideLoginModal();
    hideNameModal();
    showNotification(`Welcome ${user.name}! 🎉`, 'success');
    document.getElementById('messages').innerHTML = '';
    await createNewChatSession();
    await loadChatSessions();
    showWelcomeMessage();
    checkUsage();
}

function showNameModal() {
    document.getElementById('nameModal').classList.add('active');
    document.body.style.overflow = 'hidden';
    document.getElementById('userNameInput').focus();
}

function hideNameModal() {
    document.getElementById('nameModal').classList.remove('active');
    document.body.style.overflow = 'auto';
    document.getElementById('nameModalError').textContent = '';
    document.getElementById('userNameInput').value = '';
}

async function saveUserName() {
    const nameInput = document.getElementById('userNameInput');
    const name = nameInput.value.trim();
    const errorElement = document.getElementById('nameModalError');
    if (!name) {
        errorElement.textContent = 'Please enter your name';
        errorElement.classList.add('active');
        return;
    }
    if (name.length < 2) {
        errorElement.textContent = 'Name must be at least 2 characters';
        errorElement.classList.add('active');
        return;
    }
    try {
        const response = await fetch('/api/auth/update-name', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentState.tempGoogleUser.token}`
            },
            body: JSON.stringify({ name })
        });
        const data = await response.json();
        if (data.success) {
            currentState.tempGoogleUser.name = name;
            completeGoogleLogin(currentState.tempGoogleUser.token, currentState.tempGoogleUser);
        } else {
            showNotification('Failed to save name. Please try again.', 'error');
        }
    } catch (error) {
        console.error('Error saving name:', error);
        currentState.tempGoogleUser.name = name;
        completeGoogleLogin(currentState.tempGoogleUser.token, currentState.tempGoogleUser);
    }
}

function triggerGoogleSignIn() {
    console.log('🔵 Google sign-in triggered');
    if (!googleOAuthInitialized) {
        console.log('Google OAuth not initialized yet');
        showNotification('Google Sign-In is still loading. Please try again in a moment.', 'warning');
        return;
    }
    try {
        google.accounts.id.prompt((notification) => {
            if (notification.isNotDisplayed()) {
                console.log('Google prompt not displayed:', notification.getNotDisplayedReason());
                showNotification('Please allow popups for Google Sign-In.', 'warning');
            }
            if (notification.isSkippedMoment()) {
                console.log('Google prompt skipped:', notification.getSkippedReason());
            }
        });
    } catch (error) {
        console.error('Google sign-in trigger error:', error);
        showNotification('Google Sign-In failed. Please use email/password.', 'error');
    }
}

function triggerGoogleLogin() {
    if (!googleOAuthInitialized) {
        showNotification('Google Sign-In is still loading. Please wait...', 'warning');
        if (!googleOAuthInitialized) {
            initializeGoogleOAuth();
        }
        return;
    }
    try {
        google.accounts.id.prompt();
    } catch (error) {
        console.error('Google prompt error:', error);
        showNotification('Please click the Google Sign-In button below', 'info');
    }
}

async function directGoogleLogin() {
    showNotification('Redirecting to Google...', 'info');
    if (typeof google !== 'undefined' && google.accounts && google.accounts.id) {
        try {
            google.accounts.id.prompt();
        } catch (error) {
            console.error('Google prompt error:', error);
            showNotification('Please sign in with email/password', 'error');
        }
    } else {
        showNotification('Google Sign-In not available. Please use email/password.', 'error');
    }
}

async function verifyAndSetToken(token) {
    if (!token) return false;
    try {
        const response = await fetch('/api/auth/verify', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        if (!response.ok) return false;
        const data = await response.json();
        if (data.success && data.user) {
            localStorage.setItem('fastfoodinsight_token', token);
            currentState.user = data.user;
            updateAuthUI(true);
            console.log('✅ Token verified and user set:', data.user.email);
            return true;
        }
    } catch (error) {
        console.error('❌ Token verification failed:', error);
    }
    return false;
}

async function checkAuthStatus() {
    const token = localStorage.getItem('fastfoodinsight_token');
    if (!token) {
        updateAuthUI(false);
        return;
    }
    const verified = await verifyAndSetToken(token);
    if (!verified) {
        localStorage.removeItem('fastfoodinsight_token');
        currentState.user = null;
        updateAuthUI(false);
    }
}

function getAuthHeaders() {
    const headers = {
        'Content-Type': 'application/json'
    };
    const token = localStorage.getItem('fastfoodinsight_token');
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
}

function debugGoogleOAuth() {
    console.log('=== GOOGLE OAUTH DEBUG ===');
    console.log('Google library loaded:', typeof google !== 'undefined');
    console.log('Google accounts ID available:', typeof google?.accounts?.id !== 'undefined');
    console.log('OAuth initialized:', googleOAuthInitialized);
    console.log('Client ID available:', !!'367624804140-nn5nphkhshsljla92cv66sccaksifopt.apps.googleusercontent.com');
    fetch('/api/auth/google/config')
        .then(res => res.json())
        .then(config => {
            console.log('Server config:', config);
        })
        .catch(err => {
            console.log('Server config error:', err.message);
        });
}
window.debugGoogleOAuth = debugGoogleOAuth;

function updateAuthUI(isLoggedIn) {
    const authButton = document.getElementById('authButton');
    const logoutButton = document.getElementById('logoutButton');
    const userInfo = document.getElementById('userInfo');
    const chatHistorySection = document.getElementById('chatHistory');
    const userName = document.getElementById('userName');
    const userAvatar = document.getElementById('userAvatar');
    const newChatSection = document.getElementById('newChatSection');
    if (isLoggedIn && currentState.user) {
        authButton.innerHTML = `<i class="fas fa-user"></i> ${currentState.user.name || 'My Account'}`;
        authButton.style.display = 'none';
        logoutButton.style.display = 'flex';
        userInfo.classList.add('active');
        chatHistorySection.classList.add('active');
        if (newChatSection) newChatSection.style.display = 'block';
        userName.textContent = currentState.user.name || 'User';
        const initials = (currentState.user.name || 'U').charAt(0).toUpperCase();
        userAvatar.innerHTML = initials;
        userAvatar.title = `Logged in as ${currentState.user.name || 'User'}`;
        currentState.currentChatSession = generateSessionId();
        currentState.currentSessionName = `${currentState.user.name}'s Chat`;
        setTimeout(() => {
            loadChatSessions().catch(err => {
                console.log('Note: Could not load sessions yet:', err.message);
            });
        }, 1000);
    } else {
        authButton.innerHTML = `<i class="fas fa-sign-in-alt"></i> Sign In`;
        authButton.style.display = 'flex';
        logoutButton.style.display = 'none';
        userInfo.classList.remove('active');
        chatHistorySection.classList.remove('active');
        if (newChatSection) newChatSection.style.display = 'none';
        userName.textContent = 'Guest User';
        userAvatar.innerHTML = '<i class="fas fa-user"></i>';
        userAvatar.title = 'Guest User';
        currentState.currentChatSession = 'anonymous_' + currentState.anonymousId;
        currentState.currentSessionName = 'Guest Chat';
    }
}

function confirmLogout() {
    if (confirm('Are you sure you want to logout?')) {
        logout();
    }
}

function logout() {
    localStorage.removeItem('fastfoodinsight_token');
    localStorage.removeItem('fastfoodinsight_trial_shown');
    document.cookie = 'fastfoodinsight_token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    currentState.user = null;
    currentState.currentChatSession = null;
    currentState.chatSessions = [];
    updateAuthUI(false);
    showNotification('Logged out successfully', 'info');
    document.getElementById('messages').innerHTML = '';
    showWelcomeMessage();
    currentState.currentChatSession = 'anonymous_' + currentState.anonymousId;
    currentState.currentSessionName = 'Guest Chat';
    checkUsage();
    window.fetch = window.fetch;
}

function showTrialNotificationIfNeeded() {
    const token = localStorage.getItem('fastfoodinsight_token');
    const trialShown = localStorage.getItem('fastfoodinsight_trial_shown');
    if (token && !trialShown && currentState.user) {
        setTimeout(() => {
            showTrialNotification();
        }, 1000);
        localStorage.setItem('fastfoodinsight_trial_shown', 'true');
    }
}

function showTrialNotification() {
    if (currentState.user) {
        showNotification(
            `🎉 Welcome to FastFoodInsight AI! You've been granted 1-month free trial with unlimited messages.`,
            'success'
        );
    }
}

async function checkUsage() {
    try {
        console.log('📊 Checking usage...');
        const userInput = document.getElementById('userInput');
        const sendButton = document.getElementById('sendButton');
        if (currentState.user) {
            currentState.usage = {
                totalMessages: 0,
                remainingMessages: 999999,
                maxMessages: 999999,
                blocked: false,
                isInTrial: true
            };
            updateUsageUI();
            userInput.disabled = false;
            sendButton.disabled = false;
            return;
        }
        const anonId = currentState.anonymousId || localStorage.getItem('fastfoodinsight_anonymous_id') || '';
        const url = `/api/usage?anonymous_id=${encodeURIComponent(anonId)}`;
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        });
        if (!response.ok) {
            console.log('⚠️ Usage check failed, allowing messages anyway');
            userInput.disabled = false;
            sendButton.disabled = false;
            return;
        }
        const data = await response.json();
        if (data.success && data.usage) {
            currentState.usage = data.usage;
            console.log('📈 Usage data:', currentState.usage);
            updateUsageUI();
            if (currentState.usage.blocked && !currentState.user) {
                userInput.disabled = true;
                sendButton.disabled = true;
                userInput.placeholder = 'Sign up for unlimited access';
                showNotification('Free limit reached. Sign up for unlimited access.', 'warning');
            } else {
                userInput.disabled = false;
                sendButton.disabled = false;
            }
        }
    } catch (error) {
        console.error('Usage check failed:', error);
        document.getElementById('userInput').disabled = false;
        document.getElementById('sendButton').disabled = false;
    }
}

function updateUsageUI() {
    const messageCountElement = document.getElementById('messageCount');
    const usageStatCard = document.getElementById('usageStatCard');
    if (!messageCountElement || !usageStatCard) {
        console.warn('Usage UI elements not found (messageCount/usageStatCard)');
        return;
    }
    if (currentState.user) {
        messageCountElement.textContent = 'Unlimited';
        usageStatCard.querySelector('.stat-icon').innerHTML = '<i class="fas fa-crown"></i>';
        usageStatCard.querySelector('.stat-label').textContent = 'Trial Active';
    } else {
        messageCountElement.textContent = `${currentState.usage.totalMessages || 0}/${currentState.usage.maxMessages || 10}`;
        usageStatCard.querySelector('.stat-icon').innerHTML = '<i class="fas fa-comment"></i>';
        usageStatCard.querySelector('.stat-label').textContent = 'Messages';
    }
}

async function loadChatHistory() {
    try {
        let url = '/api/chat/history?';
        if (currentState.user) {
            url += `user_id=${currentState.user.id}`;
            console.log('Loading history for user:', currentState.user.id);
        } else {
            url += `anonymous_id=${currentState.anonymousId}`;
            console.log('Loading history for anonymous:', currentState.anonymousId);
        }
        const headers = { 'Content-Type': 'application/json' };
        const token = localStorage.getItem('fastfoodinsight_token');
        if (currentState.user && token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        const response = await fetch(url, {
            method: 'GET',
            headers: headers
        });
        const data = await response.json();
        console.log('History API response:', data);
        if (data.success && data.history) {
            currentState.chatHistory = data.history;
            console.log(`✅ Loaded ${currentState.chatHistory.length} history items`);
            renderChatHistory();
        } else {
            console.error('Failed to load chat history:', data.error);
            currentState.chatHistory = [];
            renderChatHistory();
        }
    } catch (error) {
        console.error('Failed to load chat history:', error);
        currentState.chatHistory = [];
        renderChatHistory();
    }
}

async function loadChatSession(sessionId) {
    try {
        if (!currentState.user) {
            showNotification('Login required to load sessions', 'warning');
            return;
        }
        const response = await fetch(`/api/chat/session/${encodeURIComponent(sessionId)}`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('fastfoodinsight_token')}`
            }
        });
        const data = await response.json();
        if (!data.success) {
            showNotification('Failed to load session messages', 'error');
            return;
        }
        const messagesDiv = document.getElementById('messages');
        messagesDiv.innerHTML = '';
        data.messages.forEach(msg => {
            const userMessageDiv = document.createElement('div');
            userMessageDiv.className = 'message user-message';
            userMessageDiv.innerHTML = `<div class="user-bubble">${escapeHtml(msg.user_message || '')}</div>`;
            messagesDiv.appendChild(userMessageDiv);
            const aiMessageDiv = document.createElement('div');
            aiMessageDiv.className = 'message ai-message';
            const bubbleDiv = document.createElement('div');
            bubbleDiv.className = 'ai-bubble';
            const contentDiv = document.createElement('div');
            contentDiv.className = 'ai-bubble-content';
            safeSetElementHTML(contentDiv, msg.ai_response || '');
            bubbleDiv.appendChild(contentDiv);
            aiMessageDiv.appendChild(bubbleDiv);
            messagesDiv.appendChild(aiMessageDiv);
        });
        wrapTablesInContent();
        setTimeout(() => messagesDiv.scrollTop = messagesDiv.scrollHeight, 50);
    } catch (err) {
        console.error('Error loading session:', err);
        showNotification('Failed to load chat session', 'error');
    }
}

function loadHistoryItem(item) {
    const messagesDiv = document.getElementById('messages');
    messagesDiv.innerHTML = '';
    const userMessageDiv = document.createElement('div');
    userMessageDiv.className = 'message user-message';
    userMessageDiv.innerHTML = `<div class="user-bubble">${escapeHtml(item.user_message || '')}</div>`;
    messagesDiv.appendChild(userMessageDiv);
    const aiMessageDiv = document.createElement('div');
    aiMessageDiv.className = 'message ai-message';
    const bubbleDiv = document.createElement('div');
    bubbleDiv.className = 'ai-bubble';
    const contentDiv = document.createElement('div');
    contentDiv.className = 'ai-bubble-content';
    safeSetElementHTML(contentDiv, item.ai_response || '');
    bubbleDiv.appendChild(contentDiv);
    aiMessageDiv.appendChild(bubbleDiv);
    messagesDiv.appendChild(aiMessageDiv);
    wrapTablesInContent();
    setTimeout(() => {
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }, 100);
    if (window.innerWidth <= 1200) {
        toggleSidebar();
    }
}

async function refreshHistory() {
    await loadChatHistory();
    showNotification('Chat history refreshed', 'success');
}

async function clearHistory() {
    if (!confirm('Are you sure you want to clear your chat history? This action cannot be undone.')) {
        return;
    }
    currentState.chatHistory = [];
    renderChatHistory();
    showNotification('Chat history cleared', 'info');
}

function showMessage(text, type, isHtml = false) {
    const messagesDiv = document.getElementById('messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}-message`;
    if (type === 'user') {
        const cleanText = escapeHtml(text);
        const bubbleDiv = document.createElement('div');
        bubbleDiv.className = 'user-bubble';
        bubbleDiv.textContent = cleanText;
        messageDiv.appendChild(bubbleDiv);
    } else {
        const bubbleDiv = document.createElement('div');
        bubbleDiv.className = 'ai-bubble';
        const contentDiv = document.createElement('div');
        contentDiv.className = 'ai-bubble-content';
        if (isHtml) {
            safeSetElementHTML(contentDiv, text);
        } else {
            const formattedText = formatSimpleResponse(text);
            safeSetElementHTML(contentDiv, formattedText);
        }
        bubbleDiv.appendChild(contentDiv);
        messageDiv.appendChild(bubbleDiv);
    }
    messagesDiv.appendChild(messageDiv);
    if (type === 'ai') {
        setTimeout(wrapTablesInContent, 50);
    }
    const scrollThreshold = 100;
    const isNearBottom = messagesDiv.scrollHeight - messagesDiv.scrollTop - messagesDiv.clientHeight < scrollThreshold;
    if (isNearBottom) {
        setTimeout(() => {
            messagesDiv.scrollTo({
                top: messagesDiv.scrollHeight,
                behavior: 'smooth'
            });
        }, 100);
    }
    messageDiv.style.animation = 'fadeIn 0.3s ease';
}

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

function quickQuery(text) {
    document.getElementById('userInput').value = text;
    handleSendMessage();
}

function setGoal(goal) {
    currentState.goal = goal;
    updateGoalButtons(goal);
    fetch('/api/set-goal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ goal })
    }).catch(error => {
        console.log('Goal update sent (offline mode)');
    });
    const goalNames = {
        'basic': 'Basic Nutrition',
        'weight_loss': 'Weight Loss',
        'weight_gain': 'Muscle Gain',
        'diabetes': 'Diabetes Management',
        'bp': 'Blood Pressure Control',
        'heart': 'Heart Health'
    };
    showNotification(`✅ Goal updated to ${goalNames[goal]}`, 'success');
}

function autoResize(textarea) {
    if (window.innerWidth <= 1200) {
        textarea.style.height = '40px';
        return;
    }
    textarea.style.height = 'auto';
    const newHeight = Math.min(textarea.scrollHeight, 200);
    textarea.style.height = newHeight + 'px';
    const inputContainer = document.querySelector('.input-container');
    if (newHeight > 56 && window.innerWidth > 1200) {
        inputContainer.style.paddingBottom = '20px';
    } else {
        inputContainer.style.paddingBottom = window.innerWidth <= 1200 ? '12px' : '24px';
    }
}

function updateGoalButtons(goal) {
    document.querySelectorAll('.goal-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    const goalBtn = document.querySelector(`.goal-btn[onclick*="${goal}"]`);
    if (goalBtn) {
        goalBtn.classList.add('active');
    }
}

function showTyping() {
    const messagesDiv = document.getElementById('messages');
    const typingDiv = document.createElement('div');
    typingDiv.className = 'typing-indicator';
    typingDiv.id = 'typingIndicator';
    for (let i = 0; i < 3; i++) {
        const dot = document.createElement('div');
        dot.className = 'typing-dot';
        typingDiv.appendChild(dot);
    }
    messagesDiv.appendChild(typingDiv);
    const scrollThreshold = 150;
    const isNearBottom = messagesDiv.scrollHeight - messagesDiv.scrollTop - messagesDiv.clientHeight < scrollThreshold;
    if (isNearBottom) {
        setTimeout(() => {
            messagesDiv.scrollTo({
                top: messagesDiv.scrollHeight,
                behavior: 'smooth'
            });
        }, 50);
    }
}

function hideTyping() {
    const typingDiv = document.getElementById('typingIndicator');
    if (typingDiv) {
        typingDiv.remove();
    }
}

function formatSimpleResponse(text) {
    let formatted = escapeHtml(text);
    formatted = formatted.replace(/<table([^>]*)>/g, '<div class="table-container"><table$1>');
    formatted = formatted.replace(/<\/table>/g, '</table></div>');
    formatted = formatted.replace(/^# (.*?)$/gm, '<h1>$1</h1>');
    formatted = formatted.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
    formatted = formatted.replace(/^### (.*?)$/gm, '<h3>$1</h3>');
    formatted = formatted.replace(/^#### (.*?)$/gm, '<h4>$1</h4>');
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    formatted = formatted.replace(/\*(.*?)\*/g, '<em>$1</em>');
    formatted = formatted.replace(/`(.*?)`/g, '<code>$1</code>');
    formatted = formatted.replace(/^- (.*?)$/gm, '<li>$1</li>');
    formatted = formatted.replace(/^\* (.*?)$/gm, '<li>$1</li>');
    formatted = formatted.replace(/(<li>.*?<\/li>\n?)+/g, '<ul>$&</ul>');
    formatted = formatted.split('\n\n').map(para => {
        if (para.trim() && !para.includes('<table') && !para.includes('<h')) {
            return `<p>${para.trim()}</p>`;
        }
        return para;
    }).join('');
    return formatted;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function handleEnter(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        handleSendMessage();
    }
}

function resetInputContainer() {
    const inputContainer = document.querySelector('.input-container');
    inputContainer.style.paddingBottom = '24px';
}

function showLoginModal() {
    const modal = document.getElementById('loginModal');
    if (modal) {
        modal.classList.add('active');
        modal.style.display = 'flex';
    }
    document.body.style.overflow = 'hidden';
    setTimeout(() => {
        const emailInput = document.getElementById('loginEmail');
        if (emailInput) emailInput.focus();
    }, 100);
}

function hideVerificationModal() {
    const modal = document.getElementById("verificationModal");
    if (modal) {
        modal.classList.remove("active");
        modal.style.display = "none";
    }
    document.body.style.overflow = "auto";
}

function hideLoginModal() {
    const modal = document.getElementById('loginModal');
    if (modal) {
        modal.classList.remove('active');
        modal.style.display = 'none';
    }
    document.body.style.overflow = 'auto';
    showLoginForm();
    const emailInput = document.getElementById('loginEmail');
    const passwordInput = document.getElementById('loginPassword');
    if (emailInput) emailInput.value = '';
    if (passwordInput) passwordInput.value = '';
    clearErrors();
}

function clearErrors() {
    document.querySelectorAll('.form-error').forEach(el => {
        el.classList.remove('active');
        el.textContent = '';
    });
}

function showError(elementId, message) {
    const element = document.getElementById(elementId);
    element.textContent = message;
    element.classList.add('active');
}

function resetLoginForm() {
    try {
        const emailInput = document.getElementById('loginEmail');
        const passwordInput = document.getElementById('loginPassword');
        const nameInput = document.getElementById('loginName');
        if (emailInput) emailInput.value = '';
        if (passwordInput) passwordInput.value = '';
        if (nameInput) nameInput.value = '';
        currentState.isLoginMode = false;
    } catch (error) {
        console.log('Note: resetLoginForm skipped - elements not found');
    }
}

function wrapTablesInContent() {
    document.querySelectorAll('.ai-bubble-content table').forEach(table => {
        if (!table.parentElement.classList.contains('table-container')) {
            const container = document.createElement('div');
            container.className = 'table-container';
            table.parentNode.insertBefore(container, table);
            container.appendChild(table);
        }
    });
}

function initScrollToBottom() {
    const messagesDiv = document.getElementById('messages');
    const scrollButton = document.createElement('button');
    scrollButton.className = 'scroll-to-bottom';
    scrollButton.innerHTML = '<i class="fas fa-arrow-down"></i>';
    scrollButton.title = 'Scroll to bottom';
    scrollButton.onclick = () => {
        messagesDiv.scrollTo({
            top: messagesDiv.scrollHeight,
            behavior: 'smooth'
        });
    };
    document.querySelector('.main-content').appendChild(scrollButton);
    messagesDiv.addEventListener('scroll', () => {
        const scrollThreshold = 200;
        const isNearBottom = messagesDiv.scrollHeight - messagesDiv.scrollTop - messagesDiv.clientHeight < scrollThreshold;
        if (isNearBottom) {
            scrollButton.classList.remove('visible');
        } else {
            scrollButton.classList.add('visible');
        }
    });
}

function getTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    let interval = seconds / 31536000;
    if (interval > 1) return Math.floor(interval) + ' years ago';
    interval = seconds / 2592000;
    if (interval > 1) return Math.floor(interval) + ' months ago';
    interval = seconds / 86400;
    if (interval > 1) return Math.floor(interval) + ' days ago';
    interval = seconds / 3600;
    if (interval > 1) return Math.floor(interval) + ' hours ago';
    interval = seconds / 60;
    if (interval > 1) return Math.floor(interval) + ' minutes ago';
    return Math.floor(seconds) + ' seconds ago';
}

function truncateText(text, maxLength) {
    if (text.length <= maxLength) return text;
    return text.substr(0, maxLength) + '...';
}

async function checkStatus() {
    try {
        const response = await fetch('/api/health');
        const data = await response.json();
        document.getElementById('statusText').textContent = 'Online';
        document.querySelector('.status-dot').style.background = '#10B981';
    } catch (error) {
        document.getElementById('statusText').textContent = 'Offline';
        document.querySelector('.status-dot').style.background = '#6B7280';
    }
}

function setupEventListeners() {
    const loginModal = document.getElementById('loginModal');
    if (loginModal) {
        loginModal.addEventListener('click', function(e) {
            if (e.target === this) {
                hideLoginModal();
            }
        });
    }
    const nameModal = document.getElementById('nameModal');
    if (nameModal) {
        nameModal.addEventListener('click', function(e) {
            if (e.target === this) {
                hideNameModal();
            }
        });
    }
    const verificationModalEl = document.getElementById('verificationModal');
    if (verificationModalEl) {
        verificationModalEl.addEventListener('click', function(e) {
            if (e.target === this) {
                hideVerificationModal();
            }
        });
    }
    document.addEventListener('click', function(e) {
        if (window.innerWidth <= 1200) {
            const sidebar = document.getElementById('sidebar');
            const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
            if (sidebar && sidebar.classList.contains('mobile-visible') &&
                !sidebar.contains(e.target) &&
                mobileMenuBtn && !mobileMenuBtn.contains(e.target)) {
                toggleSidebar();
            }
        }
    });
    setInterval(checkStatus, 30000);
    checkStatus();
    const sendButton = document.getElementById('sendButton');
    if (sendButton) {
        sendButton.addEventListener('click', handleSendMessage);
    }
    const userInputEl = document.getElementById('userInput');
    if (userInputEl) {
        userInputEl.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSendMessage();
            }
        });
    }
}

function checkTrialNotification() {
    if (currentState.user && subscriptionManager.currentSubscription) {
        const sub = subscriptionManager.currentSubscription;
        if (sub.subscription_status === 'free_trial' && sub.days_remaining <= 3 && sub.days_remaining > 0) {
            showNotification(`Your free trial ends in ${sub.days_remaining} days. Visit Billing to subscribe.`, 'warning');
        } else if (sub.subscription_status === 'expired' || (sub.subscription_status === 'free_trial' && sub.days_remaining <= 0)) {
            showNotification('Your free trial has expired. Please subscribe to continue.', 'error');
        }
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    console.log('🚀 DOM Content Loaded');
    let anonymousId = localStorage.getItem('fastfoodinsight_anonymous_id');
    if (!anonymousId) {
        anonymousId = 'anon_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('fastfoodinsight_anonymous_id', anonymousId);
    }
    currentState.anonymousId = anonymousId;
    document.getElementById('userInput').focus();
    updateGoalButtons(currentState.goal);
    const messagesDiv = document.getElementById('messages');
    messagesDiv.innerHTML = '';
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message ai-message';
    const bubbleDiv = document.createElement('div');
    bubbleDiv.className = 'ai-bubble';
    const contentDiv = document.createElement('div');
    contentDiv.className = 'ai-bubble-content';
    contentDiv.innerHTML = `
        <h1>Welcome to FastFoodInsight AI 🍔</h1>
        <p>Get instant nutrition analysis for any fast food item across 9 global chains in 100+ countries.</p>
        <h2><i class="fas fa-lightbulb"></i> How to Use</h2>
        <ol>
            <li><strong>Select your health goal</strong> from the sidebar</li>
            <li><strong>Click any quick query</strong> or type your own</li>
            <li><strong>Get beautiful nutrition tables</strong> with FFI scores</li>
            <li><strong>Ask complex questions</strong> - diabetes, heart health, weight loss, etc.</li>
        </ol>
        <h2><i class="fas fa-star"></i> Try These Queries</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Query Type</th>
                        <th>Example</th>
                        <th>What you get</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Specific Item</strong></td>
                        <td><code>"Big Mac at McDonalds in USA"</code></td>
                        <td>Detailed nutrition table</td>
                    </tr>
                    <tr>
                        <td><strong>Health Goal</strong></td>
                        <td><code>"Diabetes-friendly at Starbucks in Australia"</code></td>
                        <td>Filtered low-sugar options</td>
                    </tr>
                    <tr>
                        <td><strong>Comparison</strong></td>
                        <td><code>"High protein food at Burger King in Canada"</code></td>
                        <td>Ranked protein-rich items</td>
                    </tr>
                </tbody>
            </table>
        </div>
        <h2><i class="fas fa-globe"></i> Available in 100+ Countries</h2>
        <p>Including: USA, UK, Canada, Australia, India, Pakistan, Germany, France, Japan, UAE, China, Mexico, and 90+ more!</p>
        <p><br><strong>Tip:</strong> Always use format: <code>"[Food Item] at [Restaurant] in [Country]"</code></p>
        <p><br><strong>Try clicking "Zinger Burger at KFC in UK" to see beautiful tables in action!</strong></p>
    `;
    bubbleDiv.appendChild(contentDiv);
    messageDiv.appendChild(bubbleDiv);
    messagesDiv.appendChild(messageDiv);

    await checkAuthStatus();
    if (currentState.user) {
        currentState.currentChatSession = 'session_' + Date.now();
        currentState.currentSessionName = 'Chat';
    }

    // Initialize subscription and check trial
    await subscriptionManager.init();
    checkTrialNotification();

    await loadChatHistory();
    await checkUsage();
    setTimeout(() => {
        initializeGoogleOAuth().catch(err => {
            console.log('Google OAuth initialization completed in background');
        });
    }, 1000);
    setupEventListeners();
    initScrollToBottom();
    showTrialNotificationIfNeeded();
});

// Handle payment success return
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.get('payment') === 'success') {
    subscriptionManager.loadUserSubscription().then(() => {
        checkTrialNotification();
        showNotification('Payment successful! Your subscription is now active.', 'success');
    });
    window.history.replaceState({}, document.title, window.location.pathname);
}

// Unified auth fixes (load this LAST, just before </body>) – this IIFE is already in the file, keep as is.
(function () {
    function showNotification(message, type = 'info') {
        const existing = document.querySelector('.notification');
        if (existing) existing.remove();
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        const icon = type === 'success' ? 'check-circle' :
                     type === 'warning' ? 'exclamation-triangle' :
                     type === 'error' ? 'times-circle' : 'info-circle';
        const color = type === 'success' ? '#10B981' :
                      type === 'warning' ? '#F59E0B' :
                      type === 'error' ? '#EF4444' : '#3B82F6';
        const container = document.createElement('div');
        container.style.display = 'flex';
        container.style.alignItems = 'center';
        container.style.gap = '12px';
        const iconEl = document.createElement('i');
        iconEl.className = `fas fa-${icon}`;
        iconEl.style.color = color;
        iconEl.style.fontSize = '18px';
        const textSpan = document.createElement('span');
        textSpan.textContent = message;
        textSpan.style.flex = '1';
        const closeBtn = document.createElement('button');
        closeBtn.onclick = function () { if (notification.parentElement) notification.remove(); };
        closeBtn.style.background = 'none';
        closeBtn.style.border = 'none';
        closeBtn.style.color = 'var(--text-light)';
        closeBtn.style.cursor = 'pointer';
        closeBtn.style.padding = '4px';
        const closeIcon = document.createElement('i');
        closeIcon.className = 'fas fa-times';
        closeBtn.appendChild(closeIcon);
        container.appendChild(iconEl);
        container.appendChild(textSpan);
        container.appendChild(closeBtn);
        notification.appendChild(container);
        document.body.appendChild(notification);
        setTimeout(() => notification.classList.add('show'), 10);
        setTimeout(() => {
            if (notification.parentElement) {
                notification.classList.remove('show');
                setTimeout(() => notification.remove(), 300);
            }
        }, 4000);
    }

    async function handleEmailPasswordLogin_override() {
        const emailInput = document.getElementById('loginEmail');
        const passwordInput = document.getElementById('loginPassword');
        const emailError = document.getElementById('emailError');
        const passwordError = document.getElementById('passwordError');
        const email = (emailInput?.value || '').trim();
        const password = (passwordInput?.value || '');
        if (emailError) { emailError.textContent = ''; emailError.classList.remove('active'); }
        if (passwordError) { passwordError.textContent = ''; passwordError.classList.remove('active'); }
        if (!email || !email.includes('@')) {
            if (emailError) {
                emailError.textContent = 'Please enter a valid email address';
                emailError.classList.add('active');
            }
            return;
        }
        if (!password || password.length < 6) {
            if (passwordError) {
                passwordError.textContent = 'Password must be at least 6 characters';
                passwordError.classList.add('active');
            }
            return;
        }
        const submitButton = document.querySelector('#emailPasswordForm .btn-primary');
        const originalText = submitButton?.innerHTML || 'Signing in...';
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.innerHTML = '<div class="loading"></div> Signing in...';
        }
        try {
            console.log('🔐 Sending login request for', email);
            const resp = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            let data = {};
            try {
                data = await resp.json();
            } catch (e) {
                console.warn('Could not parse login response JSON', e);
            }
            console.log('📨 Login response:', { status: resp.status, data });
            if (data.requiresVerification || data.showVerificationPopup) {
                console.log('⚠️ User needs email verification');
                const loginModal = document.getElementById('loginModal');
                if (loginModal) {
                    loginModal.classList.remove('active');
                    loginModal.style.display = 'none';
                }
                document.body.style.overflow = 'auto';
                const verificationModal = document.getElementById('verificationModal');
                const verifyEmailInput = document.getElementById('verifyEmail');
                const verifyCodeInput = document.getElementById('verifyCode');
                if (verifyEmailInput) verifyEmailInput.value = email;
                if (verifyCodeInput) verifyCodeInput.value = '';
                if (verificationModal) {
                    verificationModal.style.display = 'flex';
                    document.body.style.overflow = 'hidden';
                    setTimeout(() => verifyCodeInput?.focus(), 100);
                }
                showNotification('📧 Verification code sent! Check your email.', 'warning');
                if (submitButton) {
                    submitButton.disabled = false;
                    submitButton.innerHTML = originalText;
                }
                return;
            }
            if (resp.ok && data.success && data.token) {
                localStorage.setItem('fastfoodinsight_token', data.token);
                if (window.currentState) window.currentState.user = data.user || null;
                const loginModal = document.getElementById('loginModal');
                if (loginModal) {
                    loginModal.classList.remove('active');
                    loginModal.style.display = 'none';
                }
                document.body.style.overflow = 'auto';
                if (typeof updateAuthUI === 'function') updateAuthUI(true);
                showNotification(`✅ Welcome back, ${data.user?.name || 'User'}!`, 'success');
                if (typeof createNewChatSession === 'function') await createNewChatSession();
                if (typeof loadChatSessions === 'function') await loadChatSessions();
                if (typeof checkUsage === 'function') checkUsage();
                if (submitButton) {
                    submitButton.disabled = false;
                    submitButton.innerHTML = originalText;
                }
                return;
            }
            const errMsg = (data && (data.error || data.message)) || 'Invalid email or password';
            if (passwordError) {
                passwordError.textContent = errMsg;
                passwordError.classList.add('active');
            } else {
                showNotification(errMsg, 'error');
            }
        } catch (err) {
            console.error('❌ Login error:', err);
            if (passwordError) {
                passwordError.textContent = 'Login failed. Please try again.';
                passwordError.classList.add('active');
            } else {
                showNotification('Login failed. Please try again.', 'error');
            }
        } finally {
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.innerHTML = originalText;
            }
        }
    }

    window.handleEmailPasswordLogin = handleEmailPasswordLogin_override;

    function bindLoginOverride() {
        const authBtn = document.querySelector('#emailPasswordForm .btn-primary');
        if (authBtn) {
            authBtn.removeEventListener('click', handleEmailPasswordLogin_override);
            authBtn.addEventListener('click', handleEmailPasswordLogin_override);
        }
        window.handleEmailPasswordLogin = handleEmailPasswordLogin_override;
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindLoginOverride);
    } else {
        bindLoginOverride();
    }
    window.__authFixesApplied = true;
})();

function handleInputHintVisibility() {
    const userInput = document.getElementById('userInput');
    const inputHint = document.querySelector('.input-hint');
    if (!userInput || !inputHint) return;
    if (userInput.value.trim() === '') {
        inputHint.style.display = 'flex';
    } else {
        inputHint.style.display = 'none';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const userInput = document.getElementById('userInput');
    if (userInput) {
        userInput.addEventListener('input', handleInputHintVisibility);
        userInput.addEventListener('keyup', handleInputHintVisibility);
        userInput.addEventListener('change', handleInputHintVisibility);
        handleInputHintVisibility();
    }
});

function detectDarkMode() {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
}
if (window.matchMedia) {
    const darkModeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    darkModeMediaQuery.addEventListener('change', detectDarkMode);
    detectDarkMode();
}
document.addEventListener('DOMContentLoaded', () => {
    detectDarkMode();
});

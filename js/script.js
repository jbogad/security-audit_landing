// ============================================
// BASIC UI FUNCTIONS
// ============================================

// Smooth scroll
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth' });
        }
    });
});

// Dropdown Management
function toggleAuthDropdown() {
    const dropdown = document.getElementById('authDropdown');
    dropdown.classList.toggle('active');
}

function closeAuthDropdown() {
    const dropdown = document.getElementById('authDropdown');
    dropdown.classList.remove('active');
}

// Close dropdown when clicking outside
document.addEventListener('click', function(e) {
    const dropdown = document.getElementById('authDropdown');
    const btnLogin = document.querySelector('.btn-login');
    
    if (dropdown && btnLogin && !dropdown.contains(e.target) && !btnLogin.contains(e.target)) {
        closeAuthDropdown();
    }
});

// Mostrar mensajes
function showMessage(type, message) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message-toast ${type}`;
    messageDiv.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
        ${message}
    `;
    document.body.appendChild(messageDiv);
    
    setTimeout(() => messageDiv.classList.add('show'), 100);
    setTimeout(() => {
        messageDiv.classList.remove('show');
        setTimeout(() => messageDiv.remove(), 300);
    }, 3000);
}

// ============================================
// UI UPDATES
// ============================================

async function updateUIForLoggedInUser(user) {
    const btnLogin = document.querySelector('.btn-login');
    const laboratoriosSection = document.getElementById('laboratorios');
    const authDropdown = document.getElementById('authDropdown');
    
    try {
        const { success, profile } = await window.supabaseAuth.getUserProfile(user.id);
        
        if (success && profile) {
            btnLogin.innerHTML = `<i class="fas fa-user-circle"></i> ${profile.full_name || user.email}`;
        } else {
            btnLogin.innerHTML = `<i class="fas fa-user-circle"></i> ${user.email}`;
        }
        
        // Cerrar dropdown si está abierto
        authDropdown.classList.remove('active');
        
        // Hacer el botón clickeable al perfil (no toggle, ir al perfil)
        btnLogin.style.cursor = 'pointer';
        btnLogin.onclick = () => {
            window.location.href = '/profile.html';
        };
        
        // Mostrar los laboratorios
        if (laboratoriosSection) {
            laboratoriosSection.style.display = 'block';
        }
    } catch (error) {
        console.log('Error updating UI:', error);
    }
}

// Check authentication on page load
window.addEventListener('DOMContentLoaded', async () => {
    try {
        const { success, user } = await window.supabaseAuth.getCurrentUser();
        if (success && user) {
            updateUIForLoggedInUser(user);
        } else {
            // Si no hay usuario, el botón abre el dropdown
            document.querySelector('.btn-login').onclick = toggleAuthDropdown;
        }
    } catch (error) {
        console.log('No active session');
        document.querySelector('.btn-login').onclick = toggleAuthDropdown;
    }
});

// ============================================
// TAB MANAGEMENT FOR DROPDOWN
// ============================================

function switchDropdownTab(tab) {
    document.querySelectorAll('.dropdown-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.dropdown-tab').forEach(t => t.classList.remove('active'));
    
    if (tab === 'login') {
        document.getElementById('loginDropdownTab').classList.add('active');
        document.querySelectorAll('.dropdown-tab')[0].classList.add('active');
    } else if (tab === 'register') {
        document.getElementById('registerDropdownTab').classList.add('active');
        document.querySelectorAll('.dropdown-tab')[1].classList.add('active');
    } else if (tab === 'forgot') {
        document.getElementById('forgotDropdownTab').classList.add('active');
        document.querySelectorAll('.dropdown-tab')[2].classList.add('active');
    }
}

// ============================================
// LOGIN HANDLER
// ============================================

async function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const submitBtn = e.target.querySelector('button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Iniciando...';
    
    try {
        const result = await window.supabaseAuth.loginUser(email, password);
        if (result.success) {
            showMessage('success', result.message);
            setTimeout(() => {
                closeAuthDropdown();
                location.reload();
            }, 1500);
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Login error:', error);
        showMessage('error', 'Error al iniciar sesión');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Entrar';
    }
}

// ============================================
// REGISTER HANDLER
// ============================================

async function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-confirm-password').value;
    const submitBtn = e.target.querySelector('button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creando...';
    
    try {
        const result = await window.supabaseAuth.registerUser(username, email, password, confirmPassword);
        if (result.success) {
            showMessage('success', result.message);
            setTimeout(() => {
                switchDropdownTab('login');
                document.getElementById('login-email').value = email;
                document.getElementById('login-password').value = '';
                document.getElementById('registerForm').reset();
            }, 1500);
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Register error:', error);
        showMessage('error', 'Error al crear la cuenta');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-user-plus"></i> Crear Cuenta';
    }
}

// ============================================
// LOGOUT HANDLER
// ============================================

async function handleLogout() {
    const result = await window.supabaseAuth.logoutUser();
    if (result.success) {
        showMessage('success', result.message);
        setTimeout(() => {
            window.location.href = '/';
        }, 1500);
    } else {
        showMessage('error', result.message);
    }
}

// ============================================
// PASSWORD RESET HANDLER
// ============================================

async function handleForgotPassword(e) {
    e.preventDefault();
    const email = document.getElementById('forgot-email').value;
    const submitBtn = e.target.querySelector('button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enviando...';
    
    try {
        const result = await window.supabaseAuth.requestPasswordReset(email);
        if (result.success) {
            showMessage('success', result.message);
            setTimeout(() => {
                switchDropdownTab('login');
                document.getElementById('forgotForm').reset();
            }, 2000);
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Password reset error:', error);
        showMessage('error', 'Error al enviar email de recuperación');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Enviar';
    }
}

// ============================================
// CHANGE PASSWORD HANDLER (Profile page)
// ============================================

async function handleChangePassword(e) {
    e.preventDefault();
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const submitBtn = e.target.querySelector('button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cambiando...';
    
    try {
        const result = await window.supabaseAuth.updatePassword(newPassword, confirmPassword);
        if (result.success) {
            showMessage('success', result.message);
            document.getElementById('changePasswordForm').reset();
            setTimeout(() => {
                window.location.href = '/profile.html';
            }, 1500);
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Change password error:', error);
        showMessage('error', 'Error al cambiar contraseña');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-shield-alt"></i> Cambiar Contraseña';
    }
}
            


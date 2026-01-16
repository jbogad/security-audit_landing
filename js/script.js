// ============================================
// FUNCIONES BÁSICAS
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

// Modal
function openModal() {
    document.getElementById('authModal').classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeModal() {
    document.getElementById('authModal').classList.remove('active');
    document.body.style.overflow = 'auto';
}

document.getElementById('authModal')?.addEventListener('click', function(e) {
    if (e.target === this) closeModal();
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeModal();
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

// Actualizar UI cuando está logueado
async function updateUIForLoggedInUser(user) {
    const btnLogin = document.querySelector('.btn-login');
    const { profile } = await window.supabaseAuth.getUserProfile(user.id);
    
    if (profile && profile.users) {
        btnLogin.innerHTML = `<i class="fas fa-user-circle"></i> ${profile.users.username}`;
        btnLogin.onclick = () => window.location.href = '/profile.html';
    }
}

// Logout
async function handleLogout() {
    const result = await window.supabaseAuth.logoutUser();
    if (result.success) {
        showMessage('success', 'Sesión cerrada');
        const btnLogin = document.querySelector('.btn-login');
        btnLogin.innerHTML = '<i class="fas fa-user"></i> Entrar';
        btnLogin.onclick = openModal;
    }
}

// Check auth on load
window.addEventListener('DOMContentLoaded', async () => {
    try {
        const { user } = await window.supabaseAuth.getCurrentUser();
        if (user) updateUIForLoggedInUser(user);
    } catch (error) {
        console.log('No hay sesión activa');
    }
});

// Cambiar tabs
function switchTab(tab) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
    
    if (tab === 'login') {
        document.getElementById('loginTab').classList.add('active');
        document.querySelectorAll('.modal-tab')[0].classList.add('active');
    } else if (tab === 'register') {
        document.getElementById('registerTab').classList.add('active');
        document.querySelectorAll('.modal-tab')[1].classList.add('active');
    }
}

// Login
async function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const submitBtn = e.target.querySelector('button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Iniciando sesión...';
    
    try {
        const result = await window.supabaseAuth.loginUser(email, password);
        if (result.success) {
            showMessage('success', result.message);
            setTimeout(() => {
                closeModal();
                updateUIForLoggedInUser(result.user);
                location.reload();
            }, 1500);
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        showMessage('error', 'Error al iniciar sesión');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Iniciar Sesión';
    }
}

// Register
async function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const submitBtn = e.target.querySelector('button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creando cuenta...';
    
    try {
        const result = await window.supabaseAuth.registerUser(username, email, password);
        if (result.success) {
            showMessage('success', result.message);
            setTimeout(() => {
                switchTab('login');
                document.getElementById('login-email').value = email;
                document.getElementById('login-password').value = '';
            }, 1500);
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        showMessage('error', 'Error al crear la cuenta');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-user-plus"></i> Crear Cuenta';
    }
}
            }, 1000);
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Login error:', error);
        showMessage('error', 'Error al iniciar sesión. Intenta de nuevo.');
    } finally {
        // Restaurar botón
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Iniciar Sesión';
    }
}

// ============================================
// HANDLE REGISTER
// ============================================
async function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const submitBtn = e.target.querySelector('button[type="submit"]');
    
    // Validación de contraseña segura
    const validation = window.supabaseAuth.validatePassword(password);
    if (!validation.isValid) {
        showMessage('error', 'Contraseña insegura:\n• ' + validation.errors.join('\n• '));
        return;
    }
    
    // Estado de carga
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creando cuenta...';
    
    try {
        const result = await window.supabaseAuth.registerUser(username, email, password);
        
        if (result.success) {
            // Mensaje de éxito
            showMessage('success', result.message);
            


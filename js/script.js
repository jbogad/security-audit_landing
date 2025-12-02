// ============================================
// SMOOTH SCROLLING
// ============================================
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// ============================================
// NAVBAR BACKGROUND ON SCROLL
// ============================================
window.addEventListener('scroll', function() {
    const nav = document.querySelector('nav');
    if (window.scrollY > 50) {
        nav.style.background = 'rgba(10, 14, 39, 0.98)';
    } else {
        nav.style.background = 'rgba(10, 14, 39, 0.95)';
    }
});

// ============================================
// MODAL FUNCTIONS
// ============================================
function openModal() {
    document.getElementById('authModal').classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeModal() {
    document.getElementById('authModal').classList.remove('active');
    document.body.style.overflow = 'auto';
}

// Close modal on outside click
document.getElementById('authModal').addEventListener('click', function(e) {
    if (e.target === this) {
        closeModal();
    }
});

// Close modal with ESC key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeModal();
    }
});

// ============================================
// HELPER FUNCTIONS
// ============================================

// Mostrar mensajes de éxito/error
function showMessage(type, message) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message-toast ${type}`;
    messageDiv.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
        ${message}
    `;
    
    document.body.appendChild(messageDiv);
    
    setTimeout(() => {
        messageDiv.classList.add('show');
    }, 100);
    
    setTimeout(() => {
        messageDiv.classList.remove('show');
        setTimeout(() => messageDiv.remove(), 300);
    }, 3000);
}

// Actualizar UI cuando el usuario está logueado
async function updateUIForLoggedInUser(user) {
    const btnLogin = document.querySelector('.btn-login');
    
    // Obtener perfil completo
    const { profile } = await window.supabaseAuth.getUserProfile(user.id);
    
    if (profile && profile.users) {
        btnLogin.innerHTML = `
            <i class="fas fa-user-circle"></i> ${profile.users.username}
        `;
        btnLogin.onclick = showUserMenu;
    }
}

// Menú de usuario (logout, perfil, etc)
function showUserMenu() {
    // Aquí puedes agregar un dropdown con opciones
    const confirmLogout = confirm('¿Cerrar sesión?');
    
    if (confirmLogout) {
        handleLogout();
    }
}

// Cerrar sesión
async function handleLogout() {
    const result = await window.supabaseAuth.logoutUser();
    
    if (result.success) {
        showMessage('success', 'Sesión cerrada correctamente');
        
        // Restaurar botón de login
        const btnLogin = document.querySelector('.btn-login');
        btnLogin.innerHTML = '<i class="fas fa-user"></i> Entrar';
        btnLogin.onclick = openModal;
    }
}

// ============================================
// CHECK AUTH STATUS ON LOAD
// ============================================
window.addEventListener('DOMContentLoaded', async () => {
    const { user } = await window.supabaseAuth.getCurrentUser();
    
    if (user) {
        updateUIForLoggedInUser(user);
    }
});

// ============================================
// SWITCH BETWEEN LOGIN/REGISTER TABS
// ============================================
function switchTab(tab) {
    const loginTab = document.getElementById('loginTab');
    const registerTab = document.getElementById('registerTab');
    const resetTab = document.getElementById('resetTab');
    const tabs = document.querySelectorAll('.modal-tab');
    const modalTabs = document.querySelector('.modal-tabs');

    tabs.forEach(t => t.classList.remove('active'));
    loginTab.classList.remove('active');
    registerTab.classList.remove('active');
    resetTab.classList.remove('active');
    
    // Restaurar header y tabs
    document.querySelector('.modal-header h2').textContent = 'Bienvenido a HackPrevent';
    document.querySelector('.modal-header p').textContent = 'Accede a tu cuenta o crea una nueva';
    modalTabs.style.display = 'flex';

    if (tab === 'login') {
        loginTab.classList.add('active');
        tabs[0].classList.add('active');
    } else if (tab === 'register') {
        registerTab.classList.add('active');
        tabs[1].classList.add('active');
    }
}

// ============================================
// HANDLE LOGIN
// ============================================
async function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const submitBtn = e.target.querySelector('button[type="submit"]');
    
    // Estado de carga
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Iniciando sesión...';
    
    try {
        const result = await window.supabaseAuth.loginUser(email, password);
        
        if (result.success) {
            // Mensaje de éxito
            showMessage('success', result.message);
            
            // Cerrar modal y actualizar UI
            setTimeout(() => {
                closeModal();
                updateUIForLoggedInUser(result.user);
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
    
    // Validación básica
    if (password.length < 6) {
        showMessage('error', 'La contraseña debe tener al menos 6 caracteres');
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
            
            // Cambiar a tab de login después de 2 segundos
            setTimeout(() => {
                switchTab('login');
                document.getElementById('login-email').value = email;
            }, 2000);
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Register error:', error);
        showMessage('error', 'Error al crear cuenta. Intenta de nuevo.');
    } finally {
        // Restaurar botón
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-user-plus"></i> Crear Cuenta';
    }
}

// ============================================
// SHOW PASSWORD RESET FORM
// ============================================
function showPasswordReset(e) {
    e.preventDefault();
    const loginTab = document.getElementById('loginTab');
    const registerTab = document.getElementById('registerTab');
    const resetTab = document.getElementById('resetTab');
    const tabs = document.querySelectorAll('.modal-tab');
    
    loginTab.classList.remove('active');
    registerTab.classList.remove('active');
    resetTab.classList.add('active');
    tabs.forEach(t => t.classList.remove('active'));
    
    document.querySelector('.modal-header h2').textContent = 'Recuperar Contraseña';
    document.querySelector('.modal-header p').textContent = 'Te enviaremos un enlace de recuperación';
    document.querySelector('.modal-tabs').style.display = 'none';
}

// ============================================
// HANDLE PASSWORD RESET (Supabase)
// ============================================
async function handlePasswordReset(e) {
    e.preventDefault();
    const email = document.getElementById('reset-email').value;
    const messageDiv = document.getElementById('resetMessage');
    const resetBtn = document.getElementById('resetBtn');
    
    // Cambiar botón a estado de carga
    resetBtn.disabled = true;
    resetBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enviando...';
    
    try {
        const result = await window.supabaseAuth.requestPasswordReset(email);
        
        if (result.success) {
            // Mostrar mensaje de éxito
            messageDiv.innerHTML = `
                <div class="success-message">
                    <i class="fas fa-check-circle"></i>
                    <strong>¡Email enviado!</strong><br>
                    Revisa tu bandeja de entrada en <strong>${email}</strong><br>
                    <small>(También revisa spam/correo no deseado)</small>
                </div>
            `;
            
            // Limpiar formulario
            document.getElementById('reset-email').value = '';
        } else {
            messageDiv.innerHTML = `
                <div class="error-message">
                    <i class="fas fa-exclamation-circle"></i>
                    <strong>Error</strong><br>
                    ${result.message}
                </div>
            `;
        }
        
    } catch (error) {
        console.error('Password reset error:', error);
        messageDiv.innerHTML = `
            <div class="error-message">
                <i class="fas fa-exclamation-circle"></i>
                <strong>Error al enviar el email</strong><br>
                Por favor, inténtalo de nuevo más tarde.
            </div>
        `;
    } finally {
        // Restaurar botón
        resetBtn.disabled = false;
        resetBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Enviar Email de Recuperación';
    }
}

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
function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    // Aquí irá la lógica de autenticación real
    console.log('Login:', email, password);
    alert('¡Funcionalidad de login en desarrollo! \n\nEmail: ' + email);
    closeModal();
}

// ============================================
// HANDLE REGISTER
// ============================================
function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    
    // Aquí irá la lógica de registro real
    console.log('Register:', username, email, password);
    alert('¡Cuenta creada exitosamente! \n\nUsuario: ' + username + '\nEmail: ' + email + '\n\n(Funcionalidad en desarrollo)');
    closeModal();
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
// HANDLE PASSWORD RESET (EmailJS)
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
        const resetToken = Math.random().toString(36).substring(2, 15);
        const resetLink = `https://hackprevent.es/reset-password?token=${resetToken}`;
        
        await emailjs.send(
            'service_bqquujw',
            'template_jq9mzps',
            {
                to_email: email,
                user_email: email,
                reset_link: resetLink,
                from_name: 'HackPrevent - Soporte',
                reply_to: 'soporte@hackprevent.es'
            }
        );
        
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
        
    } catch (error) {
        console.error('EmailJS Error:', error);
        messageDiv.innerHTML = `
            <div class="error-message">
                <i class="fas fa-exclamation-circle"></i>
                <strong>Error al enviar el email</strong><br>
                ${error.text || error.message || 'Por favor, inténtalo de nuevo más tarde.'}
            </div>
        `;
    } finally {
        // Restaurar botón
        resetBtn.disabled = false;
        resetBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Enviar Email de Recuperación';
    }
}

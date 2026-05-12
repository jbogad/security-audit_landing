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

// Version cache burst for main script: v5
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
// CANJEAR CÓDIGOS XP
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    const redeemForm = document.getElementById('redeem-form');
    if (redeemForm) {
        redeemForm.addEventListener('submit', handleRedeem);
    }
});

async function handleRedeem(e) {
    e.preventDefault();
    const code = document.getElementById('redeem-code').value.trim();
    const resultBox = document.getElementById('redeem-result');
    
    // Validar formato: HKPRV-WEB-XXXXX
    const codeRegex = /^HKPRV-WEB-[A-Z0-9]{5}$/i;
    
    if (codeRegex.test(code)) {
        const { success, user } = await window.supabaseAuth.getCurrentUser();
        if (!success || !user) {
            resultBox.innerHTML = '<span class="error-text" style="color: #ff3366;">Debes iniciar sesión para canjear códigos.</span>';
            return;
        }

        // Recuperar perfil y array de códigos desde la BB. Lo simulamos recuperando local por si falla.
        let userProfile = null;
        let dbCurrentXp = 0;
        let usedCodes = [];

        if (window.supabaseAuth.getUserProfile) {
            const res = await window.supabaseAuth.getUserProfile(user.id);
            if (res.success && res.profile) {
                userProfile = res.profile;
                dbCurrentXp = res.profile.xp || 0;
                // Si tienes columna used_codes tipo array o JSONB:
                // usedCodes = res.profile.used_codes || [];
            }
        }

        // Respaldo / lógica temporal de array en local por si la DB aún no tiene la columna "used_codes"
        if (usedCodes.length === 0) {
            usedCodes = JSON.parse(localStorage.getItem(`used_codes_${user.id}`) || '[]');
        }
        
        if (usedCodes.includes(code.toUpperCase())) {
            resultBox.innerHTML = '<span class="error-text" style="color: #ff3366;"><i class="fas fa-times-circle"></i> Este código ya ha sido canjeado.</span>';
        } else {
            usedCodes.push(code.toUpperCase());
            localStorage.setItem(`used_codes_${user.id}`, JSON.stringify(usedCodes));
            
            // Sumar a la DB
            dbCurrentXp += 50;
            
            if (window.supabaseAuth.updateProfile) {
                // Actualizamos DB: puedes quitar usedCodes si no tienes la columna. Asumiré que guardamos la XP
                await window.supabaseAuth.updateProfile(user.id, { xp: dbCurrentXp });
            }
            // También respaldamos en localStorage
            localStorage.setItem(`xp_${user.id}`, dbCurrentXp);

            // Actualizar visualmente la barra de navegación para que se note instantáneo
            updateUIForLoggedInUser(user);

            resultBox.innerHTML = `<span class="success-text" style="color: #00ff9d;"><i class="fas fa-check-circle"></i> ¡Código verificado! +50 XP añadidos directamente a tu cuenta. Total: ${dbCurrentXp} XP.</span>`;
            document.getElementById('redeem-code').value = '';
        }
    } else {
        resultBox.innerHTML = '<span class="error-text" style="color: #ff3366;"><i class="fas fa-times-circle"></i> Código inválido. Formato incorrecto.</span>';
    }
}

// ============================================
// UI UPDATES
// ============================================

async function updateUIForLoggedInUser(user) {
    const btnLogin = document.querySelector('.btn-login');
    const laboratoriosSection = document.getElementById('laboratorios');
    const authDropdown = document.getElementById('authDropdown');
    const isProfilePage = window.location.pathname.endsWith('/profile.html');

    try {
        const { success, profile } = await window.supabaseAuth.getUserProfile(user.id);

        if (!isProfilePage && btnLogin) {
            let xpText = '';
            if (success && profile && profile.xp !== undefined) {
                xpText = ` <span style="color: #ffeb3b; margin-left: 5px;">| <i class="fas fa-star"></i> ${profile.xp} XP</span>`;
            } else {
                let localXp = localStorage.getItem(`xp_${user.id}`);
                if (localXp) {
                    xpText = ` <span style="color: #ffeb3b; margin-left: 5px;">| <i class="fas fa-star"></i> ${localXp} XP</span>`;
                }
            }

            if (success && profile && profile.full_name) {
                btnLogin.innerHTML = `<i class="fas fa-user-circle"></i> ${profile.full_name}${xpText}`;
            } else {
                btnLogin.innerHTML = `<i class="fas fa-user-circle"></i> ${user.email.split('@')[0]}${xpText}`;
            }

            // Cerrar dropdown si está abierto
            if (authDropdown) {
                authDropdown.classList.remove('active');
            }

            // Hacer el botón clickeable al perfil (no toggle, ir al perfil)
            btnLogin.style.cursor = 'pointer';
            btnLogin.onclick = () => {
                window.location.href = '/profile.html';
            };
        }
        
        // Mostrar los laboratorios
        if (laboratoriosSection) {
            laboratoriosSection.style.display = 'block';
        }
        
        // Mostrar sección de canjeo de XP si existe
        const canjearSection = document.getElementById('canjear-xp');
        if (canjearSection) {
            canjearSection.style.display = 'block';
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



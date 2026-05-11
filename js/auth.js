// ============================================
// SUPABASE AUTHENTICATION SYSTEM
// ============================================

const SUPABASE_URL = 'https://sdudrliwounfknjiwsgb.supabase.co'
const SUPABASE_ANON_KEY = 'sb_publishable_QKSOaxQE05LKoSpraT4seg_aFvDBLLO'

const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY)

// ============================================
// VALIDATIONS
// ============================================

function validatePassword(password) {
    const errors = [];
    
    if (password.length < 6) {
        errors.push('Mínimo 6 caracteres');
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

function validateEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

function validateUsername(username) {
    if (username.length < 3) {
        return { isValid: false, message: 'El usuario debe tener al menos 3 caracteres' };
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
        return { isValid: false, message: 'El usuario solo puede contener letras, números, _ y -' };
    }
    return { isValid: true, message: '' };
}

// ============================================
// REGISTRATION
// ============================================

async function registerUser(username, email, password, confirmPassword) {
    try {
        // Validar email
        if (!validateEmail(email)) {
            return { success: false, message: 'Email inválido' };
        }

        // Validar usuario
        const usernameValidation = validateUsername(username);
        if (!usernameValidation.isValid) {
            return { success: false, message: usernameValidation.message };
        }

        // Validar contraseña
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.isValid) {
            return { success: false, message: 'Contraseña: ' + passwordValidation.errors.join(', ') };
        }

        // Validar confirmación de contraseña
        if (password !== confirmPassword) {
            return { success: false, message: 'Las contraseñas no coinciden' };
        }

        // Registrar usuario
        const { data, error } = await supabase.auth.signUp({
            email: email,
            password: password,
            options: {
                data: { 
                    username: username,
                    created_at: new Date().toISOString()
                },
                emailRedirectTo: window.location.origin
            }
        });

        if (error) {
            console.error('Signup error:', error);
            if (error.message.includes('already registered')) {
                return { success: false, message: 'Este email ya está registrado' };
            }
            return { success: false, message: 'Error al registrar: ' + error.message };
        }

        // Guardar sesión en localStorage
        if (data.session) {
            localStorage.setItem('supabase_session', JSON.stringify(data.session));
        }

        return {
            success: true,
            user: data.user,
            message: '¡Cuenta creada exitosamente!'
        };

    } catch (error) {
        console.error('Register error:', error);
        return { success: false, message: 'Error al crear la cuenta' };
    }
}

// ============================================
// LOGIN
// ============================================

async function loginUser(email, password) {
    try {
        if (!validateEmail(email)) {
            return { success: false, message: 'Email inválido' };
        }

        const { data, error } = await supabase.auth.signInWithPassword({
            email: email,
            password: password
        });

        if (error) {
            console.error('Login error:', error);
            if (error.message.includes('Invalid login credentials')) {
                return { success: false, message: 'Email o contraseña incorrectos' };
            }
            return { success: false, message: 'Error al iniciar sesión' };
        }

        // Guardar sesión en localStorage
        if (data.session) {
            localStorage.setItem('supabase_session', JSON.stringify(data.session));
            localStorage.setItem('user_email', email);
        }

        return {
            success: true,
            user: data.user,
            session: data.session,
            message: '¡Bienvenido!'
        };

    } catch (error) {
        console.error('Login error:', error);
        return { success: false, message: 'Error al iniciar sesión' };
    }
}

// ============================================
// LOGOUT
// ============================================

async function logoutUser() {
    try {
        const { error } = await supabase.auth.signOut();

        if (error) throw error;

        // Limpiar localStorage
        localStorage.removeItem('supabase_session');
        localStorage.removeItem('user_email');

        return { success: true, message: 'Sesión cerrada correctamente' };

    } catch (error) {
        console.error('Logout error:', error);
        return { success: false, message: 'Error al cerrar sesión' };
    }
}

// ============================================
// SESSION PERSISTENCE
// ============================================

async function restoreSession() {
    try {
        // Verificar si hay sesión guardada en localStorage
        const savedSession = localStorage.getItem('supabase_session');
        
        if (savedSession) {
            try {
                const session = JSON.parse(savedSession);
                // Verificar si la sesión es válida
                const { data, error } = await supabase.auth.getSession();
                
                if (data.session) {
                    return { success: true, session: data.session };
                }
            } catch (e) {
                localStorage.removeItem('supabase_session');
            }
        }

        return { success: false, session: null };

    } catch (error) {
        console.error('Restore session error:', error);
        return { success: false, session: null };
    }
}

async function getCurrentUser() {
    try {
        const { data: { user }, error } = await supabase.auth.getUser();

        if (error || !user) {
            return { success: false, user: null };
        }

        return { success: true, user: user };

    } catch (error) {
        console.error('Get current user error:', error);
        return { success: false, user: null };
    }
}

async function isAuthenticated() {
    try {
        const { data: { session } } = await supabase.auth.getSession();
        return !!session;
    } catch (error) {
        console.error('Auth check error:', error);
        return false;
    }
}

// ============================================
// PASSWORD RESET
// ============================================

async function requestPasswordReset(email) {
    try {
        if (!validateEmail(email)) {
            return { success: false, message: 'Email inválido' };
        }

        const { error } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: `${window.location.origin}/reset-password.html`
        });

        if (error) {
            console.error('Password reset error:', error);
            return { success: false, message: 'Error al enviar email de recuperación' };
        }

        return {
            success: true,
            message: 'Email de recuperación enviado. Revisa tu bandeja de entrada.'
        };

    } catch (error) {
        console.error('Password reset error:', error);
        return { success: false, message: 'Error al enviar email de recuperación' };
    }
}

// ============================================
// PASSWORD UPDATE
// ============================================

async function updatePassword(newPassword, confirmPassword) {
    try {
        // Validar contraseña
        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.isValid) {
            return { success: false, message: 'Contraseña: ' + passwordValidation.errors.join(', ') };
        }

        // Validar confirmación
        if (newPassword !== confirmPassword) {
            return { success: false, message: 'Las contraseñas no coinciden' };
        }

        const { error } = await supabase.auth.updateUser({
            password: newPassword
        });

        if (error) {
            console.error('Update password error:', error);
            return { success: false, message: 'Error al cambiar contraseña' };
        }

        return { success: true, message: 'Contraseña actualizada exitosamente' };

    } catch (error) {
        console.error('Update password error:', error);
        return { success: false, message: 'Error al cambiar contraseña' };
    }
}

// ============================================
// PROFILE FUNCTIONS
// ============================================

async function getUserProfile(userId) {
    try {
        const { data, error } = await supabase
            .from('profiles')
            .select('*')
            .eq('id', userId)
            .single();

        if (error && error.code !== 'PGRST116') {
            console.error('Get profile error:', error);
            return { success: false, profile: null };
        }

        return { success: true, profile: data || null };

    } catch (error) {
        console.error('Get profile error:', error);
        return { success: false, profile: null };
    }
}

async function updateProfile(userId, profileData) {
    try {
        const { data, error } = await supabase
            .from('profiles')
            .upsert({
                id: userId,
                ...profileData,
                updated_at: new Date().toISOString()
            });

        if (error) {
            console.error('Update profile error:', error);
            return { success: false, message: 'Error al actualizar perfil' };
        }

        return { success: true, message: 'Perfil actualizado exitosamente' };

    } catch (error) {
        console.error('Update profile error:', error);
        return { success: false, message: 'Error al actualizar perfil' };
    }
}

// ============================================
// EXPORT FUNCTIONS
// ============================================

window.supabaseAuth = {
    // Validations
    validatePassword,
    validateEmail,
    validateUsername,

    // Auth
    registerUser,
    loginUser,
    logoutUser,

    // Session
    restoreSession,
    getCurrentUser,
    isAuthenticated,

    // Password
    requestPasswordReset,
    updatePassword,

    // Profile
    getUserProfile,
    updateProfile
};

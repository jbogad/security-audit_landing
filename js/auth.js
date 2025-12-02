// ============================================
// SUPABASE AUTHENTICATION
// ============================================

// Credenciales de Supabase - HackPrevent
const SUPABASE_URL = 'https://fkpwhjczidflwqbfxtoe.supabase.co'
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZrcHdoamN6aWRmbHdxYmZ4dG9lIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjQ2NzE1ODgsImV4cCI6MjA4MDI0NzU4OH0.Mep-S0tps9Fd3Yiozv5aK_h251HKk63tsYobDr4e-pk'

const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY)

// ============================================
// VALIDACIÓN DE CONTRASEÑAS SEGURAS
// ============================================
function validatePassword(password) {
    const errors = [];
    
    // Mínimo 8 caracteres
    if (password.length < 8) {
        errors.push('Mínimo 8 caracteres');
    }
    
    // Al menos una mayúscula
    if (!/[A-Z]/.test(password)) {
        errors.push('Al menos una mayúscula');
    }
    
    // Al menos una minúscula
    if (!/[a-z]/.test(password)) {
        errors.push('Al menos una minúscula');
    }
    
    // Al menos un número
    if (!/[0-9]/.test(password)) {
        errors.push('Al menos un número');
    }
    
    // Al menos un carácter especial
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        errors.push('Al menos un carácter especial (!@#$%...)');
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

// ============================================
// CALCULAR FORTALEZA DE CONTRASEÑA
// ============================================
function getPasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) strength++;
    
    if (strength <= 2) return { level: 'weak', text: 'Débil', color: '#ff4757' };
    if (strength <= 3) return { level: 'medium', text: 'Media', color: '#ffa502' };
    if (strength <= 4) return { level: 'good', text: 'Buena', color: '#1e90ff' };
    return { level: 'strong', text: 'Fuerte', color: '#00ff9d' };
}

// ============================================
// REGISTRO DE USUARIO
// ============================================
async function registerUser(username, email, password) {
    try {
        // Validar contraseña segura
        const validation = validatePassword(password);
        if (!validation.isValid) {
            return { 
                success: false, 
                message: 'Contraseña no cumple requisitos:\n• ' + validation.errors.join('\n• ')
            };
        }
        
        // Crear usuario en Supabase Auth
        const { data: authData, error: authError } = await supabase.auth.signUp({
            email: email,
            password: password,
            options: {
                data: {
                    username: username
                },
                emailRedirectTo: 'https://hackprevent.es'
            }
        })

        if (authError) throw authError

        // Si se creó correctamente
        if (authData.user) {
            console.log('Usuario creado en auth:', authData.user.id)
        }

        return { 
            success: true, 
            user: authData.user,
            message: '¡Cuenta creada! Revisa tu email para confirmarla.' 
        }

    } catch (error) {
        console.error('Register error:', error)
        
        // Mensajes de error amigables
        if (error.message.includes('already registered') || error.message.includes('User already registered')) {
            return { success: false, message: 'Este email ya está registrado' }
        }
        if (error.message.includes('duplicate key')) {
            return { success: false, message: 'Este nombre de usuario ya existe' }
        }
        if (error.message.includes('Password')) {
            return { success: false, message: 'La contraseña no cumple los requisitos de seguridad' }
        }
        if (error.message.includes('Database error')) {
            return { success: false, message: 'El nombre de usuario ya existe' }
        }
        if (error.message.includes('rate limit')) {
            return { 
                success: false, 
                message: 'Demasiados intentos. Espera unos minutos.' 
            }
        }
        
        return { 
            success: false, 
            message: 'Error al crear la cuenta. Intenta de nuevo.' 
        }
    }
}

// ============================================
// LOGIN DE USUARIO
// ============================================
async function loginUser(email, password) {
    try {
        const { data, error } = await supabase.auth.signInWithPassword({
            email: email,
            password: password
        })

        if (error) throw error

        // Actualizar last_login
        await supabase
            .from('users')
            .update({ last_login: new Date().toISOString() })
            .eq('id', data.user.id)

        return { 
            success: true, 
            user: data.user,
            session: data.session,
            message: '¡Bienvenido de vuelta!' 
        }

    } catch (error) {
        console.error('Login error:', error)
        
        if (error.message.includes('Invalid login credentials')) {
            return { success: false, message: 'Email o contraseña incorrectos' }
        }
        
        return { 
            success: false, 
            message: error.message || 'Error al iniciar sesión' 
        }
    }
}

// ============================================
// LOGOUT
// ============================================
async function logoutUser() {
    try {
        const { error } = await supabase.auth.signOut()
        if (error) throw error
        
        return { success: true, message: 'Sesión cerrada correctamente' }
    } catch (error) {
        console.error('Logout error:', error)
        return { success: false, message: 'Error al cerrar sesión' }
    }
}

// ============================================
// OBTENER USUARIO ACTUAL
// ============================================
async function getCurrentUser() {
    try {
        const { data: { user }, error } = await supabase.auth.getUser()
        
        if (error) throw error
        
        if (!user) return { user: null }

        // Obtener datos completos del usuario
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('*, profiles(*)')
            .eq('id', user.id)
            .single()

        if (userError) throw userError

        return { user: userData }

    } catch (error) {
        console.error('Get user error:', error)
        return { user: null }
    }
}

// ============================================
// OBTENER PERFIL DE USUARIO
// ============================================
async function getUserProfile(userId) {
    try {
        const { data, error } = await supabase
            .from('profiles')
            .select('*, users!inner(username, email, created_at)')
            .eq('id', userId)
            .single()

        if (error) throw error

        return { profile: data }
    } catch (error) {
        console.error('Error al obtener perfil:', error)
        return { profile: null }
    }
}

// ============================================
// VERIFICAR SI ESTÁ LOGUEADO
// ============================================
async function isAuthenticated() {
    const { data: { session } } = await supabase.auth.getSession()
    return !!session
}

// ============================================
// SOLICITAR RESET DE PASSWORD
// ============================================
async function requestPasswordReset(email) {
    try {
        // 1. Verificar que el email existe
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single()

        if (userError || !userData) {
            // Por seguridad, no decir si el email existe o no
            return { 
                success: true, 
                message: 'Si el email existe, recibirás un enlace de recuperación' 
            }
        }

        // 2. Supabase enviará el email automáticamente
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: 'https://hackprevent.es/reset-password'
        })

        if (error) throw error

        return { 
            success: true, 
            message: 'Email de recuperación enviado correctamente' 
        }

    } catch (error) {
        console.error('Password reset error:', error)
        return { 
            success: false, 
            message: 'Error al enviar el email de recuperación' 
        }
    }
}

// ============================================
// CAMBIAR PASSWORD (con token)
// ============================================
async function updatePassword(newPassword) {
    try {
        const { error } = await supabase.auth.updateUser({
            password: newPassword
        })

        if (error) throw error

        return { 
            success: true, 
            message: 'Contraseña actualizada correctamente' 
        }

    } catch (error) {
        console.error('Update password error:', error)
        return { 
            success: false, 
            message: 'Error al actualizar la contraseña' 
        }
    }
}

// ============================================
// ACTUALIZAR PERFIL DE USUARIO
// ============================================
async function updateProfile(userId, profileData) {
    try {
        const { error } = await supabase
            .from('profiles')
            .update(profileData)
            .eq('id', userId)

        if (error) throw error

        return { success: true, message: 'Perfil actualizado' }

    } catch (error) {
        console.error('Update profile error:', error)
        return { success: false, message: 'Error al actualizar perfil' }
    }
}

// ============================================
// OBTENER PROGRESO EN LABS
// ============================================
async function getUserLabProgress(userId) {
    try {
        const { data, error } = await supabase
            .from('lab_progress')
            .select('*')
            .eq('user_id', userId)
            .order('started_at', { ascending: false })

        if (error) throw error

        return { success: true, data: data || [] }

    } catch (error) {
        console.error('Get lab progress error:', error)
        return { success: false, data: [] }
    }
}

// ============================================
// ACTUALIZAR PROGRESO EN LAB
// ============================================
async function updateLabProgress(userId, labName, status, flagsFound = 0) {
    try {
        const { error } = await supabase
            .from('lab_progress')
            .upsert({
                user_id: userId,
                lab_name: labName,
                status: status,
                flags_found: flagsFound,
                started_at: status === 'in_progress' ? new Date().toISOString() : undefined,
                completed_at: status === 'completed' ? new Date().toISOString() : undefined
            })

        if (error) throw error

        // Si completó un lab, actualizar stats del perfil
        if (status === 'completed') {
            await supabase.rpc('increment_labs_completed', { user_id: userId })
        }

        return { success: true }

    } catch (error) {
        console.error('Update lab progress error:', error)
        return { success: false }
    }
}

// ============================================
// OBTENER RANKING DE USUARIOS
// ============================================
async function getUserRanking(limit = 10) {
    try {
        const { data, error } = await supabase
            .from('user_ranking')
            .select('*')
            .limit(limit)

        if (error) throw error

        return { success: true, data: data || [] }

    } catch (error) {
        console.error('Get ranking error:', error)
        return { success: false, data: [] }
    }
}

// ============================================
// LISTENER DE CAMBIOS DE AUTH
// ============================================
function onAuthStateChange(callback) {
    return supabase.auth.onAuthStateChange((event, session) => {
        callback(event, session)
    })
}

// ============================================
// LOGIN CON OAUTH (GitHub, Google, etc.)
// ============================================
async function loginWithProvider(provider) {
    try {
        const { data, error } = await supabase.auth.signInWithOAuth({
            provider: provider,
            options: {
                redirectTo: 'https://hackprevent.es'
            }
        })

        if (error) throw error

        return { success: true }

    } catch (error) {
        console.error(`${provider} login error:`, error)
        return { 
            success: false, 
            message: `Error al iniciar sesión con ${provider}` 
        }
    }
}

// ============================================
// EXPORTAR FUNCIONES GLOBALMENTE
// ============================================
window.supabaseAuth = {
    registerUser,
    loginUser,
    logoutUser,
    requestPasswordReset,
    updatePassword,
    getCurrentUser,
    isAuthenticated,
    updateProfile,
    getUserProfile,
    getUserLabProgress,
    updateLabProgress,
    getUserRanking,
    onAuthStateChange,
    validatePassword,
    getPasswordStrength,
    loginWithProvider
}

// ============================================
// SUPABASE AUTHENTICATION
// ============================================

const SUPABASE_URL = 'https://fkpwhjczidflwqbfxtoe.supabase.co'
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZrcHdoamN6aWRmbHdxYmZ4dG9lIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjQ2NzE1ODgsImV4cCI6MjA4MDI0NzU4OH0.Mep-S0tps9Fd3Yiozv5aK_h251HKk63tsYobDr4e-pk'

const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY)

// Validación simple de contraseña
function validatePassword(password) {
    if (password.length < 6) {
        return { isValid: false, errors: ['Mínimo 6 caracteres'] };
    }
    return { isValid: true, errors: [] };
}

// Registro de usuario
async function registerUser(username, email, password) {
    try {
        const validation = validatePassword(password);
        if (!validation.isValid) {
            return { success: false, message: 'Contraseña muy corta' };
        }
        
        const { data: authData, error: authError } = await supabase.auth.signUp({
            email: email,
            password: password,
            options: {
                data: { username: username },
                emailRedirectTo: 'https://hackprevent.es'
            }
        })

        if (authError) throw authError

        return { 
            success: true, 
            user: authData.user,
            message: '¡Cuenta creada! Revisa tu email.' 
        }

    } catch (error) {
        console.error('Register error:', error)
        return { success: false, message: 'Error al crear la cuenta' }
    }
}

// Login de usuario
async function loginUser(email, password) {
    try {
        const { data, error } = await supabase.auth.signInWithPassword({
            email: email,
            password: password
        })

        if (error) throw error

        await supabase
            .from('users')
            .update({ last_login: new Date().toISOString() })
            .eq('id', data.user.id)

        return { 
            success: true, 
            user: data.user,
            session: data.session,
            message: '¡Bienvenido!' 
        }

    } catch (error) {
        console.error('Login error:', error)
        return { success: false, message: 'Email o contraseña incorrectos' }
    }
}

// Logout
async function logoutUser() {
    try {
        const { error } = await supabase.auth.signOut()
        if (error) throw error
        return { success: true, message: 'Sesión cerrada' }
    } catch (error) {
        console.error('Logout error:', error)
        return { success: false, message: 'Error al cerrar sesión' }
    }
}

// Usuario actual
async function getCurrentUser() {
    try {
        const { data: { user }, error } = await supabase.auth.getUser()
        if (error) throw error
        if (!user) return { user: null }

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

// Perfil de usuario
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

// Verificar autenticación
async function isAuthenticated() {
    const { data: { session } } = await supabase.auth.getSession()
    return !!session
}

// Reset de contraseña
async function requestPasswordReset(email) {
    try {
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: 'https://hackprevent.es/reset-password'
        })

        if (error) throw error
        return { success: true, message: 'Email de recuperación enviado' }
    } catch (error) {
        console.error('Password reset error:', error)
        return { success: false, message: 'Error al enviar email' }
    }
}

// Cambiar contraseña
async function updatePassword(newPassword) {
    try {
        const { error } = await supabase.auth.updateUser({
            password: newPassword
        })

        if (error) throw error
        return { success: true, message: 'Contraseña actualizada' }
    } catch (error) {
        console.error('Update password error:', error)
        return { success: false, message: 'Error al cambiar contraseña' }
    }
}

// Actualizar perfil
async function updateProfile(userId, data) {
    try {
        const { error } = await supabase
            .from('profiles')
            .update(data)
            .eq('id', userId)

        if (error) throw error
        return { success: true, message: 'Perfil actualizado' }
    } catch (error) {
        console.error('Update profile error:', error)
        return { success: false, message: 'Error al actualizar perfil' }
    }
}

    } catch (error) {
    } catch (error) {
        console.error('Update password error:', error)
        return { success: false, message: 'Error al cambiar contraseña' }
    }
}

// Exportar globalmente
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
    validatePassword
}

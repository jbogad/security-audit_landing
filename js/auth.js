// Supabase Auth Module
console.log('Loading auth.js');

const SUPABASE_URL = 'https://sdudrliwounfknjiwsgb.supabase.co'\;
const SUPABASE_ANON_KEY = 'sb_publishable_QKSOaxQE05LKoSpraT4seg_aFvDBLLO';
let sb = null;

async function getClient() {
    if (sb) return sb;
    for (let i = 0; i < 50; i++) {
        if (window.supabase) {
            sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
            console.log('✓ Supabase client ready');
            return sb;
        }
        await new Promise(r => setTimeout(r, 100));
    }
    throw new Error('Supabase SDK not loaded');
}

async function loginUser(email, password) {
    try {
        const client = await getClient();
        const { data, error } = await client.auth.signInWithPassword({ email, password });
        if (error) return { success: false, message: 'Credenciales incorrectas' };
        localStorage.setItem('supabase_session', JSON.stringify(data.session));
        return { success: true, message: '¡Bienvenido!' };
    } catch (e) {
        return { success: false, message: e.message };
    }
}

async function registerUser(username, email, password, confirmPassword) {
    try {
        if (password !== confirmPassword) return { success: false, message: 'Las contraseñas no coinciden' };
        const client = await getClient();
        const { data, error } = await client.auth.signUp({ email, password, options: { data: { username } } });
        if (error) return { success: false, message: error.message };
        return { success: true, message: '¡Cuenta creada!' };
    } catch (e) {
        return { success: false, message: e.message };
    }
}

async function logoutUser() {
    try {
        const client = await getClient();
        await client.auth.signOut();
        localStorage.removeItem('supabase_session');
        return { success: true };
    } catch (e) {
        return { success: false, message: e.message };
    }
}

async function requestPasswordReset(email) {
    try {
        const client = await getClient();
        const { error } = await client.auth.resetPasswordForEmail(email);
        if (error) return { success: false, message: error.message };
        return { success: true, message: 'Email enviado' };
    } catch (e) {
        return { success: false, message: e.message };
    }
}

async function getCurrentUser() {
    try {
        const client = await getClient();
        const { data: { user } } = await client.auth.getUser();
        return { success: true, user };
    } catch (e) {
        return { success: false, user: null };
    }
}

async function getUserProfile(userId) {
    try {
        const client = await getClient();
        const { data } = await client.from('profiles').select('*').eq('id', userId).single();
        return { success: true, profile: data };
    } catch (e) {
        return { success: false, profile: null };
    }
}

// Export
window.supabaseAuth = { loginUser, registerUser, logoutUser, getCurrentUser, requestPasswordReset, getUserProfile };
console.log('✓ Auth module ready');

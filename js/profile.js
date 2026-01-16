// ============================================
// PROFILE PAGE
// ============================================

let currentUser = null;
let currentProfile = null;

window.addEventListener('DOMContentLoaded', async () => {
    await checkAuthentication();
    await loadUserProfile();
});

async function checkAuthentication() {
    const { user } = await window.supabaseAuth.getCurrentUser();
    if (!user) {
        window.location.href = '/';
        return;
    }
    currentUser = user;
}

// ============================================
// LOAD USER PROFILE
// ============================================
async function loadUserProfile() {
    if (!currentUser) return;
    
    try {
        // Get full profile data
async function loadUserProfile() {
    if (!currentUser) return;
    
    try {
        const { profile } = await window.supabaseAuth.getUserProfile(currentUser.id);
        
        if (profile) {
            currentProfile = profile;
            
            document.getElementById('usernameDisplay').textContent = profile.users.username;
            document.getElementById('emailDisplay').textContent = profile.users.email;
            
            const memberDate = new Date(profile.users.created_at);
            document.getElementById('memberSince').textContent = memberDate.toLocaleDateString('es-ES');
            
            document.getElementById('labsCompleted').textContent = profile.labs_completed || 0;
            document.getElementById('userPoints').textContent = profile.points || 0;
            document.getElementById('userLevel').textContent = profile.level || 1;
            
            const avatarDisplay = document.getElementById('avatarDisplay');
            if (profile.avatar_url) {
                avatarDisplay.innerHTML = `<img src="${profile.avatar_url}" alt="Avatar" class="avatar">`;
            } else {
                const firstLetter = profile.users.username.charAt(0).toUpperCase();
                avatarDisplay.innerHTML = firstLetter;
            }
            
            document.getElementById('fullName').value = profile.full_name || '';
            document.getElementById('avatarUrl').value = profile.avatar_url || '';
            document.getElementById('bio').value = profile.bio || '';
            document.getElementById('website').value = profile.website || '';
            document.getElementById('githubUrl').value = profile.github_url || '';
            document.getElementById('twitterUrl').value = profile.twitter_url || '';
            document.getElementById('linkedinUrl').value = profile.linkedin_url || '';
        }
    } catch (error) {
        console.error('Error loading profile:', error);
        showMessage('error', 'Error al cargar el perfil');
    }
}

document.getElementById('personalInfoForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const fullName = document.getElementById('fullName').value;
    const avatarUrl = document.getElementById('avatarUrl').value;
    const bio = document.getElementById('bio').value;
    const website = document.getElementById('website').value;
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    
    try {
        const result = await window.supabaseAuth.updateProfile(currentUser.id, {
            full_name: fullName,
            avatar_url: avatarUrl,
            bio: bio,
            website: website
        });
        
        if (result.success) {
            showMessage('success', 'Perfil actualizado');
            await loadUserProfile();
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        showMessage('error', 'Error al actualizar el perfil');
    } finally {
        submitBtn.disabled = false;
    }
});

document.getElementById('socialLinksForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const githubUrl = document.getElementById('githubUrl').value;
    const twitterUrl = document.getElementById('twitterUrl').value;
    const linkedinUrl = document.getElementById('linkedinUrl').value;
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    
    try {
        const result = await window.supabaseAuth.updateProfile(currentUser.id, {
            github_url: githubUrl,
            twitter_url: twitterUrl,
            linkedin_url: linkedinUrl
        });
        
        if (result.success) {
            showMessage('success', 'Enlaces sociales actualizados');
            await loadUserProfile();
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Error updating social links:', error);
        showMessage('error', 'Error al actualizar enlaces');
    } finally {
        submitBtn.disabled = false;
    }
});

document.getElementById('changePasswordForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    if (newPassword !== confirmPassword) {
        showMessage('error', 'Las contraseñas no coinciden');
        return;
    }
    
    const validation = window.supabaseAuth.validatePassword(newPassword);
    if (!validation.isValid) {
        showMessage('error', 'Contraseña muy corta');
        return;
    }
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    
    try {
        const result = await window.supabaseAuth.updatePassword(newPassword);
        
        if (result.success) {
            showMessage('success', 'Contraseña actualizada');
            document.getElementById('newPassword').value = '';
            document.getElementById('confirmPassword').value = '';
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Error changing password:', error);
        showMessage('error', 'Error al cambiar contraseña');
    } finally {
        submitBtn.disabled = false;
    }
});

async function handleLogout() {
    if (confirm('¿Cerrar sesión?')) {
        const result = await window.supabaseAuth.logoutUser();
        if (result.success) {
            window.location.href = '/';
        }
    }
}

function showMessage(type, message) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message-toast ${type}`;
    messageDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: rgba(10, 14, 39, 0.95);
        border-radius: 8px;
        z-index: 10000;
        border-left: 4px solid ${type === 'success' ? '#00ff9d' : '#ff4757'};
        color: ${type === 'success' ? '#00ff9d' : '#ff4757'};
    `;
    
    messageDiv.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
        ${message}
    `;
    
    document.body.appendChild(messageDiv);
    setTimeout(() => messageDiv.remove(), 3000);
}

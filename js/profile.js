// ============================================
// PROFILE PAGE - USER PROFILE MANAGEMENT
// ============================================

let currentUser = null;
let currentProfile = null;

// ============================================
// CHECK AUTH ON LOAD
// ============================================
window.addEventListener('DOMContentLoaded', async () => {
    await checkAuthentication();
    await loadUserProfile();
});

// ============================================
// CHECK AUTHENTICATION
// ============================================
async function checkAuthentication() {
    const { user } = await window.supabaseAuth.getCurrentUser();
    
    if (!user) {
        // Redirect to home if not authenticated
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
        const { profile } = await window.supabaseAuth.getUserProfile(currentUser.id);
        
        if (profile) {
            currentProfile = profile;
            
            // Update header info
            document.getElementById('usernameDisplay').textContent = profile.users.username;
            document.getElementById('emailDisplay').textContent = profile.users.email;
            
            // Format member since date
            const memberDate = new Date(profile.users.created_at);
            document.getElementById('memberSince').textContent = memberDate.toLocaleDateString('es-ES', { 
                month: 'long', 
                year: 'numeric' 
            });
            
            // Update stats
            document.getElementById('labsCompleted').textContent = profile.labs_completed || 0;
            document.getElementById('userPoints').textContent = profile.points || 0;
            document.getElementById('userLevel').textContent = profile.level || 1;
            
            // Update avatar
            if (profile.avatar_url) {
                const avatarDisplay = document.getElementById('avatarDisplay');
                avatarDisplay.innerHTML = `<img src="${profile.avatar_url}" alt="Avatar" class="avatar">`;
            } else {
                // Show first letter of username
                const firstLetter = profile.users.username.charAt(0).toUpperCase();
                document.getElementById('avatarDisplay').innerHTML = firstLetter;
            }
            
            // Fill form fields
            document.getElementById('fullName').value = profile.full_name || '';
            document.getElementById('avatarUrl').value = profile.avatar_url || '';
            document.getElementById('bio').value = profile.bio || '';
            document.getElementById('website').value = profile.website || '';
            
            // Fill social links
            document.getElementById('githubUrl').value = profile.github_url || '';
            document.getElementById('twitterUrl').value = profile.twitter_url || '';
            document.getElementById('linkedinUrl').value = profile.linkedin_url || '';
        }
    } catch (error) {
        console.error('Error loading profile:', error);
        showMessage('error', 'Error al cargar el perfil');
    }
}

// ============================================
// UPDATE PERSONAL INFO
// ============================================
document.getElementById('personalInfoForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const fullName = document.getElementById('fullName').value;
    const avatarUrl = document.getElementById('avatarUrl').value;
    const bio = document.getElementById('bio').value;
    const website = document.getElementById('website').value;
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Guardando...';
    
    try {
        const result = await window.supabaseAuth.updateProfile(currentUser.id, {
            full_name: fullName,
            avatar_url: avatarUrl,
            bio: bio,
            website: website
        });
        
        if (result.success) {
            showMessage('success', '✅ Perfil actualizado correctamente');
            await loadUserProfile(); // Reload to show changes
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        showMessage('error', 'Error al actualizar el perfil');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-save"></i> Guardar Cambios';
    }
});

// ============================================
// UPDATE SOCIAL LINKS
// ============================================
document.getElementById('socialLinksForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const githubUrl = document.getElementById('githubUrl').value;
    const twitterUrl = document.getElementById('twitterUrl').value;
    const linkedinUrl = document.getElementById('linkedinUrl').value;
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Guardando...';
    
    try {
        const result = await window.supabaseAuth.updateProfile(currentUser.id, {
            github_url: githubUrl,
            twitter_url: twitterUrl,
            linkedin_url: linkedinUrl
        });
        
        if (result.success) {
            showMessage('success', '✅ Enlaces sociales actualizados');
            await loadUserProfile();
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Error updating social links:', error);
        showMessage('error', 'Error al actualizar enlaces');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-save"></i> Guardar Enlaces';
    }
});

// ============================================
// CHANGE PASSWORD
// ============================================
document.getElementById('changePasswordForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    // Validate passwords match
    if (newPassword !== confirmPassword) {
        showMessage('error', 'Las contraseñas no coinciden');
        return;
    }
    
    // Validate password strength
    const validation = window.supabaseAuth.validatePassword(newPassword);
    if (!validation.isValid) {
        showMessage('error', 'Contraseña insegura:\n• ' + validation.errors.join('\n• '));
        return;
    }
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cambiando...';
    
    try {
        const result = await window.supabaseAuth.updatePassword(newPassword);
        
        if (result.success) {
            showMessage('success', '✅ Contraseña actualizada correctamente');
            document.getElementById('newPassword').value = '';
            document.getElementById('confirmPassword').value = '';
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Error changing password:', error);
        showMessage('error', 'Error al cambiar la contraseña');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-shield-alt"></i> Cambiar Contraseña';
    }
});

// ============================================
// LOGOUT FUNCTION
// ============================================
async function handleLogout() {
    const confirmLogout = confirm('¿Estás seguro de que quieres cerrar sesión?');
    
    if (confirmLogout) {
        const result = await window.supabaseAuth.logoutUser();
        
        if (result.success) {
            window.location.href = '/';
        }
    }
}

// ============================================
// SHOW MESSAGE TOAST
// ============================================
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
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        z-index: 10000;
        opacity: 0;
        transform: translateX(400px);
        transition: all 0.3s ease;
        max-width: 350px;
        border-left: 4px solid ${type === 'success' ? '#00ff9d' : '#ff4757'};
        color: ${type === 'success' ? '#00ff9d' : '#ff4757'};
    `;
    
    messageDiv.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
        ${message}
    `;
    
    document.body.appendChild(messageDiv);
    
    setTimeout(() => {
        messageDiv.style.opacity = '1';
        messageDiv.style.transform = 'translateX(0)';
    }, 100);
    
    setTimeout(() => {
        messageDiv.style.opacity = '0';
        messageDiv.style.transform = 'translateX(400px)';
        setTimeout(() => messageDiv.remove(), 300);
    }, 3000);
}

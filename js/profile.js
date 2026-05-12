// ============================================
// PROFILE PAGE SCRIPT
// ============================================

let currentUser = null;
let currentProfile = null;

// ============================================
// PAGE INITIALIZATION
// ============================================

window.addEventListener('DOMContentLoaded', async () => {
    await checkAuthentication();
    await loadUserProfile();
});

// ============================================
// AUTHENTICATION CHECK
// ============================================

async function checkAuthentication() {
    try {
        // Esperar a que window.supabaseAuth esté disponible
        for (let i = 0; i < 50; i++) {
            if (window.supabaseAuth && typeof window.supabaseAuth.getCurrentUser === 'function') {
                break;
            }
            await new Promise(r => setTimeout(r, 50));
        }
        
        const { success, user } = await window.supabaseAuth.getCurrentUser();
        
        if (!success || !user) {
            window.location.href = '/';
            return;
        }
        
        currentUser = user;
    } catch (error) {
        console.error('Auth check error:', error);
        window.location.href = '/';
    }
}

// ============================================
// LOAD USER PROFILE
// ============================================

async function loadUserProfile() {
    if (!currentUser) {
        console.log('No current user');
        return;
    }
    
    try {
        const { success, profile } = await window.supabaseAuth.getUserProfile(currentUser.id);
        
        if (success && profile) {
            currentProfile = profile;
            console.log('Profile loaded:', profile);
            
            // Update display info
            if (document.getElementById('usernameDisplay')) {
                document.getElementById('usernameDisplay').textContent = currentUser.email;
            }
            if (document.getElementById('emailDisplay')) {
                document.getElementById('emailDisplay').textContent = currentUser.email;
            }
            
            // Update avatar
            const avatarDisplay = document.getElementById('avatarDisplay');
            if (avatarDisplay) {
                if (profile.avatar_url) {
                    avatarDisplay.innerHTML = `<img src="${profile.avatar_url}" alt="Avatar" class="avatar">`;
                } else {
                    const firstLetter = currentUser.email.charAt(0).toUpperCase();
                    avatarDisplay.innerHTML = firstLetter;
                }
            }
            
            // Populate form fields - asegurarse de que existan
            const fullNameField = document.getElementById('fullName');
            if (fullNameField) {
                fullNameField.value = profile.full_name || '';
                console.log('Set fullName to:', profile.full_name);
            }
            
            const avatarUrlField = document.getElementById('avatarUrl');
            if (avatarUrlField) {
                avatarUrlField.value = profile.avatar_url || '';
            }
            
            const bioField = document.getElementById('bio');
            if (bioField) {
                bioField.value = profile.bio || '';
                console.log('Set bio to:', profile.bio);
            }
            
            const websiteField = document.getElementById('website');
            if (websiteField) {
                websiteField.value = profile.website || '';
            }
            
            const githubUrlField = document.getElementById('githubUrl');
            if (githubUrlField) {
                githubUrlField.value = profile.github_url || '';
            }
            
            const twitterUrlField = document.getElementById('twitterUrl');
            if (twitterUrlField) {
                twitterUrlField.value = profile.twitter_url || '';
            }
            
            const linkedinUrlField = document.getElementById('linkedinUrl');
            if (linkedinUrlField) {
                linkedinUrlField.value = profile.linkedin_url || '';
            }
        } else {
            console.log('Failed to load profile or profile is null');
        }
    } catch (error) {
        console.error('Error loading profile:', error);
        showMessage('error', 'Error al cargar el perfil');
    }
}

// ============================================
// FORM HANDLERS
// ============================================

// Personal Info Form
document.addEventListener('DOMContentLoaded', () => {
    const personalForm = document.getElementById('personalInfoForm');
    if (personalForm) {
        personalForm.addEventListener('submit', handlePersonalInfoSubmit);
    }
    
    const socialForm = document.getElementById('socialLinksForm');
    if (socialForm) {
        socialForm.addEventListener('submit', handleSocialLinksSubmit);
    }
});

async function handlePersonalInfoSubmit(e) {
    e.preventDefault();
    
    if (!currentUser) return;
    
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
            showMessage('success', result.message);
            await loadUserProfile();
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        showMessage('error', 'Error al actualizar el perfil');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-save"></i> Guardar';
    }
}

async function handleSocialLinksSubmit(e) {
    e.preventDefault();
    
    if (!currentUser) return;
    
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
            showMessage('success', result.message);
            await loadUserProfile();
        } else {
            showMessage('error', result.message);
        }
    } catch (error) {
        console.error('Error updating social links:', error);
        showMessage('error', 'Error al actualizar enlaces');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-save"></i> Guardar';
    }
}

// ============================================
// CHANGE PASSWORD HANDLER
// ============================================

async function handleChangePassword(e) {
    e.preventDefault();
    
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cambiando...';
    
    try {
        const result = await window.supabaseAuth.changePassword(newPassword, confirmPassword);
        
        if (result.success) {
            showMessage('success', result.message);
            // Limpiar formulario
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
        submitBtn.innerHTML = '<i class="fas fa-key"></i> Cambiar Contraseña';
    }
}

// ============================================
// LOGOUT HANDLER
// ============================================

window.handleLogout = function() {
    if (!window.supabaseAuth || !window.supabaseAuth.logoutUser) {
        console.error('supabaseAuth not available');
        return;
    }
    
    window.supabaseAuth.logoutUser().then(result => {
        if (result.success) {
            showMessage('success', 'Sesión cerrada');
            setTimeout(() => {
                window.location.href = '/';
            }, 1000);
        } else {
            showMessage('error', result.message || 'Error al cerrar sesión');
        }
    }).catch(error => {
        console.error('Logout error:', error);
        showMessage('error', 'Error al cerrar sesión');
    });
};

// Agregar event listener al formulario de cambio de contraseña
document.addEventListener('DOMContentLoaded', () => {
    const changePasswordForm = document.getElementById('changePasswordForm');
    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', handleChangePassword);
    }
});

// ============================================
// MESSAGE DISPLAY
// ============================================

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
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
    if (!currentUser) return;
    
    try {
        const { success, profile } = await window.supabaseAuth.getUserProfile(currentUser.id);
        
        if (success && profile) {
            currentProfile = profile;
            
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
            
            // Populate form fields
            if (document.getElementById('fullName')) {
                document.getElementById('fullName').value = profile.full_name || '';
            }
            if (document.getElementById('avatarUrl')) {
                document.getElementById('avatarUrl').value = profile.avatar_url || '';
            }
            if (document.getElementById('bio')) {
                document.getElementById('bio').value = profile.bio || '';
            }
            if (document.getElementById('website')) {
                document.getElementById('website').value = profile.website || '';
            }
            if (document.getElementById('githubUrl')) {
                document.getElementById('githubUrl').value = profile.github_url || '';
            }
            if (document.getElementById('twitterUrl')) {
                document.getElementById('twitterUrl').value = profile.twitter_url || '';
            }
            if (document.getElementById('linkedinUrl')) {
                document.getElementById('linkedinUrl').value = profile.linkedin_url || '';
            }
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
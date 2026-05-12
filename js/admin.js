// ============================================
// ADMIN DASHBOARD SCRIPT
// ============================================

window.addEventListener('DOMContentLoaded', async () => {
    // 1. Verificar si el usuario actual es admin
    const { success, user } = await window.supabaseAuth.getCurrentUser();
    if (!success || !user) {
        window.location.href = '/';
        return;
    }

    const { profile } = await window.supabaseAuth.getUserProfile(user.id);
    if (!profile || profile.role !== 'admin') {
        alert('Acceso denegado. No eres administrador.');
        window.location.href = '/';
        return;
    }

    // 2. Cargar todos los usuarios (requeriría una función en auth.js que lea todos los perfiles)
    loadAllUsers();
});

async function loadAllUsers() {
    const tbody = document.getElementById('users-tbody');
    try {
        const client = await window.supabaseAuth.getClient();
        // Cargar profiles. OJO: Requiere políticas de RLS en Supabase que permitan a un admin leer toda la tabla 'profiles'.
        const { data: profiles, error } = await client.from('profiles').select('*').order('xp', { ascending: false });

        if (error) throw error;

        tbody.innerHTML = '';
        if (!profiles || profiles.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4">No hay usuarios registrados.</td></tr>';
            return;
        }

        profiles.forEach(p => {
            // Suponemos que used_codes puede estar en DB o vacío
            let codes = 'Ninguno';
            if (p.used_codes) {
                 if (Array.isArray(p.used_codes)) {
                     codes = p.used_codes.join(', ');
                 } else {
                     codes = JSON.stringify(p.used_codes);
                 }
            }
            const xp = p.xp || 0;
            const name = p.full_name || p.username || p.id;

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${name}</strong><br><small style="color:#888">${p.id}</small></td>
                <td><i class="fas fa-star" style="color:#ffeb3b"></i> <span id="xp-${p.id}">${xp}</span></td>
                <td style="font-family: monospace; font-size: 0.9em; display:block; max-width: 200px; overflow-x: auto;">${codes}</td>
                <td>
                    <button class="btn-action add" onclick="modifyXP('${p.id}', 50)">+50</button>
                    <button class="btn-action sub" onclick="modifyXP('${p.id}', -50)">-50</button>
                    <button class="btn-action" onclick="modifyXP('${p.id}', prompt('¿Cuánto XP sumar/restar? (ej. 100 o -100)'))">Ajuste Manual</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

    } catch (e) {
        console.error(e);
        tbody.innerHTML = `<tr><td colspan="4" style="color:red;">Error cargando usuarios: ${e.message}</td></tr>`;
    }
}

async function modifyXP(userId, amountStr) {
    if (!amountStr) return;
    const amount = parseInt(amountStr);
    if (isNaN(amount)) return;

    try {
        const client = await window.supabaseAuth.getClient();
        
        // Obtener XP actual
        const { data: currentProfile } = await client.from('profiles').select('xp').eq('id', userId).single();
        const currentXp = currentProfile?.xp || 0;
        const newXp = Math.max(0, currentXp + amount); // No bajar de 0

        // Actualizar
        const { error } = await client.from('profiles').update({ xp: newXp }).eq('id', userId);
        if (error) throw error;

        // Visual
        document.getElementById(`xp-${userId}`).innerText = newXp;
        
        // Notificación simplificada
        alert(`Éxito. Nuevo XP: ${newXp}`);
        
    } catch (e) {
        alert('Error al modificar XP: ' + e.message);
    }
}
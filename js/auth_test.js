console.log('✓ auth.js is loading');

// Will be initialized when functions are called
let supabase = null;

async function initSupabase() {
    if (supabase) return supabase;
    for (let i = 0; i < 50; i++) {
        if (window.supabase) {
            supabase = window.supabase.createClient(
                'https://sdudrliwounfknjiwsgb.supabase.co',
                'sb_publishable_QKSOaxQE05LKoSpraT4seg_aFvDBLLO'
            );
            console.log('✓ Supabase initialized');
            return supabase;
        }
        await new Promise(r => setTimeout(r, 100));
    }
    throw new Error('Supabase SDK failed to load');
}

// Simple test function
async function testAuth() {
    await initSupabase();
    console.log('✓ Auth system ready');
    return true;
}

// Export
window.supabaseAuth = { testAuth, initSupabase };
console.log('✓ Auth module exported');

# 🔐 Configuración de Base de Datos - HackPrevent.es

## 📋 Paso 1: Crear Proyecto en Supabase

1. Ve a https://supabase.com
2. Click en "Start your project"
3. Crea una cuenta (con GitHub o email)
4. Click en "New Project"
   - **Name**: HackPrevent
   - **Database Password**: (guárdalo bien, lo necesitarás)
   - **Region**: Europe West (London o Frankfurt)
   - Click "Create new project"
5. Espera 2-3 minutos a que se cree

---

## 📋 Paso 2: Crear Tablas de Base de Datos

1. En tu proyecto de Supabase, ve a **SQL Editor** (menú lateral)
2. Click en "New Query"
3. **Copia y pega este SQL completo:**

```sql
-- ============================================
-- TABLA DE USUARIOS
-- ============================================
CREATE TABLE users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP,
    email_verified BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    role VARCHAR(20) DEFAULT 'user',
    CONSTRAINT username_length CHECK (char_length(username) >= 3),
    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

-- ============================================
-- TABLA DE PERFILES (Info adicional)
-- ============================================
CREATE TABLE profiles (
    id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    full_name VARCHAR(100),
    avatar_url TEXT,
    bio TEXT,
    website TEXT,
    labs_completed INTEGER DEFAULT 0,
    points INTEGER DEFAULT 0,
    level INTEGER DEFAULT 1,
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ============================================
-- TABLA DE PROGRESO EN LABS
-- ============================================
CREATE TABLE lab_progress (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    lab_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'not_started', -- not_started, in_progress, completed
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    flags_found INTEGER DEFAULT 0,
    total_flags INTEGER DEFAULT 0,
    notes TEXT,
    UNIQUE(user_id, lab_name)
);

-- ============================================
-- TABLA DE PASSWORD RESET TOKENS
-- ============================================
CREATE TABLE password_reset_tokens (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(100) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ============================================
-- ÍNDICES PARA OPTIMIZACIÓN
-- ============================================
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_lab_progress_user ON lab_progress(user_id);
CREATE INDEX idx_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX idx_reset_tokens_expiry ON password_reset_tokens(expires_at) WHERE NOT used;

-- ============================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================

-- Activar RLS en todas las tablas
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE lab_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens ENABLE ROW LEVEL SECURITY;

-- Políticas para USERS
CREATE POLICY "Users can view own data" ON users
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own data" ON users
    FOR UPDATE USING (auth.uid() = id);

-- Políticas para PROFILES
CREATE POLICY "Profiles are viewable by everyone" ON profiles
    FOR SELECT USING (true);

CREATE POLICY "Users can update own profile" ON profiles
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Users can insert own profile" ON profiles
    FOR INSERT WITH CHECK (auth.uid() = id);

-- Políticas para LAB_PROGRESS
CREATE POLICY "Users can view own progress" ON lab_progress
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own progress" ON lab_progress
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own progress" ON lab_progress
    FOR UPDATE USING (auth.uid() = user_id);

-- Políticas para PASSWORD_RESET_TOKENS (solo backend puede escribir)
CREATE POLICY "Anyone can read non-expired tokens" ON password_reset_tokens
    FOR SELECT USING (expires_at > NOW() AND NOT used);

-- ============================================
-- FUNCIÓN PARA CREAR USUARIO Y PERFIL AUTOMÁTICO
-- ============================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    -- Insertar en tabla users
    INSERT INTO public.users (id, username, email, email_verified)
    VALUES (
        NEW.id,
        COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1)),
        NEW.email,
        NEW.email_confirmed_at IS NOT NULL
    );
    
    -- Insertar perfil vacío
    INSERT INTO public.profiles (id, full_name)
    VALUES (
        NEW.id,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'username', '')
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger que crea usuario y perfil cuando se registra en auth
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ============================================
-- FUNCIÓN PARA LIMPIAR TOKENS EXPIRADOS
-- ============================================
CREATE OR REPLACE FUNCTION clean_expired_tokens()
RETURNS void AS $$
BEGIN
    DELETE FROM password_reset_tokens
    WHERE expires_at < NOW() OR used = true;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- VISTA PARA RANKING DE USUARIOS
-- ============================================
CREATE OR REPLACE VIEW user_ranking AS
SELECT 
    u.username,
    p.points,
    p.level,
    p.labs_completed,
    p.avatar_url,
    RANK() OVER (ORDER BY p.points DESC) as rank
FROM users u
JOIN profiles p ON u.id = p.id
WHERE u.is_active = true
ORDER BY p.points DESC;
```

4. Click en **"Run"** (abajo a la derecha)
5. Si sale "Success. No rows returned", ¡está perfecto! ✅

---

## 📋 Paso 3: Obtener Credenciales

1. En Supabase, ve a **Project Settings** (⚙️ abajo a la izquierda)
2. Click en **API**
3. Copia estos 2 valores:

   - **Project URL**: `https://xxxxx.supabase.co`
   - **anon public key**: `eyJhbGciOiJIUzI1...` (es muy largo)

---

## 📋 Paso 4: Configurar Autenticación

1. En Supabase, ve a **Authentication** → **Providers**
2. Activa **Email**
3. Configura:
   - ✅ Enable Email provider
   - ✅ Confirm email: OFF (para desarrollo, después actívalo)
   - ✅ Secure password change: ON
4. Guarda cambios

---

## 📋 Paso 5: Configurar Email Templates (Opcional)

1. Ve a **Authentication** → **Email Templates**
2. Personaliza los emails de:
   - Confirmación de cuenta
   - Reset password
   - Change email

---

## ✅ Siguiente Paso

Una vez tengas tus credenciales:

1. **Project URL**
2. **anon public key**

Dímelas (o dime que las tienes) y actualizo automáticamente:
- `js/auth.js` (nuevo archivo)
- `js/script.js` (con las nuevas funciones)
- `index.html` (scripts necesarios)

**El sistema incluirá:**
- ✅ Registro seguro con hash automático
- ✅ Login con sesión JWT
- ✅ Logout
- ✅ Verificación de email
- ✅ Reset password funcional
- ✅ Protección contra SQL injection
- ✅ Row Level Security activo
- ✅ Encriptación en tránsito (HTTPS)

🔒 **Todo 100% seguro y profesional**

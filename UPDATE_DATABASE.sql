-- ============================================
-- ACTUALIZACIÓN DE BASE DE DATOS
-- Ejecuta esto en Supabase SQL Editor
-- ============================================

-- Agregar campos de redes sociales a profiles
ALTER TABLE profiles 
ADD COLUMN IF NOT EXISTS github_url TEXT,
ADD COLUMN IF NOT EXISTS twitter_url TEXT,
ADD COLUMN IF NOT EXISTS linkedin_url TEXT;

-- Crear función para actualizar timestamp automáticamente
CREATE OR REPLACE FUNCTION update_profile_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Crear trigger para auto-actualizar updated_at
DROP TRIGGER IF EXISTS trigger_update_profile_timestamp ON profiles;
CREATE TRIGGER trigger_update_profile_timestamp
    BEFORE UPDATE ON profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_profile_timestamp();

-- Verificar que todo esté correcto
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'profiles'
ORDER BY ordinal_position;

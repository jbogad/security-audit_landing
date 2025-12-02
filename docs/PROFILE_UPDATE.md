# Actualización de Base de Datos - Perfil Editable

Este documento describe las actualizaciones necesarias en la base de datos para soportar perfiles editables.

## Campos Adicionales en la Tabla `profiles`

Ejecuta el siguiente SQL en Supabase SQL Editor:

```sql
-- Agregar campos adicionales a la tabla profiles
ALTER TABLE profiles 
ADD COLUMN IF NOT EXISTS avatar_url TEXT,
ADD COLUMN IF NOT EXISTS bio TEXT,
ADD COLUMN IF NOT EXISTS website TEXT,
ADD COLUMN IF NOT EXISTS github_url TEXT,
ADD COLUMN IF NOT EXISTS twitter_url TEXT,
ADD COLUMN IF NOT EXISTS linkedin_url TEXT;

-- Crear índice para búsquedas por username (si no existe)
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Actualizar timestamp en cada modificación del perfil
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
```

## Verificación

Para verificar que los cambios se aplicaron correctamente:

```sql
-- Ver estructura de la tabla profiles
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'profiles';
```

## Notas de Seguridad

- Los campos `avatar_url`, `bio`, `website` son opcionales (NULL permitido)
- Las URLs deben ser validadas en el frontend antes de guardar
- Se recomienda activar RLS (Row Level Security) para producción:

```sql
-- Política RLS para que usuarios solo actualicen su propio perfil
CREATE POLICY "Users can update own profile"
ON profiles FOR UPDATE
USING (auth.uid() = id);

-- Política RLS para que usuarios lean cualquier perfil (público)
CREATE POLICY "Profiles are publicly readable"
ON profiles FOR SELECT
USING (true);
```

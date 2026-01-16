# HackPrevent.es - TFG

Plataforma simplificada de autenticación y perfil de usuario con Supabase.

## Stack

- **Frontend**: HTML5, CSS3, JavaScript vanilla
- **Backend**: Supabase (BaaS)
- **Auth**: Email/Password
- **Database**: PostgreSQL (Supabase)

## Estructura

```
/
├── index.html           # Página principal con login/register
├── profile.html         # Página de perfil del usuario
├── css/
│   ├── layout.css       # Estilos de layout
│   ├── components.css   # Componentes reutilizables
│   └── styles.css       # Estilos adicionales
└── js/
    ├── auth.js          # Funciones de autenticación
    ├── script.js        # Lógica principal
    └── profile.js       # Lógica del perfil
```

## Configuración Supabase

1. Crear proyecto en https://supabase.com
2. Las credenciales están en `js/auth.js`:
   - `SUPABASE_URL`
   - `SUPABASE_ANON_KEY`

## Funcionalidades

✅ Registro de usuarios  
✅ Login con email/contraseña  
✅ Perfil editable  
✅ Cambio de contraseña  
✅ Logout  

## Cómo usar

1. Abrir `index.html` en un navegador
2. Registrarse con email y contraseña
3. Iniciar sesión
4. Editar perfil en `/profile.html`


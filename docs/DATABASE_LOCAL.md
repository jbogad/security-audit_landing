# 🔐 Base de Datos Local - HackPrevent.es

## 📦 Stack Tecnológico

- **Backend**: Node.js + Express
- **Base de Datos**: SQLite (archivo local)
- **Seguridad**: bcrypt (hash passwords) + JWT (sesiones)
- **Validación**: express-validator

---

## 📋 Paso 1: Instalar Node.js

Si no lo tienes instalado:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nodejs npm

# Verificar instalación
node --version
npm --version
```

---

## 📋 Paso 2: Crear Backend

Ejecuta estos comandos en tu terminal:

```bash
cd /home/soc/Documentos/hackprevent
mkdir backend
cd backend
npm init -y
npm install express sqlite3 bcryptjs jsonwebtoken express-validator cors dotenv
```

---

## 📋 Paso 3: Estructura de Archivos

El backend tendrá esta estructura:

```
backend/
├── server.js          # Servidor principal
├── database.js        # Configuración de BD
├── auth.js           # Rutas de autenticación
├── .env              # Variables de entorno (secretos)
├── hackprevent.db    # Base de datos SQLite (se crea automáticamente)
└── package.json      # Dependencias
```

---

## 🔐 Características de Seguridad

✅ **Passwords hasheados** con bcrypt (12 rounds)
✅ **Sesiones JWT** con token seguro
✅ **Validación** de inputs (evita SQL injection)
✅ **CORS** configurado
✅ **Rate limiting** contra ataques de fuerza bruta
✅ **Prepared statements** (protección SQL injection)
✅ **HTTPS ready** (puedes añadir certificado SSL)

---

## 🚀 Cómo Funciona

1. **Frontend** (tu web) hace peticiones a `http://localhost:3000`
2. **Backend** valida, procesa y responde
3. **SQLite** almacena todo en un archivo local cifrado

---

## 📊 Base de Datos Incluye

- **users**: usuarios con passwords hasheados
- **profiles**: perfiles públicos
- **lab_progress**: progreso en laboratorios
- **sessions**: sesiones activas
- **password_resets**: tokens de recuperación

---

## ⚡ Ventajas de SQLite Local

✅ **Sin servidor externo** - todo en tu PC
✅ **Rápido** - acceso directo al disco
✅ **Portable** - un solo archivo `.db`
✅ **Sin costes** - 100% gratis
✅ **Privacidad total** - tus datos no salen de tu máquina
✅ **Fácil backup** - copias el archivo `.db`

---

## 🔄 Migración a Producción

Cuando quieras publicar la web, puedes:
1. Subir el backend a un VPS (DigitalOcean, Hetzner, etc.)
2. Cambiar SQLite por PostgreSQL/MySQL (opcional)
3. Añadir HTTPS con Let's Encrypt

---

## ✅ ¿Listo para crear los archivos?

Dime "sí" y te creo automáticamente:
- `backend/server.js` - Servidor Express
- `backend/database.js` - Esquema de BD con SQLite
- `backend/auth.js` - Sistema de autenticación completo
- `backend/.env` - Configuración segura
- `js/api.js` - Cliente para conectar frontend con backend
- Actualización de `js/script.js` con las funciones de login/registro

Todo listo para funcionar en 2 minutos. 🚀

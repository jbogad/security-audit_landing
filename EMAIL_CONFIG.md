# 📧 Configuración de Email para HackPrevent.es

## Opción 1: EmailJS (Recomendado - GRATIS)

EmailJS permite enviar emails desde JavaScript sin backend.

### Paso 1: Crear cuenta en EmailJS
1. Ve a https://www.emailjs.com/
2. Registrate gratis (200 emails/mes gratis)
3. Verifica tu email

### Paso 2: Configurar servicio de email
1. En el dashboard, ve a **Email Services**
2. Click en **Add New Service**
3. Selecciona tu proveedor (Gmail, Outlook, etc.)
4. Autoriza la conexión
5. Copia el **Service ID**

### Paso 3: Crear template de email
1. Ve a **Email Templates**
2. Click en **Create New Template**
3. Usa este template:

**Template ID**: `password_reset_template`

**Subject**: `🔐 Recuperación de Contraseña - HackPrevent.es`

**Content (HTML)**:
```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', Arial, sans-serif; background: #0a0e27;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background: #0a0e27; padding: 40px 20px;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background: #0f1428; border: 1px solid rgba(0, 255, 157, 0.2); border-radius: 15px; overflow: hidden;">
                    
                    <!-- Header -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #00ff9d 0%, #00cc7a 100%); padding: 30px; text-align: center;">
                            <h1 style="margin: 0; color: #0a0e27; font-size: 32px; font-weight: bold;">
                                🛡️ HackPrevent.es
                            </h1>
                            <p style="margin: 5px 0 0 0; color: #0a0e27; font-size: 14px;">
                                Ethical Hacking & Cyber Defense
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px 30px; color: #e0e0e0;">
                            <h2 style="color: #00ff9d; margin-top: 0;">Recuperación de Contraseña</h2>
                            
                            <p style="font-size: 16px; line-height: 1.6; color: #b0b0b0;">
                                Hola <strong style="color: #ffffff;">{{user_email}}</strong>,
                            </p>
                            
                            <p style="font-size: 16px; line-height: 1.6; color: #b0b0b0;">
                                Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en <strong style="color: #ffffff;">HackPrevent.es</strong>.
                            </p>
                            
                            <p style="font-size: 16px; line-height: 1.6; color: #b0b0b0;">
                                Haz click en el botón de abajo para crear una nueva contraseña:
                            </p>
                            
                            <!-- Button -->
                            <table width="100%" cellpadding="0" cellspacing="0" style="margin: 30px 0;">
                                <tr>
                                    <td align="center">
                                        <a href="{{reset_link}}" style="display: inline-block; background: linear-gradient(135deg, #00ff9d 0%, #00cc7a 100%); color: #0a0e27; padding: 15px 40px; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px;">
                                            🔓 Restablecer Contraseña
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            
                            <p style="font-size: 14px; line-height: 1.6; color: #808080; margin-top: 30px;">
                                O copia y pega este enlace en tu navegador:
                            </p>
                            <p style="font-size: 13px; color: #00ff9d; word-break: break-all; background: rgba(0,255,157,0.1); padding: 10px; border-radius: 5px;">
                                {{reset_link}}
                            </p>
                            
                            <div style="margin-top: 30px; padding: 15px; background: rgba(255,69,0,0.1); border-left: 4px solid #ff4500; border-radius: 5px;">
                                <p style="margin: 0; font-size: 14px; color: #ff6347;">
                                    <strong>⚠️ Importante:</strong> Este enlace expira en <strong>1 hora</strong>.
                                </p>
                            </div>
                            
                            <p style="font-size: 14px; line-height: 1.6; color: #808080; margin-top: 30px;">
                                Si no solicitaste este cambio, puedes ignorar este email. Tu contraseña permanecerá sin cambios.
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="background: rgba(0,0,0,0.3); padding: 20px 30px; text-align: center; border-top: 1px solid rgba(0,255,157,0.2);">
                            <p style="margin: 0; font-size: 13px; color: #808080;">
                                © 2025 HackPrevent.es | Todos los derechos reservados
                            </p>
                            <p style="margin: 10px 0 0 0; font-size: 12px; color: #606060;">
                                Si tienes problemas, contacta a <a href="mailto:soporte@hackprevent.es" style="color: #00ff9d; text-decoration: none;">soporte@hackprevent.es</a>
                            </p>
                        </td>
                    </tr>
                    
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
```

### Paso 4: Integrar EmailJS en tu web

1. Copia tu **Public Key** desde Account > General
2. Añade este script en el `<head>` de tu index.html:

```html
<script type="text/javascript" src="https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js"></script>
<script type="text/javascript">
    (function(){
        emailjs.init("TU_PUBLIC_KEY"); // Reemplaza con tu Public Key
    })();
</script>
```

3. Reemplaza la función `handlePasswordReset` con esta:

```javascript
async function handlePasswordReset(e) {
    e.preventDefault();
    const email = document.getElementById('reset-email').value;
    const messageDiv = document.getElementById('resetMessage');
    const resetBtn = document.getElementById('resetBtn');
    
    resetBtn.disabled = true;
    resetBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enviando...';
    
    try {
        const resetToken = Math.random().toString(36).substring(2, 15);
        const resetLink = `https://hackprevent.es/reset-password?token=${resetToken}`;
        
        // Enviar con EmailJS
        await emailjs.send(
            'TU_SERVICE_ID',  // Service ID de EmailJS
            'password_reset_template',  // Template ID
            {
                user_email: email,
                reset_link: resetLink,
                to_email: email
            }
        );
        
        messageDiv.innerHTML = `
            <div class="success-message">
                <i class="fas fa-check-circle"></i>
                <strong>¡Email enviado!</strong><br>
                Revisa tu bandeja de entrada en <strong>${email}</strong><br>
                <small>(También revisa spam/correo no deseado)</small>
            </div>
        `;
        
        document.getElementById('reset-email').value = '';
        
    } catch (error) {
        console.error('Error:', error);
        messageDiv.innerHTML = `
            <div class="error-message">
                <i class="fas fa-exclamation-circle"></i>
                <strong>Error al enviar el email</strong><br>
                Por favor, inténtalo de nuevo más tarde.
            </div>
        `;
    } finally {
        resetBtn.disabled = false;
        resetBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Enviar Email de Recuperación';
    }
}
```

---

## Opción 2: Formspree (Más simple pero menos personalizado)

Si prefieres usar Formspree (que ya tienes configurado):

1. Crea un nuevo form en https://formspree.io/forms
2. Usa este endpoint en la función `handlePasswordReset`:

```javascript
const response = await fetch('https://formspree.io/f/TU_FORM_ID', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        email: email,
        subject: '🔐 Recuperación de Contraseña - HackPrevent.es',
        message: `Enlace de recuperación: ${resetLink}`
    })
});
```

⚠️ **Nota**: Formspree no soporta HTML personalizado en emails, solo texto plano.

---

## 🎯 Recomendación

**EmailJS** es la mejor opción porque:
- ✅ 200 emails gratis al mes
- ✅ Emails HTML completamente personalizados
- ✅ Sin backend necesario
- ✅ Fácil de configurar (10 minutos)

Una vez configurado, los emails se enviarán automáticamente con el diseño bonito que he creado.

¿Necesitas ayuda para configurarlo?

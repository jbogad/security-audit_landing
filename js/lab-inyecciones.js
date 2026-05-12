// ==========================================
// LABORATORIO: SQLi & XSS (Simulación)
// ==========================================

let currentLevel = 1;

function nextLevel(level) {
    if (level === 2) {
        document.getElementById('level1').style.display = 'none';
        document.getElementById('level2').style.display = 'block';
        currentLevel = 2;
    } else if (level === 3) {
        document.getElementById('level2').style.display = 'none';
        document.getElementById('level3').style.display = 'block';
        currentLevel = 3;
    } else if (level === 'finish') {
        document.getElementById('level3').style.display = 'none';
        document.getElementById('completion-screen').style.display = 'block';
    }
}

// ------------------------------------------
// PRUEBA 1: SQLi Login
// ------------------------------------------
function handleSqlLogin(e) {
    e.preventDefault();
    const user = document.getElementById('sqli-user').value;
    const pass = document.getElementById('sqli-pass').value;
    const resultBox = document.getElementById('sqli-login-result');

    // Detección más tolerante para inyecciones
    const sqliRegex = /'\s*OR|"\s*OR|'\s*=|"\s*=|'\s*--|"\s*--|admin'/i;
    
    if (sqliRegex.test(user) || sqliRegex.test(pass)) {
        // SQL Inyectado exitosamente!
        resultBox.innerHTML = `
            <span class="success-text"><i class="fas fa-exclamation-triangle"></i> ¡Inyección SQL Exitosa! Has superado el primer reto.</span>
            <br>
            <button type="button" class="btn-login" style="margin-top: 15px; width: auto; padding: 0.5rem 1.5rem;" onclick="nextLevel(2)">Siguiente Nivel →</button>
        `;
    } else if (user === 'admin' && pass === '1234') {
        resultBox.innerHTML = '<span class="error-text">Login correcto pero sin inyectar nada... inténtalo vulnerando el SQL.</span>';
    } else {
        resultBox.innerHTML = '<span class="error-text"><i class="fas fa-times-circle"></i> Credenciales incorrectas y no se detectó inyección.</span>';
    }
}

// ------------------------------------------
// PRUEBA 2: SQLi Búsqueda
// ------------------------------------------
const mockDatabase = [
    { id: 1, name: "Sudadera Red Team", price: "25.00€", visible: 1 },
    { id: 2, name: "Taza 'I read your traffic'", price: "12.00€", visible: 1 },
    { id: 3, name: "Pegatinas Null Byte", price: "5.00€", visible: 1 },
    { id: 4, name: "FLAG{SQLi_Data_Exfiltration_Rules}", price: "INVALUABLE", visible: 0 } // Producto oculto
];

function handleSqlSearch(e) {
    e.preventDefault();
    const idInput = document.getElementById('sqli-search').value.trim();
    const resultBox = document.getElementById('sqli-search-result');

    if (!idInput) {
        resultBox.innerHTML = '<em>Escribe un ID para buscar...</em>';
        return;
    }

    // Detección más tolerante
    const orRegex = /OR|1=1|'1'='1'|true/i;
    
    let results = [];
    
    if (orRegex.test(idInput)) {
        // Devuelve todo, simulando que el OR 1=1 anula el resto
        results = mockDatabase;
    } else {
        // Comportamiento normal (solo extrae el ID exacto y visible=1)
        const idNumeric = parseInt(idInput, 10);
        results = mockDatabase.filter(item => item.id === idNumeric && item.visible === 1);
    }

    if (results.length > 0) {
        let html = '<table class="db-table"><tr><th>ID</th><th>Nombre</th><th>Precio</th></tr>';
        results.forEach(r => {
            const rowStyle = r.visible === 0 ? 'style="color: #ff3366; font-weight: bold;"' : '';
            html += `<tr ${rowStyle}><td>${r.id}</td><td>${r.name}</td><td>${r.price}</td></tr>`;
        });
        html += '</table>';
        
        if (results.some(r => r.visible === 0)) {
            // Conseguido
            html += `
                <p class="success-text" style="margin-top: 10px;"><i class="fas fa-exclamation-triangle"></i> ¡Has extraído datos ocultos de la base de datos!</p>
                <button type="button" class="btn-login" style="margin-top: 15px; width: auto; padding: 0.5rem 1.5rem;" onclick="nextLevel(3)">Siguiente Nivel →</button>
            `;
        }
        
        resultBox.innerHTML = html;
    } else {
        resultBox.innerHTML = '<span class="error-text">No se encontraron productos con ese ID.</span>';
    }
}

// ------------------------------------------
// PRUEBA 3: XSS
// ------------------------------------------
function handleXss(e) {
    e.preventDefault();
    const input = document.getElementById('xss-input').value;
    const resultBox = document.getElementById('xss-result');

    if (!input) {
        resultBox.innerHTML = '<em>Invitado</em>';
        return;
    }

    // Interceptar la alerta para detectar si el XSS se ejecutó
    const originalAlert = window.alert;
    let xssExecuted = false;
    
    window.alert = function(msg) {
        xssExecuted = true;
        originalAlert(msg);
        nextLevel('finish');
    };

    resultBox.innerHTML = input;

    // Restaurar el alert despues de dar tiempo a que evalúe y forzar victoria si vemos un vector claro
    setTimeout(() => {
        window.alert = originalAlert;
        if (!xssExecuted) {
            // Si el HTML5 no quiso ejecutar el JS (pasa mucho con innerHTML y <script>) pero el vector era obvio:
            if (input.toLowerCase().includes('<script>') || input.toLowerCase().includes('onerror=')) {
                nextLevel('finish');
            }
        }
    }, 100);
}
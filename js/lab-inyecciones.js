// ==========================================
// LABORATORIO: SQLi & XSS (Simulación)
// ==========================================

// Actualización en tiempo real de los snippets
function updateQuery1() {
    const user = document.getElementById('sqli-user').value;
    const pass = document.getElementById('sqli-pass').value;
    document.getElementById('sqli1-user-query').textContent = user || 'INPUT';
    document.getElementById('sqli1-pass-query').textContent = pass || 'INPUT';
}

function updateQuery2() {
    const id = document.getElementById('sqli-search').value;
    document.getElementById('sqli2-query').textContent = id || 'INPUT';
}

// ------------------------------------------
// PRUEBA 1: SQLi Login
// ------------------------------------------
function handleSqlLogin(e) {
    e.preventDefault();
    const user = document.getElementById('sqli-user').value;
    const pass = document.getElementById('sqli-pass').value;
    const resultBox = document.getElementById('sqli-login-result');

    // Detección muy básica de inyecciones simples tipo bypass: ' OR '1'='1, ' OR 1=1, admin' --
    const sqliRegex = /'\s*OR\s*.*|'\s*--|"\s*OR\s*.*/i;
    
    // Autenticación mock
    if (user === 'admin' && pass === '1234') {
        resultBox.innerHTML = '<span class="success-text"><i class="fas fa-check-circle"></i> Login correcto (uso normal). Has iniciado como admin.</span>';
    } else if (sqliRegex.test(user) || sqliRegex.test(pass)) {
        // SQL Inyectado exitosamente!
        resultBox.innerHTML = '<span class="success-text"><i class="fas fa-exclamation-triangle"></i> ¡Inyección SQL Exitosa! La base de datos evaluó la condición como VERDADERA e inició sesión como el primer usuario de la tabla (Admin).</span>';
    } else {
        resultBox.innerHTML = '<span class="error-text"><i class="fas fa-times-circle"></i> Credenciales incorrectas.</span>';
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

    const orRegex = /\s*OR\s+1=1|\s*OR\s+'1'='1'/i;
    
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
            // Si vemos items no visibles (como el ID 4), remarcarlos!
            const rowStyle = r.visible === 0 ? 'style="color: #ff3366; font-weight: bold;"' : '';
            html += `<tr ${rowStyle}><td>${r.id}</td><td>${r.name}</td><td>${r.price}</td></tr>`;
        });
        html += '</table>';
        
        if (results.some(r => r.visible === 0)) {
            html += '<p class="success-text" style="margin-top: 10px;"><i class="fas fa-exclamation-triangle"></i> ¡Has extraído datos ocultos de la base de datos!</p>';
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

    // Al usar innerHTML tal cual de la entrada del usuario, simulamos la vulnerabilidad XSS
    // Si el usuario introduce <img src="x" onerror="alert(1)">, saltará.
    // Hack preventivo de JS: Al inyectar una etiqueta <script> con innerHTML, el navegador a veces no la ejecuta.
    // Usar <img src=x onerror="..."> es el vector ideal que SIEMPRE funciona.
    
    if (!input) {
        resultBox.innerHTML = '<em>Invitado</em>';
        return;
    }

    resultBox.innerHTML = input;

    // Hint extra si intentan un vector que HTML5 bloquea (etiquetas directas <script>):
    if (input.includes('<script>')) {
        setTimeout(() => {
            if (!document.getElementById('xss-hint')) {
                const hint = document.createElement('div');
                hint.id = 'xss-hint';
                hint.style.color = 'yellow';
                hint.style.fontSize = '0.9em';
                hint.style.marginTop = '10px';
                hint.innerHTML = '<em>Nota: Modern browsers block direct &lt;script&gt; injections via innerHTML. Prueba con atributos de eventos como <code>&lt;img src=x onerror=alert(1)&gt;</code></em>';
                resultBox.parentNode.appendChild(hint);
            }
        }, 500);
    }
}
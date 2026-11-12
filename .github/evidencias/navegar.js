// Recorre la aplicacion en un Chromium con ventana (sobre Xvfb) y toma capturas de la pantalla
// completa con ImageMagick, para que se vea la barra de direcciones y los dialogos del navegador.
// uso: node navegar.js <carpeta-capturas> <api-flujo.sh>
const { chromium } = require('playwright');
const { execSync, spawn } = require('child_process');
const [salida, apiFlujo] = process.argv.slice(2);
const B = 'http://localhost:8080';
const espera = (ms) => new Promise(r => setTimeout(r, ms));
const pantalla = (nombre) => { execSync(`import -window root ${salida}/${nombre}`); console.log('captura', nombre); };

async function paso(nombre, fn) {
  try { await fn(); } catch (e) { console.log('FALLO en', nombre, e.message); }
}

(async () => {
  const navegador = await chromium.launch({ headless: false, args: ['--window-position=0,0', '--window-size=1366,900'] });
  const contexto = await navegador.newContext({ viewport: null, locale: 'es-CO' });
  const p = await contexto.newPage();
  p.on('dialog', d => { console.log('dialogo inesperado:', d.message()); d.dismiss(); });

  const registrar = async (nombre, email, clave) => {
    await p.goto(`${B}/registro`);
    await p.fill('#nombre', nombre); await p.fill('#email', email); await p.fill('#contrasenia', clave);
    await p.click('button[type=submit]'); await p.waitForLoadState();
  };
  const entrar = async (email, clave) => {
    await p.goto(`${B}/login`);
    await p.fill('input[name=username]', email); await p.fill('input[name=password]', clave);
    await p.click('button[type=submit]'); await p.waitForLoadState();
  };
  const salir = async () => { await p.click('text=Cerrar Sesión'); await p.waitForLoadState(); };
  const crearTarea = async (titulo, descripcion) => {
    await p.goto(`${B}/tareas`);
    await p.fill('#titulo', titulo); await p.fill('#descripcion', descripcion);
    await p.click('text=Crear tarea'); await p.waitForLoadState();
  };
  const buscar = async (texto) => {
    await p.goto(`${B}/tareas`); await p.fill('input[name=texto]', texto);
    await p.click('text=Buscar'); await p.waitForLoadState();
  };

  await paso('redireccion al login', async () => {
    await p.goto(`${B}/dashboard`); await espera(800);
    console.log('GET /dashboard sin sesion termina en', p.url());
    pantalla('login.png');
  });
  await paso('registro con payload XSS', async () => {
    await registrar('<script>alert("XSS")</script>', 'xss@universidad.edu', 'clave-xss-123');
    pantalla('registro-exitoso.png');
  });
  await paso('dashboard seguro', async () => {
    await entrar('xss@universidad.edu', 'clave-xss-123'); await espera(800);
    pantalla('dashboard-seguro.png');
    console.log('HTML del saludo:', await p.innerHTML('p:has-text("Bienvenido")'));
    await salir(); await espera(500);
    pantalla('logout-ok.png');
  });
  await paso('tareas de pedro', async () => {
    await registrar('Pedro Rojas', 'pedro@universidad.edu', 'clave-pedro-1');
    await entrar('pedro@universidad.edu', 'clave-pedro-1');
    await crearTarea('Revisar informe de costos', 'Tarea privada de Pedro');
    await salir();
  });
  await paso('tareas y busqueda de laura', async () => {
    await registrar('Laura Gomez', 'laura@universidad.edu', 'clave-laura-1');
    await entrar('laura@universidad.edu', 'clave-laura-1');
    await crearTarea('Preparar informe de laboratorio', 'Capturas y README');
    await crearTarea('Estudiar Spring Security', 'Filtros y sesiones');
    await espera(500); pantalla('tareas-usuario.png');
    await buscar("' OR '1'='1"); await espera(500); pantalla('sql-injection-mitigado.png');
    await buscar('informe'); await espera(500); pantalla('busqueda-normal.png');
  });
  await paso('usuario sin permiso en /admin', async () => {
    await p.goto(`${B}/admin`); await espera(800); pantalla('admin-403.png');
    await p.goto(`${B}/dashboard`); await salir();
  });
  await paso('admin', async () => {
    await entrar('admin@universidad.edu', 'admin123'); await espera(800);
    pantalla('dashboard-admin.png');
    await p.goto(`${B}/admin`); await espera(800); pantalla('admin-panel.png');
    await p.goto(`${B}/dashboard`); await espera(500);
  });
  await paso('convivencia de sesion y JWT', async () => {
    // la ventana del navegador a la derecha y una terminal real a la izquierda ejecutando la API
    const cdp = await contexto.newCDPSession(p);
    const { windowId } = await cdp.send('Browser.getWindowForTarget');
    await cdp.send('Browser.setWindowBounds', { windowId, bounds: { left: 620, top: 0, width: 746, height: 900 } });
    const terminal = spawn('xterm', ['-geometry', '100x58+0+0', '-fa', 'DejaVu Sans Mono', '-fs', '8',
      '-bg', '#0d1117', '-fg', '#c9d1d9', '-T', 'curl contra /api/**',
      '-e', 'bash', '-c', `bash ${apiFlujo}; sleep 120`], { stdio: 'ignore', detached: true });
    await espera(9000);
    await p.reload(); await espera(1200);
    console.log('despues de usar la API, el navegador sigue en', p.url());
    pantalla('coexistencia.png');
    terminal.kill();
    await cdp.send('Browser.setWindowBounds', { windowId, bounds: { left: 0, top: 0, width: 1366, height: 900 } });
  });
  await paso('XSS con th:utext (variante temporal en el puerto 8081)', async () => {
    const q = await contexto.newPage();
    q.on('dialog', async d => {
      console.log('dialogo de la pagina:', d.type(), d.message());
      await espera(1500);
      pantalla('xss-utext.png');
      await d.accept();
    });
    await q.goto('http://localhost:8081/login');
    await q.fill('input[name=username]', 'xss@universidad.edu'); await q.fill('input[name=password]', 'clave-xss-123');
    await q.click('button[type=submit]');
    await espera(4000);
    console.log('HTML en la variante:', await q.innerHTML('div.tarjeta'));
    await q.close();
  });
  await navegador.close();
})();

/* =====================================================================
   Nodo 03 · Oficialía de Partes Cifrada — lógica de la interfaz
   ---------------------------------------------------------------------
   JavaScript sin frameworks, organizado así:
     1. Utilidades (escapar HTML, fechas, tamaños, hashes)
     2. Cliente de la API local (/api/local/...)
     3. Alertamiento en tiempo real (Server-Sent Events + sonido + notificación)
     4. Enrutador por hash (#/panel, #/enviar, ...)
     5. Una función por pantalla
     6. Cajón lateral (detalle de Consultas)
   Regla de seguridad: TODO texto que viene del servidor (y que pudo escribir
   otro equipo, como nombres de archivo) pasa por esc() antes de ir al HTML,
   para evitar inyección de HTML/JS (XSS).
   ===================================================================== */
'use strict';

/* ------------------------------------------------------------------ 1. Utilidades */

const $ = (sel, raiz = document) => raiz.querySelector(sel);
const $$ = (sel, raiz = document) => [...raiz.querySelectorAll(sel)];

/** Escapa texto para insertarlo como HTML de forma segura. */
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Fecha UTC del servidor -> hora local legible. */
function fecha(iso, conFecha = true) {
  if (!iso) return '—';
  const d = new Date(iso);
  const hora = d.toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  return conFecha ? `${d.toLocaleDateString('es-MX', { day: '2-digit', month: 'short' })} · ${hora}` : hora;
}

/** 14820 -> "14.5 KB" */
function tamano(bytes) {
  if (bytes == null) return '—';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0, n = Number(bytes);
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

/** Hash con los primeros 8 caracteres resaltados (= SHA8 del nombre del zip). */
function hashHtml(h) {
  if (!h) return '<span class="hash">—</span>';
  return `<span class="hash"><mark>${esc(h.slice(0, 8))}</mark>${esc(h.slice(8))}</span>`;
}

/** Sello de verificación X.509. */
function selloVerif(v) {
  return v === 'X.509 OK'
    ? '<span class="sello sello--ok">X.509 OK</span>'
    : `<span class="sello sello--mal">${esc(v || 'Inválida')}</span>`;
}

/** Sello de estado de una solicitud. */
function selloEstado(e) {
  const clase = { Pendiente: 'pend', Aceptada: 'ok', Rechazada: 'mal' }[e] || 'info';
  return `<span class="sello sello--${clase} sello--plano">${esc(e)}</span>`;
}

function chipAlg(codigo) {
  const c = String(codigo || '').toUpperCase();
  const clase = c === 'RSA' ? 'chip--rsa' : c === 'ECC' ? 'chip--ecc' : '';
  return `<span class="chip ${clase}">${esc(c || '¿?')}</span>`;
}

const nombreModo = m => ({ text: 'Texto', image: 'Imagen', file: 'Archivo' }[m] || m);

/** Almacenamiento del navegador con try/catch (puede estar bloqueado). */
const preferencia = {
  leer(k, def) { try { const v = localStorage.getItem('nodo03.' + k); return v === null ? def : JSON.parse(v); } catch { return def; } },
  guardar(k, v) { try { localStorage.setItem('nodo03.' + k, JSON.stringify(v)); } catch { /* sin almacenamiento */ } },
};

/* ------------------------------------------------------------------ 2. API */

async function pedir(metodo, url, cuerpo) {
  const opciones = { method: metodo, headers: {} };
  if (cuerpo instanceof FormData) opciones.body = cuerpo;
  else if (cuerpo !== undefined) { opciones.body = JSON.stringify(cuerpo); opciones.headers['Content-Type'] = 'application/json'; }
  const r = await fetch(url, opciones);
  const tipo = r.headers.get('content-type') || '';
  const datos = tipo.includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error((datos && datos.error) || (datos && datos.message) || `Error ${r.status}`);
  return datos;
}
const api = {
  get: url => pedir('GET', url),
  post: (url, c) => pedir('POST', url, c),
  put: (url, c) => pedir('PUT', url, c),
  del: url => pedir('DELETE', url),
};

/* ------------------------------------------------------------------ 3. Alertamiento */

let audio = null;
/** El navegador solo permite sonido después de que el usuario hizo clic alguna vez. */
document.addEventListener('pointerdown', () => {
  if (!audio) { try { audio = new (window.AudioContext || window.webkitAudioContext)(); } catch { audio = null; } }
}, { once: true });

/** "Timbre" de oficialía: dos tonos cortos. */
function sonar(tipo = 'ok') {
  if (!audio || !preferencia.leer('sonido', true)) return;
  const tonos = tipo === 'mal' ? [330, 220] : [660, 880];
  tonos.forEach((f, i) => {
    const osc = audio.createOscillator(), vol = audio.createGain();
    osc.type = 'sine'; osc.frequency.value = f;
    const t = audio.currentTime + i * 0.16;
    vol.gain.setValueAtTime(0.0001, t);
    vol.gain.exponentialRampToValueAtTime(0.18, t + 0.02);
    vol.gain.exponentialRampToValueAtTime(0.0001, t + 0.14);
    osc.connect(vol).connect(audio.destination);
    osc.start(t); osc.stop(t + 0.15);
  });
}

/** Aviso emergente dentro de la página. */
function telegrama(titulo, texto, tipo = 'ok', ir) {
  const el = document.createElement('div');
  el.className = `telegrama telegrama--${tipo}`;
  el.innerHTML = `<b>${esc(titulo)}</b><span>${esc(texto)}</span>`;
  el.addEventListener('click', () => { if (ir) location.hash = ir; el.remove(); });
  $('#avisos').prepend(el);
  setTimeout(() => el.remove(), 7000);
}

/** Notificación del sistema operativo (si el usuario dio permiso y la pestaña no está visible). */
function notificarSistema(titulo, texto) {
  if (!('Notification' in window) || Notification.permission !== 'granted' || !document.hidden) return;
  try { new Notification(titulo, { body: texto, tag: 'nodo03' }); } catch { /* algunos navegadores lo bloquean */ }
}

/** Contador de pendientes en la pestaña "Solicitudes" y en el título de la ventana. */
function actualizarContador(n) {
  const b = $('#contador-pendientes');
  b.textContent = n;
  b.hidden = !n;
  document.title = (n ? `(${n}) ` : '') + 'Nodo 03 · Oficialía de Partes Cifrada';
}

/**
 * Conexión SSE con el servidor. El navegador reconecta solo si se cae;
 * solo actualizamos el indicador de estado del membrete.
 */
function conectarEventos() {
  const estado = $('#estado-conexion');
  const poner = (e, t) => { estado.dataset.estado = e; estado.querySelector('span').textContent = t; };
  const fuente = new EventSource('/api/local/eventos');
  fuente.onopen = () => poner('en-linea', 'En línea · escuchando la red');
  fuente.onerror = () => poner('sin-conexion', 'Sin conexión con el nodo… reintentando');

  fuente.addEventListener('solicitud', ev => {
    const d = JSON.parse(ev.data);
    actualizarContador(d.pendientes);
    const valida = d.verificacion === 'X.509 OK';
    const titulo = valida ? `Llegó un paquete de ${d.nodo}` : `Paquete INVÁLIDO de ${d.nodo}`;
    const texto = `${d.zip} · ${d.algoritmo}${d.salto ? ' · rebote #' + d.salto : ''}`;
    telegrama(titulo, texto, valida ? 'ok' : 'mal', '#/solicitudes');
    sonar(valida ? 'ok' : 'mal');
    notificarSistema(titulo, texto);
    refrescarSi(['solicitudes', 'panel']);
  });
  fuente.addEventListener('decision', ev => {
    const d = JSON.parse(ev.data);
    if (d.pendientes !== undefined) actualizarContador(d.pendientes);
    if (d.automatico) telegrama('Ping-pong automático', 'Pelota aceptada; regresando…', 'alerta');
    refrescarSi(['solicitudes', 'consultas', 'panel']);
  });
  const alEnviar = ev => {
    const d = JSON.parse(ev.data);
    const titulo = ev.type === 'rebote' ? `Rebote #${d.salto} → ${d.destino}` : `Envío → ${d.destino}`;
    telegrama(titulo, `${d.zip} · ${d.resultado}`, d.ok ? 'ok' : 'mal', '#/consultas');
    refrescarSi(['consultas', 'panel']);
  };
  fuente.addEventListener('envio', alEnviar);
  fuente.addEventListener('rebote', alEnviar);
  fuente.addEventListener('error', ev => {
    if (!ev.data) return; // errores de conexión de EventSource también llegan como 'error'
    const d = JSON.parse(ev.data);
    telegrama(d.mensaje, d.detalle || '', 'mal');
    sonar('mal');
  });
}

/* ------------------------------------------------------------------ 4. Enrutador */

const pantallas = {};
let rutaActual = '';

function refrescarSi(rutas) {
  // No redibujamos el formulario de Enviar ni el Verificador para no borrar lo que el usuario escribió.
  if (rutas.includes(rutaActual)) pantallas[rutaActual]?.(true);
}

async function navegar() {
  const [ruta, ...extra] = (location.hash.replace(/^#\/?/, '') || 'panel').split('/');
  rutaActual = pantallas[ruta] ? ruta : 'panel';
  $$('.carpeta a').forEach(a => {
    if (a.dataset.ruta === rutaActual) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  cerrarCajon();
  try {
    await pantallas[rutaActual](false, extra);
  } catch (e) {
    $('#vista').innerHTML = `<div class="vacio"><strong>No se pudo cargar</strong>${esc(e.message)}</div>`;
  }
  if (!extra.length) $('#vista').focus({ preventScroll: true });
}

function pintar(html) { $('#vista').innerHTML = html; }

/* ------------------------------------------------------------------ 5. Pantallas */

/* ===== Panel ===== */
pantallas.panel = async () => {
  const [id, bitacora] = await Promise.all([api.get('/api/local/identidad'), api.get('/api/local/bitacora?limite=150')]);
  actualizarContador(id.pendientes);

  // Agrupa la bitácora por rally (cada pelota de ping-pong tiene su rallyId).
  const rallies = new Map();
  [...bitacora].reverse().forEach(e => {
    if (!e.rallyId || e.salto == null) return;
    if (!rallies.has(e.rallyId)) rallies.set(e.rallyId, []);
    rallies.get(e.rallyId).push(e);
  });
  const ultimos = [...rallies.entries()].slice(-5).reverse();

  const golpe = e => {
    const tipo = e.tipo === 'recepcion' ? 'entra' : e.tipo === 'rechazo-automatico' || e.tipo === 'error' ? 'mal' : 'sale';
    if (!['recepcion', 'envio', 'rebote', 'rechazo-automatico', 'generado'].includes(e.tipo)) return '';
    return `<span class="golpe golpe--${tipo}" title="${esc(e.mensaje)}"><span class="golpe__bola">${e.salto}</span><span class="golpe__red"></span></span>`;
  };

  pintar(`
    <div class="encabezado">
      <div>
        <span class="etiqueta">Mesa de control</span>
        <h1>Panel del ${esc(id.nodoId)}</h1>
        <p>Cada paquete es un oficio sellado con certificado X.509. Aquí se ve quién envió qué y cómo va el ping-pong entre células.</p>
      </div>
      <a class="btn btn--grande" href="#/enviar">✉ Nuevo envío</a>
    </div>

    <div class="rejilla rejilla--3" style="margin-bottom:18px">
      <a class="hoja cifra cifra--sello" href="#/solicitudes" style="text-decoration:none;color:inherit">
        <span class="etiqueta">Solicitudes pendientes</span><b>${id.pendientes}</b></a>
      <a class="hoja cifra cifra--verde" href="#/consultas" style="text-decoration:none;color:inherit">
        <span class="etiqueta">Registros en Consultas</span><b>${id.consultas}</b></a>
      <div class="hoja cifra"><span class="etiqueta">Dirección en la LAN</span>
        <b style="font:600 20px var(--f-mono);margin-top:12px">${esc(id.direccion)}</b></div>
    </div>

    <div class="rejilla rejilla--panel">
      <section class="hoja credencial" aria-labelledby="t-cred">
        <div class="hoja__titulo"><h2 id="t-cred">Credencial del nodo</h2><span class="etiqueta">Certificados públicos</span></div>
        ${id.certificados.map(c => `
          <div class="cert">
            <span class="cert__tipo cert__tipo--${c.codigo.toLowerCase()}">${c.codigo}</span>
            <div>
              <strong>${esc(c.llave)}</strong>
              <small>Firma: ${esc(c.firma)} · vigente hasta ${new Date(c.hasta).toLocaleDateString('es-MX')}</small>
              <div class="hash" title="Huella SHA-256 del certificado">${esc(c.huella.match(/.{1,4}/g).join(' '))}</div>
            </div>
            <a class="btn btn--sec btn--chico" href="/api/local/certificado/${c.codigo}" download>.pem</a>
          </div>`).join('')}
        <p class="ayuda" style="margin-top:10px">Comparte estas huellas con los demás equipos: si coinciden con las del paquete que reciben, el paquete es del Nodo 03.</p>
      </section>

      <section class="hoja" aria-labelledby="t-rally">
        <div class="hoja__titulo"><h2 id="t-rally">Ping-pong</h2><span class="etiqueta">Últimos rallies</span></div>
        ${ultimos.length ? ultimos.map(([rid, eventos]) => `
          <div class="rally">
            <div class="rally__cab"><span>Rally <code>${esc(rid.slice(0, 8))}</code></span><span>${eventos.length} ${eventos.length === 1 ? 'golpe' : 'golpes'} · ${fecha(eventos.at(-1).fechaUtc, false)}</span></div>
            <div class="mesa">${eventos.map(golpe).join('')}</div>
          </div>`).join('') : `<div class="vacio"><strong>Aún no hay pelotas en juego</strong>Envía un paquete RSA o ECC a otro nodo para empezar.</div>`}
        <div class="leyenda"><span><i class="l-sale"></i>sale de este nodo</span><span><i class="l-entra"></i>llega a este nodo</span><span>el número es el rebote</span></div>
      </section>
    </div>

    <section class="hoja" style="margin-top:18px" aria-labelledby="t-bit">
      <div class="hoja__titulo"><h2 id="t-bit">Bitácora</h2><span class="etiqueta">En tiempo real</span></div>
      <ul class="bitacora">
        ${bitacora.slice(0, 40).map(e => `<li><time>${fecha(e.fechaUtc, false)}</time><span class="t-${esc(e.tipo)}">${esc(e.mensaje)}</span></li>`).join('')}
      </ul>
    </section>`);
};

/* ===== Enviar (Modo Emisor) ===== */
pantallas.enviar = async (refresco, extra = []) => {
  if (refresco) return;
  const nodos = await api.get('/api/local/nodos').catch(() => []);
  const ipInicial = extra[0] ? decodeURIComponent(extra[0]) : '';

  pintar(`
    <div class="encabezado"><div>
      <span class="etiqueta">Modo emisor</span>
      <h1>Nuevo envío</h1>
      <p>Carga una frase, una imagen o un archivo. Se cifra con RSA o ECC, se firma con el certificado del nodo y se manda como <code>.zip</code> estándar.</p>
    </div></div>

    <form class="hoja" id="form-envio" novalidate>
      <div class="paso">
        <span class="paso__num">1</span>
        <div>
          <h2>¿Qué vas a cifrar?</h2>
          <div class="segmentos" role="radiogroup" aria-label="Tipo de contenido">
            <label><input type="radio" name="modo" value="text" checked><span>Frase</span></label>
            <label><input type="radio" name="modo" value="image"><span>Imagen</span></label>
            <label><input type="radio" name="modo" value="file"><span>Archivo</span></label>
          </div>
          <div id="caja-texto">
            <label class="campo"><span class="etiqueta">Mensaje</span>
              <textarea name="texto" placeholder="Ej. CURP: VERA040101HDFLMR09 — información de prueba para la célula 5"></textarea></label>
            <p class="ayuda" id="cuenta-texto">0 bytes. Hasta 190 bytes RSA cifra directo; más largo usa RSA + AES-GCM.</p>
          </div>
          <div id="caja-archivo" hidden>
            <label class="soltar" id="soltar">
              <input type="file" name="archivo" id="archivo">
              <strong>Suelta aquí la imagen o el archivo</strong>
              <span class="ayuda">o haz clic para elegirlo · máximo 50 MB</span>
              <div class="previa" id="previa"></div>
            </label>
          </div>
        </div>
      </div>

      <div class="paso">
        <span class="paso__num">2</span>
        <div>
          <h2>Algoritmo</h2>
          <div class="algoritmos">
            <label class="algoritmo"><input type="radio" name="algoritmo" value="RSA" checked>
              <div><span class="etiqueta">#5 · Asimétrico</span><b>RSA</b>
                <small>RSA-2048 con OAEP-SHA256 para cifrar y PSS-SHA256 para firmar. Contenidos grandes: híbrido RSA + AES-256-GCM.</small></div></label>
            <label class="algoritmo"><input type="radio" name="algoritmo" value="ECC">
              <div><span class="etiqueta">#6 · Curva elíptica</span><b>ECC</b>
                <small>ECIES sobre P-256: ECDH efímero + HKDF-SHA256 + AES-256-GCM. Firma ECDSA-P256-SHA256.</small></div></label>
          </div>
        </div>
      </div>

      <div class="paso">
        <span class="paso__num">3</span>
        <div>
          <h2>Destino</h2>
          <label class="campo"><span class="etiqueta">Dirección del nodo (IP:Puerto)</span>
            <div class="acciones">
              <input type="text" name="direccion" list="nodos-conocidos" placeholder="192.168.1.14:5000" value="${esc(ipInicial)}" style="flex:1 1 220px;font-family:var(--f-mono)" autocomplete="off">
              <button type="button" class="btn btn--sec" id="probar">Probar conexión</button>
            </div>
            <datalist id="nodos-conocidos">${nodos.map(n => `<option value="${esc(n.direccion)}">${esc(n.nodoId)}</option>`).join('')}</datalist>
          </label>
          <p class="ayuda" id="resultado-prueba"></p>

          <span class="etiqueta" style="display:block;margin:12px 0 8px">¿Para quién se cifra? (dueño de la llave pública)</span>
          <div class="destinos">
            <label class="destino"><input type="radio" name="destinatario" value="remoto" checked>
              <div><strong>Para el nodo destino</strong><div class="ayuda">Se pide su certificado a <code>/api/certificate</code>. Solo él podrá descifrar. Es el modo del ping-pong.</div></div></label>
            <label class="destino"><input type="radio" name="destinatario" value="pem">
              <div><strong>Para un certificado que subo</strong><div class="ayuda">Útil si el otro equipo te pasó su <code>.pem</code> pero su nodo no lo publica.</div>
                <div class="sub"><input type="file" name="certificado" accept=".pem,.crt,.cer"></div></div></label>
            <label class="destino"><input type="radio" name="destinatario" value="propio">
              <div><strong>Para mí (Nodo 03)</strong><div class="ayuda">Para equipos que solo validan la firma, o para generar un archivo de prueba.</div></div></label>
          </div>

          <label class="interruptor" style="margin-top:14px"><input type="checkbox" name="soloGenerar"> Solo generar el <code>.zip</code> (no enviar por la red)</label>
        </div>
      </div>

      <div class="acciones" style="margin-top:26px;justify-content:flex-end">
        <button class="btn btn--grande" type="submit" id="btn-enviar">Sellar y enviar</button>
      </div>
    </form>
    <div id="acuse"></div>`);

  const form = $('#form-envio');
  const modoActual = () => form.modo.value;

  // Cambiar entre frase / imagen / archivo
  form.addEventListener('change', e => {
    if (e.target.name === 'modo') {
      $('#caja-texto').hidden = modoActual() !== 'text';
      $('#caja-archivo').hidden = modoActual() === 'text';
      $('#archivo').accept = modoActual() === 'image' ? 'image/*' : '';
    }
    if (e.target.name === 'soloGenerar' || e.target.name === 'destinatario') {
      $('#btn-enviar').textContent = form.soloGenerar.checked ? 'Sellar y generar .zip' : 'Sellar y enviar';
    }
  });

  // Contador de bytes (UTF-8) para explicar RSA directo vs híbrido
  form.texto.addEventListener('input', () => {
    const n = new TextEncoder().encode(form.texto.value).length;
    $('#cuenta-texto').textContent = `${n} bytes · ` + (n <= 190
      ? 'con RSA se cifra DIRECTO con la llave pública (RSA-OAEP).'
      : 'con RSA se usa el esquema HÍBRIDO (RSA-OAEP protege una llave AES-256-GCM).');
  });

  // Arrastrar y soltar + vista previa
  const zona = $('#soltar'), entrada = $('#archivo');
  ['dragenter', 'dragover'].forEach(t => zona.addEventListener(t, e => { e.preventDefault(); zona.classList.add('encima'); }));
  ['dragleave', 'drop'].forEach(t => zona.addEventListener(t, () => zona.classList.remove('encima')));
  zona.addEventListener('drop', e => { e.preventDefault(); entrada.files = e.dataTransfer.files; mostrarPrevia(); });
  entrada.addEventListener('change', mostrarPrevia);
  function mostrarPrevia() {
    const f = entrada.files[0];
    if (!f) return;
    const img = f.type.startsWith('image/') ? `<img alt="" src="${URL.createObjectURL(f)}">` : '';
    $('#previa').innerHTML = `${img}<div><strong style="font-size:15px">${esc(f.name)}</strong><span class="ayuda">${tamano(f.size)} · ${esc(f.type || 'binario')}</span></div>`;
    if (f.type.startsWith('image/') && modoActual() === 'file') form.querySelector('[name=modo][value=image]').click();
  }

  // Probar conexión con /api/status del destino (vía el directorio de nodos)
  $('#probar').addEventListener('click', async () => {
    const dir = form.direccion.value.trim();
    if (!dir) return;
    $('#resultado-prueba').textContent = 'Probando…';
    try {
      const n = await api.post('/api/local/nodos', { direccion: dir });
      $('#resultado-prueba').innerHTML = `${esc(n.nodoId)} · <strong>${esc(n.estado)}</strong> · certificado RSA ${n.tieneRsa ? '✓' : '✕'} · ECC ${n.tieneEcc ? '✓' : '✕'}`;
    } catch (e) { $('#resultado-prueba').textContent = e.message; }
  });

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const fd = new FormData();
    fd.append('modo', modoActual());
    fd.append('algoritmo', form.algoritmo.value);
    fd.append('destinatario', form.destinatario.value);
    fd.append('direccion', form.direccion.value.trim());
    fd.append('soloGenerar', form.soloGenerar.checked ? 'true' : 'false');
    if (modoActual() === 'text') {
      if (!form.texto.value.trim()) return telegrama('Falta el mensaje', 'Escribe una frase para cifrar.', 'alerta');
      fd.append('texto', form.texto.value);
    } else {
      if (!entrada.files[0]) return telegrama('Falta el archivo', 'Elige una imagen o archivo.', 'alerta');
      fd.append('archivo', entrada.files[0]);
    }
    if (form.destinatario.value === 'pem') {
      if (!form.certificado.files[0]) return telegrama('Falta el certificado', 'Sube el .pem del destinatario.', 'alerta');
      fd.append('certificado', form.certificado.files[0]);
    }
    const boton = $('#btn-enviar');
    boton.disabled = true; boton.textContent = 'Cifrando y firmando…';
    try {
      const r = await api.post('/api/local/enviar', fd);
      const sello = form.soloGenerar.checked ? '<span class="sello sello--info">Generado</span>'
        : r.ok ? `<span class="sello sello--ok">Entregado · ${r.codigoHttp}</span>`
          : `<span class="sello sello--mal">No entregado${r.codigoHttp ? ' · ' + r.codigoHttp : ''}</span>`;
      $('#acuse').innerHTML = `
        <div class="acuse">${sello}
          <span class="etiqueta">Acuse</span><h2>${esc(r.mensaje)}</h2>
          <dl>
            <dt>Paquete</dt><dd class="mono">${esc(r.nombreZip)}</dd>
            <dt>SHA-256 datos.enc</dt><dd>${hashHtml(r.sha256)}</dd>
            <dt>Algoritmo</dt><dd>${chipAlg(form.algoritmo.value)}</dd>
          </dl>
          <div class="acciones">
            <a class="btn" href="/api/local/consultas/${encodeURIComponent(r.consultaId)}/zip" download>Descargar .zip</a>
            <a class="btn btn--sec" href="#/consultas/${encodeURIComponent(r.consultaId)}">Ver en Consultas</a>
          </div>
        </div>`;
      $('#acuse').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
      telegrama('No se pudo enviar', err.message, 'mal');
      $('#acuse').innerHTML = `<div class="acuse"><span class="sello sello--mal">Error</span><span class="etiqueta">Acuse</span><h2>${esc(err.message)}</h2></div>`;
    } finally {
      boton.disabled = false;
      boton.textContent = form.soloGenerar.checked ? 'Sellar y generar .zip' : 'Sellar y enviar';
    }
  });
};

/* ===== Solicitudes (bandeja del Modo Receptor) ===== */
let filtroSolicitudes = 'Pendiente';
pantallas.solicitudes = async () => {
  const lista = await api.get('/api/local/solicitudes' + (filtroSolicitudes ? `?estado=${filtroSolicitudes}` : ''));
  const filtros = [['Pendiente', 'Pendientes'], ['Aceptada', 'Aceptadas'], ['Rechazada', 'Rechazadas'], ['', 'Todas']];

  pintar(`
    <div class="encabezado"><div>
      <span class="etiqueta">Modo receptor · POST /api/requests/receive</span>
      <h1>Solicitudes</h1>
      <p>Paquetes que llegaron por la red. El nodo ya revisó la estructura, el SHA-256 y la firma X.509; tú decides si entran al archivo de Consultas.</p>
    </div></div>
    <div class="filtros" role="group" aria-label="Filtrar por estado">
      ${filtros.map(([v, t]) => `<button type="button" data-filtro="${v}" aria-pressed="${v === filtroSolicitudes}">${t}</button>`).join('')}
    </div>
    <div class="oficios">
      ${lista.length ? lista.map(s => `
        <article class="oficio ${s.estado !== 'Pendiente' ? 'oficio--decidido' : ''}">
          <div class="oficio__talon">
            <span class="etiqueta">Folio</span>
            <b>${esc((s.sha256 || '').slice(0, 8).toUpperCase())}</b>
            <span class="ayuda">${fecha(s.recibidoUtc)}</span>
          </div>
          <div class="oficio__cuerpo">
            <h3>${esc(s.nombreZip)}</h3>
            <div class="oficio__meta">
              <span>De <strong>${esc(s.nodoOrigen)}</strong></span>
              <span>IP <code>${esc(s.origenIp)}</code></span>
              <span>${chipAlg(s.algoritmoCodigo)} ${esc(s.algoritmoDescripcion)}</span>
              <span>${esc(nombreModo(s.modo))} · ${esc(s.nombreOriginal)} · ${tamano(s.tamanoOriginal)}</span>
              ${s.salto ? `<span>Rebote #${s.salto}</span>` : ''}
            </div>
          </div>
          <div class="oficio__lado">
            <div class="acciones">${selloVerif(s.verificacion)} ${s.estado !== 'Pendiente' ? selloEstado(s.estado) : ''}</div>
            <div class="acciones">
              <button class="btn btn--sec btn--chico" data-detalle="${esc(s.id)}">Detalle</button>
              ${s.estado === 'Pendiente' ? `
                <button class="btn btn--mal btn--chico" data-rechazar="${esc(s.id)}">Rechazar</button>
                <button class="btn btn--ok btn--chico" data-aceptar="${esc(s.id)}">Aceptar</button>` : ''}
            </div>
          </div>
        </article>`).join('') : `<div class="vacio"><strong>Bandeja vacía</strong>Cuando otra célula envíe un paquete a este nodo, aparecerá aquí con una alerta.</div>`}
    </div>`);

  $$('[data-filtro]').forEach(b => b.addEventListener('click', () => { filtroSolicitudes = b.dataset.filtro; pantallas.solicitudes(); }));
  $$('[data-aceptar]').forEach(b => b.addEventListener('click', async () => {
    b.disabled = true;
    try {
      const r = await api.post(`/api/local/solicitudes/${b.dataset.aceptar}/aceptar`);
      telegrama('Aceptada', 'Se guardó en Consultas.', 'ok', `#/consultas/${r.consultaId}`);
    } catch (e) { telegrama('No se pudo aceptar', e.message, 'mal'); }
    pantallas.solicitudes();
  }));
  $$('[data-rechazar]').forEach(b => b.addEventListener('click', async () => {
    b.disabled = true;
    try { await api.post(`/api/local/solicitudes/${b.dataset.rechazar}/rechazar`); telegrama('Rechazada', 'No entra a Consultas.', 'alerta'); }
    catch (e) { telegrama('No se pudo rechazar', e.message, 'mal'); }
    pantallas.solicitudes();
  }));
  $$('[data-detalle]').forEach(b => b.addEventListener('click', () => abrirSolicitud(b.dataset.detalle)));
};

/* ===== Consultas (archivo principal) ===== */
pantallas.consultas = async (refresco, extra = []) => {
  const lista = await api.get('/api/local/consultas');
  pintar(`
    <div class="encabezado"><div>
      <span class="etiqueta">Base de datos local</span>
      <h1>Consultas</h1>
      <p>Todo lo que este nodo recibió y aceptó, envió o generó. Abre un registro para descargarlo, descifrarlo, rebotarlo o reenviarlo.</p>
    </div></div>
    ${lista.length ? `
    <div class="tabla-envoltura"><table>
      <thead><tr><th>Fecha</th><th>Origen</th><th>Paquete</th><th>Nodo</th><th>Contenido</th><th>Verificación</th></tr></thead>
      <tbody>
        ${lista.map(c => `
          <tr data-id="${esc(c.id)}" tabindex="0">
            <td>${fecha(c.fechaUtc)}</td>
            <td><span class="origen origen--${esc(c.origen)}">${esc(c.origen)}</span>${c.salto ? ` <span class="ayuda">#${c.salto}</span>` : ''}</td>
            <td class="td-zip">${esc(c.nombreZip)}</td>
            <td>${esc(c.nodoRemoto)}</td>
            <td>${chipAlg(c.algoritmoCodigo)} ${esc(nombreModo(c.modo))}</td>
            <td>${c.origen === 'Recibido' ? selloVerif(c.verificacion) : `<span class="ayuda">${esc(c.resultadoEnvio || 'firmado')}</span>`}</td>
          </tr>`).join('')}
      </tbody></table></div>` : `<div class="vacio"><strong>Sin registros</strong>Acepta una solicitud o envía un paquete para empezar.</div>`}`);

  $$('tbody tr').forEach(tr => {
    tr.addEventListener('click', () => abrirConsulta(tr.dataset.id));
    tr.addEventListener('keydown', e => { if (e.key === 'Enter') abrirConsulta(tr.dataset.id); });
  });
  if (!refresco && extra[0]) abrirConsulta(decodeURIComponent(extra[0]));
};

/* ===== Verificador ===== */
pantallas.verificador = async refresco => {
  if (refresco) return;
  pintar(`
    <div class="encabezado"><div>
      <span class="etiqueta">Herramienta</span>
      <h1>Verificador de paquetes</h1>
      <p>Revisa cualquier <code>.zip</code> del estándar (de cualquier equipo, con cualquier algoritmo) sin registrarlo: estructura, nombre, SHA-256, huella y firma del certificado.</p>
    </div></div>
    <label class="soltar hoja" id="soltar-v">
      <input type="file" accept=".zip" id="zip-v">
      <strong>Suelta aquí un paquete .zip</strong>
      <span class="ayuda">El archivo no sale de este nodo.</span>
    </label>
    <div id="reporte"></div>`);

  const zona = $('#soltar-v'), entrada = $('#zip-v');
  ['dragenter', 'dragover'].forEach(t => zona.addEventListener(t, e => { e.preventDefault(); zona.classList.add('encima'); }));
  ['dragleave', 'drop'].forEach(t => zona.addEventListener(t, () => zona.classList.remove('encima')));
  zona.addEventListener('drop', e => { e.preventDefault(); entrada.files = e.dataTransfer.files; verificar(); });
  entrada.addEventListener('change', verificar);

  async function verificar() {
    const f = entrada.files[0];
    if (!f) return;
    const fd = new FormData();
    fd.append('package', f);
    $('#reporte').innerHTML = '<p class="ayuda" style="margin-top:14px">Verificando…</p>';
    try {
      const r = await api.post('/api/local/verificar', fd);
      if (!r.estructura) {
        $('#reporte').innerHTML = `<div class="acuse"><span class="sello sello--mal">Malformado · 400</span><span class="etiqueta">${esc(r.nombre)}</span><h2>${esc(r.error)}</h2></div>`;
        return;
      }
      $('#reporte').innerHTML = `
        <div class="acuse">${selloVerif(r.validacion.etiqueta)}
          <span class="etiqueta">Reporte</span><h2 class="mono" style="font-size:15px;padding-right:130px;word-break:break-all">${esc(r.nombre)}</h2>
          <div style="margin-top:16px">${listaChecks(r.validacion, r.nombreValido)}</div>
          ${r.validacion.certificado ? bloqueCertificado(r.validacion.certificado) : ''}
          <div class="cajon__seccion"><span class="etiqueta">manifest.json</span><pre class="json">${esc(JSON.stringify(r.manifiesto, null, 2))}</pre></div>
        </div>`;
    } catch (e) { $('#reporte').innerHTML = `<p class="ayuda">${esc(e.message)}</p>`; }
  }
};

/* ===== Nodos ===== */
pantallas.nodos = async () => {
  const lista = await api.get('/api/local/nodos');
  pintar(`
    <div class="encabezado"><div>
      <span class="etiqueta">Conectividad entre dispositivos</span>
      <h1>Directorio de células</h1>
      <p>Registra la IP:Puerto de cada equipo. El nodo consulta su <code>/api/status</code> y, si lo publica, guarda su certificado para cifrarle.</p>
    </div></div>
    <form class="hoja acciones" id="form-nodo" style="align-items:flex-end">
      <label style="flex:1 1 260px"><span class="etiqueta">IP:Puerto</span>
        <input type="text" name="direccion" placeholder="192.168.1.20:5000" required style="font-family:var(--f-mono);margin-top:6px"></label>
      <button class="btn" type="submit">Agregar y probar</button>
    </form>
    <div style="margin-top:18px">
    ${lista.length ? `<div class="tabla-envoltura"><table>
      <thead><tr><th>Nodo</th><th>Dirección</th><th>Estado</th><th>Certificados</th><th>Última respuesta</th><th></th></tr></thead>
      <tbody>${lista.map(n => `
        <tr>
          <td><strong>${esc(n.nodoId)}</strong></td>
          <td class="mono">${esc(n.direccion)}</td>
          <td>${n.estado === 'en línea' ? '<span class="sello sello--ok sello--plano">En línea</span>' : `<span class="sello sello--mal sello--plano">${esc(n.estado)}</span>`}</td>
          <td>${n.tieneRsa ? chipAlg('RSA') : ''} ${n.tieneEcc ? chipAlg('ECC') : ''} ${!n.tieneRsa && !n.tieneEcc ? '<span class="ayuda">no publica</span>' : ''}</td>
          <td>${fecha(n.vistoUtc)}</td>
          <td><div class="acciones" style="justify-content:flex-end">
            <button class="btn btn--sec btn--chico" data-probar="${esc(n.direccion)}">Probar</button>
            <a class="btn btn--chico" href="#/enviar/${encodeURIComponent(n.direccion)}">Enviar</a>
            <button class="btn btn--mal btn--chico" data-quitar="${esc(n.direccion)}" aria-label="Quitar ${esc(n.nodoId)}">×</button></div></td>
        </tr>`).join('')}</tbody></table></div>`
      : `<div class="vacio"><strong>Sin células registradas</strong>Pide a cada equipo su IP (ipconfig / ip a) y el puerto donde corre su nodo.</div>`}
    </div>`);

  $('#form-nodo').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      const n = await api.post('/api/local/nodos', { direccion: e.target.direccion.value });
      telegrama(`${n.nodoId}`, `${n.direccion} · ${n.estado}`, n.estado === 'en línea' ? 'ok' : 'alerta');
    } catch (err) { telegrama('Dirección inválida', err.message, 'mal'); }
    pantallas.nodos();
  });
  $$('[data-probar]').forEach(b => b.addEventListener('click', async () => {
    b.disabled = true;
    const n = await api.post('/api/local/nodos', { direccion: b.dataset.probar }).catch(e => ({ estado: e.message }));
    telegrama(b.dataset.probar, n.estado, n.estado === 'en línea' ? 'ok' : 'alerta');
    pantallas.nodos();
  }));
  $$('[data-quitar]').forEach(b => b.addEventListener('click', async () => {
    await api.del('/api/local/nodos?direccion=' + encodeURIComponent(b.dataset.quitar));
    pantallas.nodos();
  }));
};

/* ===== Ajustes ===== */
pantallas.ajustes = async refresco => {
  if (refresco) return;
  const a = await api.get('/api/local/ajustes');
  const permiso = 'Notification' in window ? Notification.permission : 'no disponible';
  pintar(`
    <div class="encabezado"><div>
      <span class="etiqueta">Configuración</span>
      <h1>Ajustes</h1>
      <p>Se guardan en la base del nodo y aplican de inmediato.</p>
    </div></div>
    <form id="form-ajustes" class="rejilla rejilla--2">
      <section class="hoja">
        <h2 style="margin-bottom:14px">Recepción</h2>
        <label class="interruptor campo"><input type="checkbox" name="aceptandoPaquetes" ${a.aceptandoPaquetes ? 'checked' : ''}> Aceptar paquetes de la red (<code>acceptingPackages</code>)</label>
        <span class="etiqueta" style="display:block;margin:16px 0 8px">Algoritmos que se pueden descifrar</span>
        <label class="interruptor"><input type="checkbox" name="alg" value="RSA" ${a.algoritmosHabilitados.includes('RSA') ? 'checked' : ''}> RSA</label>
        <label class="interruptor" style="margin-top:6px"><input type="checkbox" name="alg" value="ECC" ${a.algoritmosHabilitados.includes('ECC') ? 'checked' : ''}> ECC</label>
        <label class="interruptor" style="margin-top:16px"><input type="checkbox" name="adminRemoto" ${a.adminRemoto ? 'checked' : ''}> Administración remota (manejar el nodo desde el celular)</label>
        <p class="ayuda">Apagado, solo esta computadora puede aceptar, rechazar o descifrar. Enciéndelo solo en una red de confianza.</p>
      </section>
      <section class="hoja">
        <h2 style="margin-bottom:14px">Ping-pong</h2>
        <label class="interruptor campo"><input type="checkbox" name="rebotarAutomatico" ${a.rebotarAutomatico ? 'checked' : ''}> Rebotar automáticamente las pelotas RSA/ECC dirigidas a este nodo</label>
        <div class="rejilla rejilla--2">
          <label class="campo"><span class="etiqueta">Máximo de rebotes</span><input type="number" name="maxRebotes" min="1" max="50" value="${a.maxRebotes}"></label>
          <label class="campo"><span class="etiqueta">Pausa entre rebotes (ms)</span><input type="number" name="pausaRebotesMs" min="0" max="10000" step="100" value="${a.pausaRebotesMs}"></label>
        </div>
        <h2 style="margin:10px 0 14px">Alertas</h2>
        <label class="interruptor campo"><input type="checkbox" id="sonido" ${preferencia.leer('sonido', true) ? 'checked' : ''}> Sonido al llegar un paquete</label>
        <button type="button" class="btn btn--sec" id="permiso-notif">Activar notificaciones del sistema</button>
        <p class="ayuda" style="margin-top:6px">Permiso actual: ${esc(permiso)}</p>
      </section>
      <div class="acciones" style="grid-column:1/-1;justify-content:flex-end"><button class="btn btn--grande" type="submit">Guardar ajustes</button></div>
    </form>`);

  $('#sonido').addEventListener('change', e => preferencia.guardar('sonido', e.target.checked));
  $('#permiso-notif').addEventListener('click', async () => {
    if (!('Notification' in window)) return telegrama('No disponible', 'Este navegador no soporta notificaciones.', 'alerta');
    const p = await Notification.requestPermission();
    telegrama('Notificaciones', p === 'granted' ? 'Activadas.' : 'No se dio permiso.', p === 'granted' ? 'ok' : 'alerta');
  });
  $('#form-ajustes').addEventListener('submit', async e => {
    e.preventDefault();
    const f = e.target;
    try {
      await api.put('/api/local/ajustes', {
        aceptandoPaquetes: f.aceptandoPaquetes.checked,
        rebotarAutomatico: f.rebotarAutomatico.checked,
        maxRebotes: Number(f.maxRebotes.value),
        pausaRebotesMs: Number(f.pausaRebotesMs.value),
        algoritmosHabilitados: $$('[name=alg]:checked', f).map(x => x.value),
        adminRemoto: f.adminRemoto.checked,
      });
      telegrama('Ajustes guardados', 'Ya están activos.', 'ok');
    } catch (err) { telegrama('No se guardó', err.message, 'mal'); }
  });
};

/* ------------------------------------------------------------------ 6. Cajón lateral */

function abrirCajon(html) {
  $('#cajon-contenido').innerHTML = html;
  $('#cajon').classList.add('abierto');
  $('#cajon').setAttribute('aria-hidden', 'false');
  $('#velo').hidden = false;
  $('.cajon__cerrar').focus();
}
function cerrarCajon() {
  $('#cajon').classList.remove('abierto');
  $('#cajon').setAttribute('aria-hidden', 'true');
  $('#velo').hidden = true;
}
$('.cajon__cerrar').addEventListener('click', cerrarCajon);
$('#velo').addEventListener('click', cerrarCajon);
document.addEventListener('keydown', e => { if (e.key === 'Escape') cerrarCajon(); });

/** Lista de comprobaciones a partir de un ResultadoValidacion. */
function listaChecks(v, nombreValido) {
  const items = [
    [true, 'Estructura: datos.enc, certificado.pem y manifest.json en la raíz'],
    [v.integridadOk, `Integridad SHA-256 de datos.enc ${v.integridadOk ? 'coincide' : 'NO coincide'}`],
    [v.huellaOk, `Huella del certificado ${v.huellaOk ? 'coincide con el manifiesto' : 'NO coincide'}`],
    [v.firmaOk, `Firma digital: ${v.detalleFirma || (v.firmaOk ? 'válida' : 'inválida')}`],
  ];
  if (nombreValido === false) v.avisos = ['El nombre no sigue NODO_ALG_FECHA_HORA_SHA8.zip', ...(v.avisos || [])];
  return `<ul class="checks">
    ${items.map(([ok, t]) => `<li class="${ok ? '' : 'mal'}">${esc(t)}</li>`).join('')}
    ${(v.errores || []).filter(e => !/firma|huella|SHA-256/i.test(e)).map(e => `<li class="mal">${esc(e)}</li>`).join('')}
    ${(v.avisos || []).map(a => `<li class="aviso">${esc(a)}</li>`).join('')}
  </ul>`;
}

function bloqueCertificado(c) {
  return `<div class="cajon__seccion"><span class="etiqueta">Certificado del emisor</span>
    <div class="hoja" style="padding:14px 16px;box-shadow:none">
      <strong>${esc(c.sujeto)}</strong>
      <div class="ayuda">Llave ${esc(c.tipoLlave)} · ${c.autofirmado ? 'autofirmado' : 'emitido por ' + esc(c.emisor)} · ${c.vigente ? 'vigente' : 'NO vigente'}
        (${new Date(c.noAntes).toLocaleDateString('es-MX')} – ${new Date(c.noDespues).toLocaleDateString('es-MX')})</div>
      <div class="hash" style="margin-top:6px">${esc(c.huella)}</div>
    </div></div>`;
}

async function abrirSolicitud(id) {
  const r = await api.get(`/api/local/solicitudes/${id}`);
  const s = r.solicitud, v = r.detalle;
  abrirCajon(`
    <span class="etiqueta">Solicitud · ${esc(s.estado)}</span>
    <h2 class="mono" style="font-size:15px;margin:6px 40px 12px 0;word-break:break-all">${esc(s.nombreZip)}</h2>
    <div class="acciones">${selloVerif(s.verificacion)} ${selloEstado(s.estado)}</div>
    <div class="cajon__seccion"><span class="etiqueta">Verificación automática</span>${listaChecks(v)}</div>
    ${v.certificado ? bloqueCertificado(v.certificado) : ''}
    <div class="cajon__seccion"><span class="etiqueta">Remitente</span>
      <p>${esc(s.nodoOrigen)} desde <code>${esc(s.origenIp)}</code>; responde a <code>${esc(s.direccionRespuesta || '—')}</code></p>
      <p class="ayuda">Paquete ${esc(s.packetId)} · rally ${esc(s.rallyId.slice(0, 8))} · rebote #${s.salto}</p></div>`);
}

async function abrirConsulta(id) {
  const r = await api.get(`/api/local/consultas/${id}`);
  const c = r.consulta, v = r.validacion;
  const puedeRebotar = c.origen === 'Recibido' && r.paraMi && r.descifrable;
  abrirCajon(`
    <span class="etiqueta">Consulta · ${esc(c.origen)}</span>
    <h2 class="mono" style="font-size:15px;margin:6px 40px 12px 0;word-break:break-all">${esc(c.nombreZip)}</h2>
    <div class="acciones" style="margin-bottom:14px">${selloVerif(v.etiqueta)} ${chipAlg(c.algoritmoCodigo)}</div>
    <div class="acciones">
      <a class="btn btn--chico" href="/api/local/consultas/${encodeURIComponent(c.id)}/zip" download>Descargar .zip</a>
      <button class="btn btn--sec btn--chico" id="b-descifrar" ${r.descifrable && r.paraMi ? '' : 'disabled title="Solo se descifran paquetes RSA/ECC cifrados para este nodo"'}>Descifrar</button>
      ${puedeRebotar ? `<button class="btn btn--ok btn--chico" id="b-rebotar">Rebotar a ${esc(c.nodoRemoto)} ↩</button>` : ''}
    </div>
    <div id="claro"></div>
    <div class="cajon__seccion"><span class="etiqueta">Reenviar el .zip tal cual a otra IP</span>
      <form class="acciones" id="f-reenviar">
        <input type="text" name="direccion" placeholder="IP:Puerto" required style="flex:1 1 180px;font-family:var(--f-mono)">
        <button class="btn btn--sec btn--chico" type="submit">Reenviar</button>
      </form>
      <p class="ayuda" style="margin-top:6px">Se conserva la firma del emisor original; el destino podrá verificar quién lo creó.</p></div>
    <div class="cajon__seccion"><span class="etiqueta">Verificación</span>${listaChecks(v)}</div>
    ${v.certificado ? bloqueCertificado(v.certificado) : ''}
    <div class="cajon__seccion"><span class="etiqueta">Datos</span>
      <p>${esc(nombreModo(c.modo))} · ${esc(c.nombreOriginal)} · ${tamano(c.tamanoOriginal)}<br>
      ${c.origen === 'Recibido' ? 'De' : 'Para'} ${esc(c.nodoRemoto)} <code>${esc(c.direccion)}</code> · ${fecha(c.fechaUtc)}<br>
      SHA-256: ${hashHtml(c.sha256)}</p>
      ${c.resultadoEnvio ? `<p>Resultado del envío: <strong>${esc(c.resultadoEnvio)}</strong></p>` : ''}</div>
    <div class="cajon__seccion"><span class="etiqueta">manifest.json</span><pre class="json">${esc(JSON.stringify(r.manifiesto, null, 2))}</pre></div>`);

  $('#b-descifrar')?.addEventListener('click', async () => {
    try {
      const d = await api.post(`/api/local/consultas/${id}/descifrar`);
      let cuerpo;
      if (d.modo === 'text') cuerpo = `<blockquote>${esc(d.texto)}</blockquote>`;
      else if (d.mime.startsWith('image/')) cuerpo = `<img alt="Imagen descifrada" src="data:${esc(d.mime)};base64,${d.base64}">`;
      else cuerpo = `<p>${esc(d.nombre)} · ${tamano(d.tamano)}</p>`;
      const enlace = `data:${d.mime};base64,${d.base64}`;
      $('#claro').innerHTML = `<div class="cajon__seccion"><span class="etiqueta">Contenido en claro</span>
        <div class="claro">${cuerpo}</div>
        <a class="btn btn--sec btn--chico" style="margin-top:8px" href="${esc(enlace)}" download="${esc(d.nombre)}">Guardar ${esc(d.nombre)}</a></div>`;
    } catch (e) { telegrama('No se pudo descifrar', e.message, 'mal'); }
  });
  $('#b-rebotar')?.addEventListener('click', async ev => {
    ev.target.disabled = true;
    try {
      const x = await api.post(`/api/local/consultas/${id}/rebotar`);
      telegrama(x.ok ? 'Pelota regresada' : 'No se pudo regresar', x.mensaje, x.ok ? 'ok' : 'mal');
    } catch (e) { telegrama('No se pudo rebotar', e.message, 'mal'); }
    ev.target.disabled = false;
  });
  $('#f-reenviar').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      const x = await api.post(`/api/local/consultas/${id}/reenviar`, { direccion: e.target.direccion.value.trim() });
      telegrama(x.ok ? 'Reenviado' : 'No se reenvió', x.mensaje, x.ok ? 'ok' : 'mal');
    } catch (err) { telegrama('No se reenvió', err.message, 'mal'); }
  });
}

/* ------------------------------------------------------------------ Arranque */

(async function iniciar() {
  try {
    const id = await api.get('/api/local/identidad');
    $('#nodo-id').textContent = id.nodoId;
    $('#nodo-dir').textContent = id.direccion;
    actualizarContador(id.pendientes);
  } catch (e) {
    pintar(`<div class="vacio"><strong>Acceso restringido</strong>${esc(e.message)}</div>`);
    return;
  }
  window.addEventListener('hashchange', navegar);
  conectarEventos();
  navegar();
})();

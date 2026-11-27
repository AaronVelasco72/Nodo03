/* =====================================================================
   Nodo EQ03 · Oficialía de Partes Cifrada — lógica de la interfaz (v2.0)
   ---------------------------------------------------------------------
   JavaScript sin frameworks, organizado así:
     1. Utilidades (escapar HTML, fechas, tamaños, hashes, sellos)
     2. Cliente de la API local (/api/local/...)
     3. Alertamiento en tiempo real (Server-Sent Events + sonido + notificación)
     4. Enrutador por hash (#/panel, #/operar, ...)
     5. Una función por pantalla
     6. Cajón lateral (detalle de Solicitudes y Consultas)
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

/** Huella en grupos de 4 para leerla en voz alta al confirmar (TOFU). */
const huellaLegible = h => h ? esc(h.match(/.{1,4}/g).join(' ')) : '—';

/** Sello de validación de la sección 15: Firma OK / Inválida / Remitente no confirmado. */
function selloVerif(v) {
  if (v === 'Firma OK') return '<span class="sello sello--ok">Firma OK</span>';
  if (v === 'Remitente no confirmado') return '<span class="sello sello--pend">Remitente no confirmado</span>';
  return `<span class="sello sello--mal">${esc(v || 'Inválida')}</span>`;
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

const nombreModo = m => ({ text: 'Texto', image: 'Imagen', file: 'Archivo', multipart: 'Multiparte' }[m] || m);

/** Almacenamiento del navegador con try/catch (puede estar bloqueado). */
const preferencia = {
  leer(k, def) { try { const v = localStorage.getItem('nodo03.' + k); return v === null ? def : JSON.parse(v); } catch { return def; } },
  guardar(k, v) { try { localStorage.setItem('nodo03.' + k, JSON.stringify(v)); } catch { /* sin almacenamiento */ } },
};

/** Muestra el contenido en claro que devuelve un inverse (texto, imagen o archivo). */
function htmlClaro(d) {
  let cuerpo;
  if (d.texto != null && d.modo === 'text') cuerpo = `<blockquote>${esc(d.texto)}</blockquote>`;
  else if (String(d.mime).startsWith('image/') && d.base64) cuerpo = `<img alt="Imagen recuperada" src="data:${esc(d.mime)};base64,${d.base64}">`;
  else cuerpo = `<p>${esc(d.nombre)} · ${tamano(d.tamano)}</p>`;
  const veredicto = d.verificacion ? `<p class="${d.verificacion.valid ? '' : 'mal'}"><strong>Verificación:</strong> ${d.verificacion.valid ? 'válida' : 'NO válida'} · ${esc(d.verificacion.detail)}</p>` : '';
  const enlace = d.base64 ? `<a class="btn btn--sec btn--chico" style="margin-top:8px" href="data:${esc(d.mime)};base64,${d.base64}" download="${esc(d.nombre)}">Guardar ${esc(d.nombre)}</a>` : '';
  return `<div class="cajon__seccion"><span class="etiqueta">Resultado · ejecutó ${esc(d.ejecutor)}${d.delegado ? ' (delegado)' : ' (local)'}</span>
    <div class="claro">${veredicto}${cuerpo}</div>${enlace}</div>`;
}

/* ------------------------------------------------------------------ 2. API */

async function pedir(metodo, url, cuerpo) {
  const opciones = { method: metodo, headers: {} };
  if (cuerpo instanceof FormData) opciones.body = cuerpo;
  else if (cuerpo !== undefined) { opciones.body = JSON.stringify(cuerpo); opciones.headers['Content-Type'] = 'application/json'; }
  const r = await fetch(url, opciones);
  const tipo = r.headers.get('content-type') || '';
  const datos = tipo.includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error((datos && (datos.error || datos.detail || datos.message)) || `Error ${r.status}`);
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

let nodoActual = 'EQ03';
/** Contador de pendientes en la pestaña "Solicitudes" y en el título de la ventana. */
function actualizarContador(n) {
  const b = $('#contador-pendientes');
  b.textContent = n;
  b.hidden = !n;
  document.title = (n ? `(${n}) ` : '') + `${nodoActual} · Oficialía de Partes Cifrada`;
}

/** Conexión SSE con el servidor. El navegador reconecta solo si se cae. */
function conectarEventos() {
  const estado = $('#estado-conexion');
  const poner = (e, t) => { estado.dataset.estado = e; estado.querySelector('span').textContent = t; };
  const fuente = new EventSource('/api/local/eventos');
  fuente.onopen = () => poner('en-linea', 'En línea · escuchando la red');
  fuente.onerror = () => poner('sin-conexion', 'Sin conexión con el nodo… reintentando');

  fuente.addEventListener('solicitud', ev => {
    const d = JSON.parse(ev.data);
    actualizarContador(d.pendientes);
    const valida = d.verificacion !== 'Inválida';
    const titulo = valida ? `Llegó un paquete de ${d.nodo}` : `Paquete INVÁLIDO de ${d.nodo}`;
    const texto = `${d.zip} · ${d.algoritmo} ${d.operacion || ''} · ${d.verificacion}${d.salto ? ' · rebote #' + d.salto : ''}`;
    telegrama(titulo, texto, valida ? (d.verificacion === 'Firma OK' ? 'ok' : 'alerta') : 'mal', '#/solicitudes');
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
  fuente.addEventListener('consulta', () => refrescarSi(['consultas', 'panel']));
  fuente.addEventListener('nodo', ev => {
    const d = JSON.parse(ev.data);
    if (d.nuevo) telegrama(`Nodo nuevo: ${d.nodeId}`, `${d.direccion} · confirma su huella en Nodos`, 'alerta', '#/nodos');
    refrescarSi(['nodos', 'panel']);
  });
  fuente.addEventListener('alerta', ev => {
    const d = JSON.parse(ev.data);
    telegrama('¡Cambio de certificado!', d.mensaje + ' — no se usará hasta que lo confirmes.', 'mal', '#/nodos');
    sonar('mal');
    notificarSistema('Cambio de certificado', d.mensaje);
    refrescarSi(['nodos']);
  });
  fuente.addEventListener('trabajo', ev => {
    const d = JSON.parse(ev.data);
    telegrama(`${d.nodo} está procesando`, d.mensaje, 'alerta');
  });
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
  // No redibujamos Operar ni el Verificador para no borrar lo que el usuario escribió.
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
  const [id, bitacora, llaves] = await Promise.all([
    api.get('/api/local/identidad'), api.get('/api/local/bitacora?limite=150'), api.get('/api/local/llaves')]);
  actualizarContador(id.pendientes);
  const c = id.certificado;

  // Agrupa la bitácora por rally (cada pelota de ping-pong tiene su rallyId).
  const rallies = new Map();
  const golpes = ['recepcion', 'envio', 'rebote', 'rechazo-automatico'];
  [...bitacora].reverse().forEach(e => {
    if (!e.rallyId || e.salto == null || !golpes.includes(e.tipo)) return;
    if (!rallies.has(e.rallyId)) rallies.set(e.rallyId, []);
    rallies.get(e.rallyId).push(e);
  });
  const ultimos = [...rallies.entries()].slice(-5).reverse();
  const golpe = e => {
    const tipo = e.tipo === 'recepcion' ? 'entra' : e.tipo === 'rechazo-automatico' ? 'mal' : 'sale';
    return `<span class="golpe golpe--${tipo}" title="${esc(e.mensaje)}"><span class="golpe__bola">${e.salto}</span><span class="golpe__red"></span></span>`;
  };

  pintar(`
    <div class="encabezado">
      <div>
        <span class="etiqueta">Mesa de control · protocolo v${esc(id.protocolo)}</span>
        <h1>Panel del ${esc(id.nodoId)}</h1>
        <p>Proveedor de ${id.provee.length ? id.provee.map(chipAlg).join(' ') : 'ningún algoritmo (solo solicitante)'} para el Centro de Ciberseguridad. Los demás algoritmos se delegan a su dueño.</p>
      </div>
      <a class="btn btn--grande" href="#/operar">✉ Cifrar / operar</a>
    </div>

    <div class="rejilla rejilla--4" style="margin-bottom:18px">
      <a class="hoja cifra cifra--sello" href="#/solicitudes" style="text-decoration:none;color:inherit">
        <span class="etiqueta">Solicitudes pendientes</span><b>${id.pendientes}</b></a>
      <a class="hoja cifra cifra--verde" href="#/consultas" style="text-decoration:none;color:inherit">
        <span class="etiqueta">Registros en Consultas</span><b>${id.consultas}</b></a>
      <a class="hoja cifra" href="#/nodos" style="text-decoration:none;color:inherit">
        <span class="etiqueta">Nodos en línea</span><b>${id.nodos}</b></a>
      <div class="hoja cifra"><span class="etiqueta">Dirección en la LAN</span>
        <b style="font:600 19px var(--f-mono);margin-top:12px">${esc(id.direccion)}</b>
        <span class="ayuda">UDP ${id.udp.puerto}: ${id.udp.activo ? `anunciando cada ${id.udp.intervalo} s · ${id.udp.recibidos} anuncios oídos` : 'apagado o bloqueado'}</span></div>
    </div>

    <div class="rejilla rejilla--panel">
      <section class="hoja credencial" aria-labelledby="t-cred">
        <div class="hoja__titulo"><h2 id="t-cred">Credencial del nodo</h2><span class="etiqueta">Identidad X.509 (sección 7)</span></div>
        <div class="cert">
          <span class="cert__tipo cert__tipo--rsa">ID</span>
          <div>
            <strong>${esc(c.sujeto)}</strong>
            <small>${esc(c.llave)} · ${esc(c.firmaCertificado)} · manifiestos ${esc(c.firmaManifiestos)} · vigente hasta ${new Date(c.hasta).toLocaleDateString('es-MX')}</small>
            <div class="hash" title="Huella SHA-256 del certificado (DER)">${huellaLegible(c.huella)}</div>
          </div>
          <a class="btn btn--sec btn--chico" href="/api/local/certificado" download>.pem</a>
        </div>
        <p class="ayuda" style="margin-top:10px">Esta huella es la que los demás equipos deben confirmar (TOFU). Si la regeneras, verán una alerta.</p>
        <div class="cajon__seccion"><span class="etiqueta">Llaves de algoritmo (keyId) · ${id.llaves}</span>
          ${llaves.length ? `<ul class="bitacora" style="max-height:180px">${llaves.slice(0, 12).map(k => `
            <li><time>${esc(k.algoritmo)}</time><span class="mono" title="${k.restringida ? 'Solo: ' + esc(k.permitidos) : 'Cualquier nodo'}">${esc(k.keyId)}${k.restringida ? ' 🔒' : ''}</span></li>`).join('')}</ul>`
            : '<p class="ayuda">Aún no hay llaves: se crea una por cada forward RSA/ECC sin keyId.</p>'}
        </div>
      </section>

      <section class="hoja" aria-labelledby="t-rally">
        <div class="hoja__titulo"><h2 id="t-rally">Ping-pong</h2><span class="etiqueta">Últimos rallies</span></div>
        ${ultimos.length ? ultimos.map(([rid, eventos]) => `
          <div class="rally">
            <div class="rally__cab"><span>Rally <code>${esc(rid.slice(0, 8))}</code></span><span>${eventos.length} ${eventos.length === 1 ? 'golpe' : 'golpes'} · ${fecha(eventos.at(-1).fechaUtc, false)}</span></div>
            <div class="mesa">${eventos.map(golpe).join('')}</div>
          </div>`).join('') : `<div class="vacio"><strong>Aún no hay pelotas en juego</strong>Cifra con RSA o ECC y mándalo a la bandeja de otro nodo.</div>`}
        <div class="leyenda"><span><i class="l-sale"></i>sale de este nodo</span><span><i class="l-entra"></i>llega a este nodo</span><span>el número es el rebote</span></div>
      </section>
    </div>

    <section class="hoja" style="margin-top:18px" aria-labelledby="t-bit">
      <div class="hoja__titulo"><h2 id="t-bit">Bitácora</h2><span class="etiqueta">En tiempo real · sin secretos</span></div>
      <ul class="bitacora">
        ${bitacora.slice(0, 50).map(e => `<li><time>${fecha(e.fechaUtc, false)}</time><span class="t-${esc(e.tipo)}">${esc(e.mensaje)}</span></li>`).join('')}
      </ul>
    </section>`);
};

/* ===== Operar (forward con cualquiera de los 21 algoritmos) ===== */

/**
 * Campos de parámetros para un algoritmo. Si el dueño publica su perfil
 * (GET /api/algorithms, sección 10.4) se usa; si no, el mínimo de la tabla 4.2.
 */
function camposParametros(alg, perfil) {
  const secretos = perfil?.secretParameters?.length ? perfil.secretParameters
    : (alg.secretos || []).map(n => ({ name: n, type: 'texto' }));
  const opciones = (perfil?.options || []).filter(o => !['hop', 'rallyId'].includes(o.name));
  const campoSecreto = s => `
    <label class="campo"><span class="etiqueta">${esc(s.name)} · secreto${alg.llave === 'SecretaOpcional' ? ' (opcional)' : ''}</span>
      <input type="password" data-secreto="${esc(s.name)}" autocomplete="off" placeholder="${esc(s.type || '')}${s.minBytes ? ' · mín. ' + s.minBytes + ' bytes' : ''}">
    </label>`;
  const campoOpcion = o => Array.isArray(o.values) && o.values.length
    ? `<label class="campo"><span class="etiqueta">${esc(o.name)}</span><select data-opcion="${esc(o.name)}">
        ${o.values.map(v => `<option ${v === o.default ? 'selected' : ''}>${esc(v)}</option>`).join('')}</select></label>`
    : `<label class="campo"><span class="etiqueta">${esc(o.name)}${o.required ? '' : ' (opcional)'}</span>
        <input type="text" data-opcion="${esc(o.name)}" value="${esc(o.default || '')}" placeholder="${esc(o.description || '')}"></label>`;
  return `
    ${alg.llave === 'KeyId' ? `
      <label class="campo"><span class="etiqueta">keyId (opcional)</span>
        <input type="text" data-keyid style="font-family:var(--f-mono)" placeholder="vacío = ${esc(alg.dueno)} genera una llave nueva">
        <span class="ayuda">La llave la guarda el dueño del algoritmo. Para reutilizar una, pega su keyId (EQ03-KEY-…).</span></label>` : ''}
    ${secretos.map(campoSecreto).join('')}
    ${opciones.map(campoOpcion).join('')}
    ${alg.codigo === 'LSBSTEGO' ? `<label class="campo"><span class="etiqueta">Imagen portadora (cover) PNG/BMP</span><input type="file" data-cover accept=".png,.bmp,image/png,image/bmp"></label>` : ''}
    ${secretos.length ? '<p class="ayuda">Los secretos viajan cifrados en un sobre CC-ENV-1 solo para el dueño; este nodo no los guarda.</p>' : ''}
    ${!secretos.length && !opciones.length && alg.llave !== 'KeyId' ? '<p class="ayuda">Este algoritmo no necesita parámetros.</p>' : ''}`;
}

/** Lee los campos de parámetros del formulario. */
function leerParametros(raiz) {
  const secretos = {}, opciones = {};
  $$('[data-secreto]', raiz).forEach(i => { if (i.value) secretos[i.dataset.secreto] = i.value; });
  $$('[data-opcion]', raiz).forEach(i => { if (i.value) opciones[i.dataset.opcion] = i.value; });
  return { secretos, opciones, keyId: $('[data-keyid]', raiz)?.value.trim() || '', cover: $('[data-cover]', raiz)?.files[0] };
}

pantallas.operar = async (refresco) => {
  if (refresco) return;
  const [algoritmos, nodos] = await Promise.all([api.get('/api/local/algoritmos'), api.get('/api/local/nodos').catch(() => [])]);
  const inicial = algoritmos.find(a => a.propio && a.disponible) || algoritmos.find(a => a.disponible) || algoritmos[0];

  pintar(`
    <div class="encabezado"><div>
      <span class="etiqueta">Roles emisor y solicitante · forward</span>
      <h1>Cifrar / operar</h1>
      <p>Elige cualquiera de los 21 algoritmos. RSA y ECC se ejecutan aquí; los demás se le piden a su dueño con <code>/api/crypto/forward</code>. El resultado es un <code>.zip</code> v2.0 que puedes mandar a la bandeja de otro nodo.</p>
    </div></div>

    <form class="hoja" id="form-op" novalidate>
      <div class="paso">
        <span class="paso__num">1</span>
        <div>
          <h2>¿Qué vas a procesar?</h2>
          <div class="segmentos" role="radiogroup" aria-label="Tipo de contenido">
            <label><input type="radio" name="modo" value="text" checked><span>Frase</span></label>
            <label><input type="radio" name="modo" value="image"><span>Imagen</span></label>
            <label><input type="radio" name="modo" value="file"><span>Archivo</span></label>
          </div>
          <div id="caja-texto">
            <label class="campo"><span class="etiqueta">Mensaje</span>
              <textarea name="texto" placeholder="Ej. CURP: VERA040101HDFLMR09 — información de prueba"></textarea></label>
            <p class="ayuda" id="cuenta-texto">0 bytes</p>
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
          <div class="algoritmos algoritmos--21">
            ${algoritmos.map(a => `
              <label class="algoritmo ${a.disponible ? '' : 'algoritmo--no'}" title="${esc(a.motivo)}">
                <input type="radio" name="algoritmo" value="${esc(a.codigo)}" ${a.codigo === inicial.codigo ? 'checked' : ''}>
                <div><span class="etiqueta">#${a.id} · ${esc(a.dueno)}</span><b>${esc(a.codigo)}</b>
                  <small>${esc(a.nombre)}</small>
                  <small class="algoritmo__estado">${a.propio ? '● local' : a.disponible ? '● ' + esc(a.ejecutor) : '○ no disponible'}</small></div></label>`).join('')}
          </div>
          <p class="ayuda" id="motivo-alg" style="margin-top:10px"></p>
        </div>
      </div>

      <div class="paso">
        <span class="paso__num">3</span>
        <div>
          <h2>Parámetros</h2>
          <div id="parametros"></div>
        </div>
      </div>

      <div class="acciones" style="margin-top:26px;justify-content:flex-end">
        <button class="btn btn--grande" type="submit" id="btn-op">Ejecutar forward</button>
      </div>
    </form>
    <div id="acuse"></div>`);

  const form = $('#form-op');
  const modoActual = () => form.modo.value;
  const algActual = () => algoritmos.find(a => a.codigo === form.algoritmo.value);

  async function alCambiarAlgoritmo() {
    const a = algActual();
    $('#motivo-alg').innerHTML = `<strong>${esc(a.codigo)}</strong> (${esc(a.forward)} / ${esc(a.inverse)}) · ${esc(a.motivo)}`;
    $('#btn-op').textContent = `${a.forward[0].toUpperCase() + a.forward.slice(1)} con ${a.codigo}`;
    $('#btn-op').disabled = !a.disponible;
    $('#parametros').innerHTML = camposParametros(a, null);
    if (!a.disponible) return;
    try {
      const p = await api.get(`/api/local/perfil/${a.codigo}`);
      if (form.algoritmo.value === a.codigo && p.perfil) $('#parametros').innerHTML = camposParametros(a, p.perfil);
    } catch { /* sin perfil: se queda el mínimo de la tabla 4.2 */ }
  }

  form.addEventListener('change', e => {
    if (e.target.name === 'modo') {
      $('#caja-texto').hidden = modoActual() !== 'text';
      $('#caja-archivo').hidden = modoActual() === 'text';
      $('#archivo').accept = modoActual() === 'image' ? 'image/*' : '';
    }
    if (e.target.name === 'algoritmo') alCambiarAlgoritmo();
  });
  form.texto.addEventListener('input', () => {
    $('#cuenta-texto').textContent = `${new TextEncoder().encode(form.texto.value).length} bytes (UTF-8)`;
  });

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

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const a = algActual();
    const p = leerParametros(form);
    const fd = new FormData();
    fd.append('modo', modoActual());
    fd.append('algoritmo', a.codigo);
    fd.append('opciones', JSON.stringify(p.opciones));
    fd.append('secretos', JSON.stringify(p.secretos));
    if (p.keyId) fd.append('keyId', p.keyId);
    if (p.cover) fd.append('cover', p.cover);
    if (modoActual() === 'text') {
      if (!form.texto.value.trim()) return telegrama('Falta el mensaje', 'Escribe una frase.', 'alerta');
      fd.append('texto', form.texto.value);
    } else {
      if (!entrada.files[0]) return telegrama('Falta el archivo', 'Elige una imagen o archivo.', 'alerta');
      fd.append('archivo', entrada.files[0]);
    }
    const boton = $('#btn-op'), texto = boton.textContent;
    boton.disabled = true; boton.textContent = a.propio ? 'Procesando y firmando…' : `Pidiendo a ${a.ejecutor}…`;
    try {
      const r = await api.post('/api/local/forward', fd);
      const c = r.consulta;
      $('#acuse').innerHTML = `
        <div class="acuse"><span class="sello sello--ok">${r.delegado ? 'Delegado' : 'Local'} · ${esc(r.ejecutor)}</span>
          <span class="etiqueta">Acuse · Consultas (Generado)</span><h2>${esc(a.forward)} con ${esc(a.codigo)} listo</h2>
          <dl>
            <dt>Paquete</dt><dd class="mono">${esc(c.nombreZip)}</dd>
            <dt>Productor</dt><dd>${esc(c.nodoProductor)}</dd>
            <dt>SHA-256 datos.enc</dt><dd>${hashHtml(c.sha256)}</dd>
          </dl>
          <form class="acciones" id="f-mandar">
            <input type="text" name="destino" list="dl-nodos" placeholder="EQ05 o 192.168.1.20:5005" required style="flex:1 1 220px;font-family:var(--f-mono)">
            <datalist id="dl-nodos">${nodos.map(n => `<option value="${esc(n.nodeId)}">${esc(n.direccion)}</option>`).join('')}</datalist>
            <button class="btn" type="submit">Mandar a su bandeja</button>
          </form>
          <div class="acciones" style="margin-top:10px">
            <a class="btn btn--sec" href="/api/local/consultas/${encodeURIComponent(c.id)}/zip" download>Descargar .zip</a>
            <a class="btn btn--sec" href="#/consultas/${encodeURIComponent(c.id)}">Ver en Consultas</a>
          </div>
        </div>`;
      $('#f-mandar').addEventListener('submit', ev => mandarABandeja(ev, c.id));
      $('#acuse').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
      telegrama('No se pudo', err.message, 'mal');
      $('#acuse').innerHTML = `<div class="acuse"><span class="sello sello--mal">Error</span><span class="etiqueta">Acuse</span><h2>${esc(err.message)}</h2></div>`;
    } finally {
      boton.disabled = false; boton.textContent = texto;
    }
  });

  alCambiarAlgoritmo();
};

/** Envía un registro de Consultas a la bandeja de otro nodo (reempaquetado 9.6). */
async function mandarABandeja(ev, consultaId) {
  ev.preventDefault();
  const boton = ev.target.querySelector('button');
  boton.disabled = true;
  try {
    const x = await api.post(`/api/local/consultas/${consultaId}/enviar`, { destino: ev.target.destino.value.trim() });
    telegrama(x.ok ? 'Entregado' : 'No se entregó', x.mensaje, x.ok ? 'ok' : 'mal');
  } catch (err) { telegrama('No se entregó', err.message, 'mal'); }
  boton.disabled = false;
}

/* ===== Solicitudes (bandeja del rol Receptor) ===== */
let filtroSolicitudes = 'Pendiente';
pantallas.solicitudes = async () => {
  const lista = await api.get('/api/local/solicitudes' + (filtroSolicitudes ? `?estado=${filtroSolicitudes}` : ''));
  const filtros = [['Pendiente', 'Pendientes'], ['Aceptada', 'Aceptadas'], ['Rechazada', 'Rechazadas'], ['', 'Todas']];

  pintar(`
    <div class="encabezado"><div>
      <span class="etiqueta">Rol receptor · POST /api/requests/receive</span>
      <h1>Solicitudes</h1>
      <p>Paquetes que llegaron por la red. El nodo ya pasó las 14 validaciones de la sección 13.1; tú decides si entran a Consultas.</p>
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
              <span>De <strong>${esc(s.nodoOrigen)}</strong>${s.nodoProductor && s.nodoProductor !== s.nodoOrigen ? ` (producido por ${esc(s.nodoProductor)})` : ''}</span>
              <span>IP <code>${esc(s.origenIp)}</code></span>
              <span>${chipAlg(s.algoritmoCodigo)} ${esc(s.operacionNombre)}</span>
              <span>${esc(nombreModo(s.modo))} · ${esc(s.nombreOriginal)} · ${tamano(s.tamanoOriginal)}</span>
              ${s.salto ? `<span>Rebote #${s.salto}</span>` : ''}
            </div>
            ${s.verificacion === 'Inválida' ? `<p class="ayuda" style="color:var(--sello);margin-top:6px">${esc(s.detalle)}</p>` : ''}
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
        </article>`).join('') : `<div class="vacio"><strong>Bandeja vacía</strong>Cuando otro nodo envíe un paquete a este, aparecerá aquí con una alerta.</div>`}
    </div>`);

  $$('[data-filtro]').forEach(b => b.addEventListener('click', () => { filtroSolicitudes = b.dataset.filtro; pantallas.solicitudes(); }));
  $$('[data-aceptar]').forEach(b => b.addEventListener('click', async () => {
    b.disabled = true;
    try {
      const r = await api.post(`/api/local/solicitudes/${b.dataset.aceptar}/aceptar`);
      telegrama('Aceptada', 'Se guardó en Consultas (Recibido).', 'ok', `#/consultas/${r.consultaId}`);
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

/* ===== Consultas ===== */
pantallas.consultas = async (refresco, extra = []) => {
  const lista = await api.get('/api/local/consultas');
  pintar(`
    <div class="encabezado"><div>
      <span class="etiqueta">Base de datos local</span>
      <h1>Consultas</h1>
      <p><b>Generado</b>: forward propio o delegado · <b>Recibido</b>: aceptado de la bandeja · <b>Resultado</b>: devuelto por un inverse. Abre un registro para descargarlo, hacer el inverse, mandarlo a otro nodo o ver su manifiesto.</p>
    </div></div>
    ${lista.length ? `
    <div class="tabla-envoltura"><table>
      <thead><tr><th>Fecha</th><th>Origen</th><th>Paquete</th><th>Productor</th><th>Contenido</th><th>Validación</th></tr></thead>
      <tbody>
        ${lista.map(c => `
          <tr data-id="${esc(c.id)}" tabindex="0">
            <td>${fecha(c.fechaUtc)}</td>
            <td><span class="origen origen--${esc(c.origen)}">${esc(c.origen)}</span>${c.salto ? ` <span class="ayuda">#${c.salto}</span>` : ''}</td>
            <td class="td-zip">${esc(c.nombreZip)}</td>
            <td>${esc(c.nodoProductor)}</td>
            <td>${chipAlg(c.algoritmoCodigo)} ${esc(c.operacionNombre)} · ${esc(nombreModo(c.modo))}</td>
            <td>${selloVerif(c.verificacion)}${c.resultadoEnvio ? `<div class="ayuda">→ ${esc(c.nodoRemoto)}: ${esc(c.resultadoEnvio)}</div>` : ''}</td>
          </tr>`).join('')}
      </tbody></table></div>` : `<div class="vacio"><strong>Sin registros</strong>Acepta una solicitud o ejecuta un forward para empezar.</div>`}`);

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
      <span class="etiqueta">Herramienta · sección 13.1</span>
      <h1>Verificador de paquetes</h1>
      <p>Revisa cualquier <code>.zip</code> v2.0 (de cualquier equipo y algoritmo) sin registrarlo: estructura, manifiesto, hash, parámetros canónicos, certificado, huella, firma y fecha. Te dice el código de error exacto del Anexo B.</p>
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
      const sello = r.valido
        ? selloVerif(r.confianza && r.confianza.startsWith('E-') ? 'Inválida' : r.confianza || 'Firma OK')
        : `<span class="sello sello--mal">${esc(r.codigo)} · ${r.status}</span>`;
      $('#reporte').innerHTML = `
        <div class="acuse">${sello}
          <span class="etiqueta">Reporte</span><h2 class="mono" style="font-size:15px;padding-right:150px;word-break:break-all">${esc(r.nombre)}</h2>
          <ul class="checks" style="margin-top:16px">
            <li class="${r.valido ? '' : 'mal'}">${esc(r.detalle)}</li>
            ${r.confianza ? `<li class="${r.confianza === 'Firma OK' ? '' : r.confianza.startsWith('E-') ? 'mal' : 'aviso'}">Confianza del remitente: ${esc(r.confianza)}</li>` : ''}
            <li class="${r.nombreValido ? '' : 'aviso'}">${r.nombreValido ? 'Nombre con el formato 9.2' : 'El nombre no sigue [RES_]EQnn_ALG_YYYYMMDD_HHMMSS_SHA8.zip (es solo informativo)'}</li>
          </ul>
          ${r.certificado ? bloqueCertificado(r.certificado) : ''}
          ${r.cadenaFirma ? `<div class="cajon__seccion"><span class="etiqueta">Cadena de firma (8.4)</span><pre class="json">${esc(r.cadenaFirma)}</pre></div>` : ''}
          ${r.parametrosCanonicos != null ? `<div class="cajon__seccion"><span class="etiqueta">publicParameters canónicos (8.5)</span><pre class="json">${esc(r.parametrosCanonicos || '(vacío)')}</pre></div>` : ''}
          ${r.manifiesto ? `<div class="cajon__seccion"><span class="etiqueta">manifest.json</span><pre class="json">${esc(JSON.stringify(r.manifiesto, null, 2))}</pre></div>` : ''}
        </div>`;
    } catch (e) { $('#reporte').innerHTML = `<p class="ayuda">${esc(e.message)}</p>`; }
  }
};

/* ===== Nodos (directorio, sección 6) ===== */
pantallas.nodos = async () => {
  const lista = await api.get('/api/local/nodos');
  const estadoNodo = n => n.alerta ? '<span class="sello sello--mal sello--plano">¡Huella cambió!</span>'
    : !n.huellaFijada ? '<span class="sello sello--pend sello--plano">Sin confirmar</span>'
      : n.estado === 'online' ? '<span class="sello sello--ok sello--plano">En línea</span>'
        : '<span class="sello sello--info sello--plano">Fuera de línea</span>';
  pintar(`
    <div class="encabezado"><div>
      <span class="etiqueta">Conectividad entre dispositivos · anuncio UDP 5099 + escaneo + alta manual</span>
      <h1>Directorio de nodos</h1>
      <p>Los nodos aparecen solos por el anuncio UDP. Antes de usarlos se verifica <code>/api/status</code> y <code>/api/certificate</code>; tú confirmas la huella una vez (TOFU) y queda fijada.</p>
    </div>
    <button class="btn btn--sec" id="buscar">⟳ Buscar nodos (/24, puertos 5001–5020)</button></div>
    <form class="hoja acciones" id="form-nodo" style="align-items:flex-end">
      <label style="flex:1 1 260px"><span class="etiqueta">Alta manual · IP:Puerto</span>
        <input type="text" name="destino" placeholder="192.168.1.20:5005" required style="font-family:var(--f-mono);margin-top:6px"></label>
      <button class="btn" type="submit">Agregar y verificar</button>
    </form>
    <div style="margin-top:18px">
    ${lista.length ? `<div class="tabla-envoltura"><table>
      <thead><tr><th>Nodo</th><th>Dirección</th><th>Estado</th><th>Algoritmos</th><th>Fuente · visto</th><th>Huella</th><th></th></tr></thead>
      <tbody>${lista.map(n => `
        <tr>
          <td><strong>${esc(n.nodeId)}</strong><div class="ayuda">Equipo ${n.equipo}</div></td>
          <td class="mono">${esc(n.direccion)}</td>
          <td>${estadoNodo(n)}</td>
          <td>${n.algoritmos.length ? n.algoritmos.map(chipAlg).join(' ') : '<span class="ayuda">ninguno</span>'}</td>
          <td>${esc(n.fuente)}<div class="ayuda">${fecha(n.vistoUtc)}</div></td>
          <td><div class="hash" style="max-width:230px">${huellaLegible(n.huellaPresentada)}</div>
            ${n.alerta ? `<div class="ayuda" style="color:var(--sello)">Fijada: ${huellaLegible(n.huellaFijada)}</div>` : ''}</td>
          <td><div class="acciones" style="justify-content:flex-end">
            ${!n.huellaFijada || n.alerta ? `<button class="btn btn--ok btn--chico" data-confirmar="${esc(n.nodeId)}">${n.alerta ? 'Aceptar nueva huella' : 'Confirmar huella'}</button>` : ''}
            <button class="btn btn--sec btn--chico" data-probar="${esc(n.direccion)}">Verificar</button>
            <button class="btn btn--mal btn--chico" data-quitar="${esc(n.nodeId)}" aria-label="Quitar ${esc(n.nodeId)}">×</button></div></td>
        </tr>`).join('')}</tbody></table></div>`
      : `<div class="vacio"><strong>Sin nodos todavía</strong>Si la red bloquea el broadcast, usa “Buscar nodos” o el alta manual con la IP de cada equipo (ipconfig / ip a) y su puerto 5000 + número de equipo.</div>`}
    </div>`);

  $('#form-nodo').addEventListener('submit', async e => {
    e.preventDefault();
    try {
      const n = await api.post('/api/local/nodos', { destino: e.target.destino.value });
      telegrama(n.nodo, n.mensaje + ' Confirma su huella.', 'ok');
    } catch (err) { telegrama('No se pudo dar de alta', err.message, 'mal'); }
    pantallas.nodos();
  });
  $('#buscar').addEventListener('click', async ev => {
    ev.target.disabled = true; ev.target.textContent = 'Buscando… (puede tardar ~1 min)';
    try {
      const r = await api.post('/api/local/nodos/buscar');
      telegrama('Búsqueda terminada', `${r.encontrados} nodo(s) respondieron.`, r.encontrados ? 'ok' : 'alerta');
    } catch (err) { telegrama('Búsqueda', err.message, 'alerta'); }
    pantallas.nodos();
  });
  $$('[data-confirmar]').forEach(b => b.addEventListener('click', async () => {
    const n = lista.find(x => x.nodeId === b.dataset.confirmar);
    if (!confirm(`¿La huella de ${n.nodeId} es esta?\n\n${n.huellaPresentada.match(/.{1,4}/g).join(' ')}\n\nCompárala con la que muestra su Panel (en persona o por un canal confiable).`)) return;
    try { await api.post(`/api/local/nodos/${encodeURIComponent(n.nodeId)}/confirmar`); telegrama('Huella fijada', `${n.nodeId} ya es de confianza.`, 'ok'); }
    catch (err) { telegrama('No se confirmó', err.message, 'mal'); }
    pantallas.nodos();
  }));
  $$('[data-probar]').forEach(b => b.addEventListener('click', async () => {
    b.disabled = true;
    try { const n = await api.post('/api/local/nodos', { destino: b.dataset.probar }); telegrama(n.nodo, n.mensaje, 'ok'); }
    catch (err) { telegrama(b.dataset.probar, err.message, 'alerta'); }
    pantallas.nodos();
  }));
  $$('[data-quitar]').forEach(b => b.addEventListener('click', async () => {
    await api.del('/api/local/nodos/' + encodeURIComponent(b.dataset.quitar));
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
        <h2 style="margin-bottom:14px">Recepción y proveedor</h2>
        <label class="interruptor campo"><input type="checkbox" name="aceptandoPaquetes" ${a.aceptandoPaquetes ? 'checked' : ''}> Aceptar paquetes en la bandeja (<code>acceptingPackages</code>)</label>
        <span class="etiqueta" style="display:block;margin:16px 0 8px">Algoritmos propios que se atienden (forward / inverse)</span>
        <label class="interruptor"><input type="checkbox" name="alg" value="RSA" ${a.algoritmosHabilitados.includes('RSA') ? 'checked' : ''}> RSA</label>
        <label class="interruptor" style="margin-top:6px"><input type="checkbox" name="alg" value="ECC" ${a.algoritmosHabilitados.includes('ECC') ? 'checked' : ''}> ECC</label>
        <label class="interruptor" style="margin-top:16px"><input type="checkbox" name="adminRemoto" ${a.adminRemoto ? 'checked' : ''}> Administración remota (manejar el nodo desde el celular)</label>
        <p class="ayuda">Apagado, solo esta computadora puede aceptar, rechazar u operar. Enciéndelo solo en una red de confianza.</p>
      </section>
      <section class="hoja">
        <h2 style="margin-bottom:14px">Ping-pong</h2>
        <label class="interruptor campo"><input type="checkbox" name="rebotarAutomatico" ${a.rebotarAutomatico ? 'checked' : ''}> Rebotar automáticamente las pelotas RSA/ECC que lleguen a la bandeja</label>
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

function bloqueCertificado(c) {
  return `<div class="cajon__seccion"><span class="etiqueta">Certificado del remitente</span>
    <div class="hoja" style="padding:14px 16px;box-shadow:none">
      <strong>${esc(c.sujeto)}</strong>
      <div class="ayuda">Vigente del ${new Date(c.noAntes).toLocaleDateString('es-MX')} al ${new Date(c.noDespues).toLocaleDateString('es-MX')}</div>
      <div class="hash" style="margin-top:6px">${huellaLegible(c.huella)}</div>
    </div></div>`;
}

async function abrirSolicitud(id) {
  const r = await api.get(`/api/local/solicitudes/${id}`);
  const s = r.solicitud;
  abrirCajon(`
    <span class="etiqueta">Solicitud · ${esc(s.estado)}</span>
    <h2 class="mono" style="font-size:15px;margin:6px 40px 12px 0;word-break:break-all">${esc(s.nombreZip)}</h2>
    <div class="acciones">${selloVerif(s.verificacion)} ${selloEstado(s.estado)}</div>
    <div class="cajon__seccion"><span class="etiqueta">Validación 13.1</span><p>${esc(s.detalle)}</p></div>
    <div class="cajon__seccion"><span class="etiqueta">Remitente</span>
      <p>${esc(s.nodoOrigen)} desde <code>${esc(s.origenIp)}</code>; responde a <code>${esc(s.direccionRespuesta || '—')}</code><br>
      Productor: ${esc(s.nodoProductor)} · ${chipAlg(s.algoritmoCodigo)} ${esc(s.algoritmoNombre)} · ${esc(s.operacionNombre)}</p>
      <p class="ayuda">packetId ${esc(s.packetId)} · rally ${esc((s.rallyId || '').slice(0, 8))} · rebote #${s.salto}</p></div>
    ${r.manifiesto ? `<div class="cajon__seccion"><span class="etiqueta">manifest.json</span><pre class="json">${esc(JSON.stringify(r.manifiesto, null, 2))}</pre></div>` : ''}`);
}

async function abrirConsulta(id) {
  const [r, nodos] = await Promise.all([api.get(`/api/local/consultas/${id}`), api.get('/api/local/nodos').catch(() => [])]);
  const c = r.consulta, v = r.validacion;
  const alg = { llave: r.llave, secretos: r.secretos, codigo: c.algoritmoCodigo, dueno: r.ejecutorInverse || '—' };
  const necesitaSecretos = !r.esResultado && (r.secretos || []).length > 0;
  const nombreInverse = r.esResultado ? 'Abrir resultado' : `${c.operacion === 'forward' ? 'Inverse' : 'Operar'} (${esc(r.ejecutorInverse || '?')})`;
  abrirCajon(`
    <span class="etiqueta">Consulta · ${esc(c.origen)}</span>
    <h2 class="mono" style="font-size:15px;margin:6px 40px 12px 0;word-break:break-all">${esc(c.nombreZip)}</h2>
    <div class="acciones" style="margin-bottom:14px">${selloVerif(c.verificacion)} ${chipAlg(c.algoritmoCodigo)} <span class="ayuda">${esc(c.operacionNombre)} · productor ${esc(c.nodoProductor)}</span></div>
    <div class="acciones">
      <a class="btn btn--chico" href="/api/local/consultas/${encodeURIComponent(c.id)}/zip" download>Descargar .zip</a>
    </div>

    <div class="cajon__seccion"><span class="etiqueta">${r.esResultado ? 'Resultado cifrado para ' + esc(r.paraMi ? 'este nodo' : 'otro nodo') : 'Inverse (descifrar / verificar / extraer…)'}</span>
      <form id="f-inverse">
        ${necesitaSecretos ? camposParametros({ ...alg, secretos: r.secretos }, null).replace(/<p class="ayuda">Este algoritmo.*?<\/p>/, '') : ''}
        <div class="acciones">
          <button class="btn btn--sec btn--chico" type="submit" ${r.esResultado && !r.paraMi ? 'disabled' : ''}>${nombreInverse}</button>
          ${c.origen === 'Recibido' && !r.esResultado ? `<button class="btn btn--ok btn--chico" type="button" id="b-rebotar">Rebotar a ${esc(c.nodoOrigen)} ↩</button>` : ''}
        </div>
      </form>
    </div>
    <div id="claro"></div>

    <div class="cajon__seccion"><span class="etiqueta">Mandar a la bandeja de otro nodo (reenvío 9.6)</span>
      <form class="acciones" id="f-mandar">
        <input type="text" name="destino" list="dl-nodos-c" placeholder="EQ05 o IP:Puerto" required style="flex:1 1 180px;font-family:var(--f-mono)">
        <datalist id="dl-nodos-c">${nodos.map(n => `<option value="${esc(n.nodeId)}">${esc(n.direccion)}</option>`).join('')}</datalist>
        <button class="btn btn--sec btn--chico" type="submit">Mandar</button>
      </form>
      <p class="ayuda" style="margin-top:6px">Se conserva datos.enc, parámetros, keyRef y productor; cambia packetId, fecha, remitente (este nodo) y firma.</p></div>

    <div class="cajon__seccion"><span class="etiqueta">Validación (sin ventana de tiempo)</span>
      <ul class="checks"><li class="${v.valido ? '' : 'mal'}">${esc(v.codigo ? v.codigo + ': ' : '')}${esc(v.detalle)}</li></ul></div>
    ${v.certificado ? bloqueCertificado(v.certificado) : ''}
    <div class="cajon__seccion"><span class="etiqueta">Datos</span>
      <p>${esc(nombreModo(c.modo))} · ${esc(c.nombreOriginal)} · ${tamano(c.tamanoOriginal)} · ${fecha(c.fechaUtc)}<br>
      SHA-256: ${hashHtml(c.sha256)}</p>
      ${c.resultadoEnvio ? `<p>Último envío a ${esc(c.nodoRemoto)} <code>${esc(c.direccion)}</code>: <strong>${esc(c.resultadoEnvio)}</strong></p>` : ''}</div>
    <div class="cajon__seccion"><span class="etiqueta">Cadena de firma (8.4)</span><pre class="json">${esc(r.cadenaFirma)}</pre></div>
    <div class="cajon__seccion"><span class="etiqueta">manifest.json</span><pre class="json">${esc(JSON.stringify(r.manifiesto, null, 2))}</pre></div>`);

  $('#f-inverse').addEventListener('submit', async e => {
    e.preventDefault();
    const boton = e.target.querySelector('[type=submit]');
    boton.disabled = true;
    try {
      const d = await api.post(`/api/local/consultas/${id}/inverse`, { secretos: leerParametros(e.target).secretos });
      $('#claro').innerHTML = htmlClaro(d);
    } catch (err) { telegrama('No se pudo', err.message, 'mal'); }
    boton.disabled = false;
  });
  $('#b-rebotar')?.addEventListener('click', async ev => {
    ev.target.disabled = true;
    try {
      const x = await api.post(`/api/local/consultas/${id}/rebotar`, { secretos: leerParametros($('#f-inverse')).secretos });
      telegrama(x.ok ? 'Pelota regresada' : 'No se pudo regresar', x.mensaje, x.ok ? 'ok' : 'mal');
    } catch (e) { telegrama('No se pudo rebotar', e.message, 'mal'); }
    ev.target.disabled = false;
  });
  $('#f-mandar').addEventListener('submit', ev => mandarABandeja(ev, id));
}

/* ------------------------------------------------------------------ Arranque */

(async function iniciar() {
  try {
    const id = await api.get('/api/local/identidad');
    nodoActual = id.nodoId;
    $('#nodo-id').textContent = id.nodoId;
    $('#nodo-dir').textContent = id.direccion;
    $('.sello-mini').textContent = String(id.equipo).padStart(2, '0');
    actualizarContador(id.pendientes);
  } catch (e) {
    pintar(`<div class="vacio"><strong>Acceso restringido</strong>${esc(e.message)}</div>`);
    return;
  }
  window.addEventListener('hashchange', navegar);
  conectarEventos();
  navegar();
})();

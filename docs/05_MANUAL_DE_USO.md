# 5. Manual de uso y guion de demo (estándar v2.0)

## 5.1 Pantallas

| Pantalla | Para qué |
| --- | --- |
| **Panel** | Credencial del nodo (sujeto y huella del certificado, descarga del `.pem`), llaves `keyId`, contadores, estado del anuncio UDP, rallies de ping-pong y bitácora en vivo. |
| **Operar** | Forward con **cualquiera de los 21 algoritmos**: contenido (frase, imagen o archivo) → algoritmo (cada tarjeta dice si es local, a quién se delega o por qué no está disponible) → parámetros (se arman con el perfil `/api/algorithms` del dueño; secretos en campos de contraseña) → acuse con el zip y el botón **Mandar a su bandeja**. |
| **Solicitudes** | Bandeja: remitente, IP, zip, algoritmo, `operationName` y sello **Firma OK** / **Remitente no confirmado** / **Inválida** (con el código de error). **Aceptar** / **Rechazar** / **Detalle** (manifiesto). |
| **Consultas** | Orígenes **Generado**, **Recibido** y **Resultado**. Panel lateral: descargar, **Inverse** (local o delegado; pide los secretos si el algoritmo los usa), **Rebotar**, **Mandar a otro nodo** (reenvío 9.6), cadena de firma y manifiesto. |
| **Verificador** | Arrastra cualquier `.zip` v2.0 y te da el código exacto del Anexo B, la cadena 8.4 y los parámetros canónicos 8.5. |
| **Nodos** | Directorio: los nodos llegan solos por UDP; **Buscar nodos** (escaneo) y **alta manual**. **Confirmar huella** (TOFU) y alerta roja si cambia. |
| **Ajustes** | Aceptar paquetes, algoritmos propios habilitados, ping-pong automático (máximo y pausa), administración remota, sonido y notificaciones. |

**Alertas.** Al llegar un paquete: timbre, aviso, contador rojo, título de la pestaña y notificación del sistema (si se dio
permiso). También avisa cuando aparece un nodo nuevo o cuando un nodo cambia de certificado.

## 5.2 Preparación el día de la presentación

1. Todas las computadoras en la **misma red** (router o hotspot propio; las redes escolares suelen bloquear broadcast).
2. `dotnet run --project src/Nodo03.Web -c Release` → `http://localhost:5003`. Permitir **Redes privadas** en el firewall
   (TCP 5003 y UDP 5099).
3. Si la consola muestra una IP rara (VirtualBox, WSL), arrancar con `--Nodo:IpPublica=192.168.x.x`.
4. En **Nodos**: esperar los anuncios (≤ 30 s) o **Buscar nodos**; comparar en persona la huella de cada equipo con su
   Panel y **Confirmar**.
5. Dar a los demás nuestra huella (Panel) para que nos confirmen.

## 5.3 Guion de demo (8 minutos)

1. **Descubrimiento.** Abrir Nodos: aparecen los equipos por UDP; confirmar una huella.
2. **Algoritmo propio.** Operar → Frase → RSA → acuse con `EQ03_RSA_…zip` y su `keyId`. Descargar el zip y mostrar los
   3 archivos; `python herramientas/verificar_paquete.py <zip>` → VÁLIDO desde Python.
3. **Delegación.** Operar → AESGCM (dueño EQ01) con su clave → el acuse dice "Delegado · EQ01".
4. **Bandeja.** Mandar el paquete a la bandeja del vecino; que el vecino nos mande uno: suena la alerta, sello **Firma OK**.
5. **Inverse.** Aceptar → Consultas → Inverse: si es RSA/ECC se hace aquí; si es de otro equipo, se le pide a su dueño y
   regresa como **Resultado** cifrado para nosotros.
6. **Ataque.** Cambiar un byte de `datos.enc` y subirlo al Verificador → `E-HASH`; cambiar `producerNode` → `E-SIGNATURE`;
   reenviar el mismo zip → `409 E-DUPLICATE`.
7. **Ping-pong automático** (EQ03 ↔ otro nodo, o EQ03 ↔ EQ13 local): activar en Ajustes y ver el rally en el Panel.
8. **Interoperabilidad y pruebas.** `python herramientas/cliente_v2.py <IP>:5003 "Hola"` y `dotnet test` → 102 en verde.

## 5.4 Problemas comunes

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| No aparecen nodos | La red bloquea broadcast o el firewall bloquea UDP 5099 | **Buscar nodos** o alta manual; abrir UDP 5099 |
| "Confirma la huella de EQxx" | Nodo encontrado pero sin TOFU | Nodos → Confirmar huella |
| "EQxx presenta una huella distinta" | Regeneró su certificado (o alguien lo suplanta) | Verificar en persona y **Aceptar nueva huella** |
| `E-TIMESTAMP` | Relojes desfasados más de 10 min | Sincronizar la hora (Windows: Configuración → Hora → Sincronizar ahora) |
| `E-CERT-UNTRUSTED` (403) al mandar | El otro nodo tiene fijada otra huella nuestra | Que nos vuelva a confirmar |
| `E-BUSY` (503) | El nodo no acepta paquetes o hay 10 operaciones en curso | Revisar Ajustes / reintentar |
| 403 al abrir la interfaz desde el celular | Administración remota apagada | Activarla en Ajustes desde la PC |
| Se perdieron las llaves `keyId` | Se borró o cambió la carpeta `datos` | Copiar `datos` completa (nunca subirla a GitHub) |
| `DllNotFoundException: sqlite` en Linux | Falta la librería del sistema | `sudo apt install libsqlite3-0` |

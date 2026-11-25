# 1. Arquitectura

## 1.1 Cómo se cubren los puntos del pizarrón

| Punto | Decisión en el Nodo 03 |
| --- | --- |
| **Arquitectura de software** | Dos capas: `Nodo03.Core` (dominio: protocolo, criptografía, datos) y `Nodo03.Web` (transporte HTTP + interfaz). El núcleo no sabe que existe la web; se prueba solo. |
| **Bases de datos** | SQLite local (un archivo `datos/nodo03.db`), modo WAL, consultas parametrizadas. Tablas `solicitudes`, `consultas`, `bitacora`, `nodos`, `ajustes`. |
| **Lenguaje de programación** | C# 12 sobre .NET 8 (acuerdo del grupo). JavaScript estándar en el navegador. |
| **APIs** | API REST del protocolo (`/api/status`, `/api/requests/receive`, extensión `/api/certificate`) y API REST local para la interfaz (`/api/local/...`). |
| **Web services** | Servicios HTTP/JSON sobre Kestrel; alertas en tiempo real por Server-Sent Events (`/api/local/eventos`). |
| **Conectividad entre dispositivos** | Cada nodo escucha en `0.0.0.0:5000` dentro de la LAN; descubrimiento por `GET /api/status`; directorio de nodos conocidos; administración desde el celular opcional. |

## 1.2 Componentes

```
                         ┌───────────────────────── Nodo03.Web ─────────────────────────┐
 Otros nodos ──HTTP──▶   │ ProtocoloEndpoints ─▶ ServicioRecepcion ─▶ MotorPingPong      │
 (cualquier lenguaje)    │   /api/status           valida, guarda,      (cola en         │
                         │   /api/requests/receive  alerta              segundo plano)   │
                         │   /api/certificate                                │           │
 Navegador (PC/cel) ──▶  │ LocalEndpoints ───▶ ServicioEnvio ──▶ ClienteNodos ──HTTP──▶ otros nodos
                         │   /api/local/...        arma y manda      (HttpClient único)  │
                         │ BusEventos (SSE) ──▶ alertas en vivo al navegador             │
                         └──────────────┬────────────────────────────────────────────────┘
                                        │ usa
                         ┌──────────────▼──────────── Nodo03.Core ───────────────────────┐
                         │ Servicios/ServicioPaquetes   Armar (cifrar+firmar+zip) / Abrir │
                         │ Cripto/  IdentidadNodo · CifradorRsa · CifradorEcc ·           │
                         │          FirmaManifiesto · Huellas                             │
                         │ Protocolo/ Manifiesto · NombrePaquete · EmpaquetadorZip ·      │
                         │            ValidadorPaquete · CodigosAlgoritmo                 │
                         │ Datos/  BaseDatos (SQLite P/Invoke) · RepositorioNodo          │
                         └────────────────────────────────────────────────────────────────┘
```

Todas las piezas de `Nodo03.Web` se registran como *singleton* en `NodoHost.Crear()`: un nodo es una identidad y una base. `NodoHost` está separado de `Program.cs` para que las pruebas levanten varios nodos reales en el mismo proceso.

## 1.3 Flujo de recepción (Modo Receptor)

1. `POST /api/requests/receive` llega con `multipart/form-data`, campo `package`.
2. Si el cuerpo declara más del límite → **413** sin leerlo.
3. `ServicioRecepcion` espera turno en un semáforo (2 × núcleos) para no saturar memoria.
4. `EmpaquetadorZip.Leer` revisa estructura → **400** si no cumple.
5. Si el `packetId` ya existe → **202** con `duplicate: true` (idempotente).
6. `ValidadorPaquete` revisa SHA-256, huella y firma → si falla, se guarda como `Rechazada`/`Inválida` y responde **422**.
7. Se guarda como `Pendiente`, se escribe en la bitácora y `BusEventos` avisa a los navegadores abiertos → **202**.
8. Si el ping-pong automático está encendido y la pelota es para este nodo, se encola en `MotorPingPong`.

## 1.4 Flujo de envío (Modo Emisor)

1. La pantalla Enviar manda el contenido a `POST /api/local/enviar`.
2. `ServicioEnvio` resuelve la llave pública del destinatario: la pide a `/api/certificate` del destino, la toma del directorio de nodos, la sube el usuario (`.pem`) o usa la propia.
3. `ServicioPaquetes.Armar` cifra, arma el manifiesto, firma y crea el zip con nombre oficial.
4. Se guarda en `datos/paquetes/enviados/` y en `consultas` con origen `Enviado` o `Generado`.
5. `ClienteNodos` hace el `POST` con cabeceras `X-Source-Node` y `X-Packet-Id`; el código de respuesta se guarda y se muestra en el acuse.

## 1.5 Base de datos

```
solicitudes ─────────────┐ 1
  id (PK)                │
  packet_id (UNIQUE)     │   ← evita duplicados aun con peticiones simultáneas
  estado CHECK(Pendiente|Aceptada|Rechazada)
  verificacion ("X.509 OK" | "Inválida"), detalle_json, ruta_zip, salto, rally_id …
                         │
consultas ───────────────┘ 0..1
  id (PK), solicitud_id (UNIQUE, FK) ← una solicitud aceptada produce como máximo 1 consulta
  origen CHECK(Recibido|Enviado|Generado), direccion, resultado_envio, salto, rally_id …

bitacora (id autoincremental, tipo, mensaje, rally_id, salto)   → panel y rally
nodos    (direccion PK, nodo_id, estado, cert_rsa_pem, cert_ecc_pem)
ajustes  (clave PK, valor JSON)
```

Los zips no van dentro de la base: se guardan en `datos/paquetes/{recibidos|invalidos|enviados}/<id>__<nombre>.zip` y la base guarda la ruta.

**¿Por qué SQLite por P/Invoke?** El proyecto no depende de NuGet: usa el SQLite que ya trae el sistema (`winsqlite3.dll` en Windows 10/11, `libsqlite3` en Linux y macOS). Si el equipo prefiere `Microsoft.Data.Sqlite`, solo se reescribe `BaseDatos`.

## 1.6 API completa

### Protocolo (entre nodos)

| Método | Ruta | Respuesta |
| --- | --- | --- |
| GET | `/api/status` | `{nodeId, protocolVersion, status, acceptingPackages, algorithms, certificateEndpoint}` |
| POST | `/api/requests/receive` | 202, 400, 413, 422, 503 con `{status, message, requestId, packetId, verification, duplicate, errors, warnings}` |
| GET | `/api/certificate?algorithm=RSA\|ECC` | Certificado PEM (extensión propuesta por el Equipo 3) |

### Local (solo la interfaz; por defecto solo desde la misma máquina)

| Método | Ruta | Uso |
| --- | --- | --- |
| GET | `/api/local/identidad` | Datos del nodo y huellas de sus certificados |
| GET | `/api/local/certificado/{RSA\|ECC}` | Descarga el `.pem` propio |
| GET | `/api/local/eventos` | Stream SSE de alertas |
| GET | `/api/local/bitacora` | Últimos eventos |
| GET | `/api/local/solicitudes?estado=` | Bandeja |
| GET | `/api/local/solicitudes/{id}` | Detalle con verificación |
| POST | `/api/local/solicitudes/{id}/aceptar` | 200 o 409 si ya estaba decidida |
| POST | `/api/local/solicitudes/{id}/rechazar` | 200 o 409 |
| GET | `/api/local/consultas` | Archivo principal |
| GET | `/api/local/consultas/{id}` | Detalle, manifiesto y verificación |
| GET | `/api/local/consultas/{id}/zip` | Descarga con el nombre oficial |
| POST | `/api/local/consultas/{id}/descifrar` | Contenido en claro (texto o Base64) |
| POST | `/api/local/consultas/{id}/rebotar` | Ping-pong: descifra, re-cifra para el emisor y regresa |
| POST | `/api/local/consultas/{id}/reenviar` | Reenvía el zip intacto a otra IP |
| POST | `/api/local/enviar` | Modo emisor (multipart) |
| POST | `/api/local/verificar` | Verifica un zip sin registrarlo |
| GET/POST/DELETE | `/api/local/nodos` | Directorio de células |
| GET/PUT | `/api/local/ajustes` | Ajustes |

## 1.7 Seguridad de la aplicación

- **Administración protegida:** `/api/local/*` responde 403 a cualquier IP que no sea la propia máquina, salvo que se active "Administración remota". Así otro equipo de la LAN no puede aceptar, rechazar ni descifrar nuestras solicitudes.
- **Zips hostiles:** solo se aceptan los 3 nombres exactos (sin *zip slip*), se limita el tamaño descomprimido (sin bombas zip) y la validación se hace en memoria.
- **Nombres de archivo ajenos:** se limpian antes de tocar el disco (`AlmacenPaquetes.NombreSeguro`).
- **SQL:** siempre con parámetros `?1, ?2…`; hay una prueba que intenta inyección.
- **XSS:** la interfaz escapa todo texto que viene del servidor (`esc()` en `app.js`), porque nombres de archivo y nodos los escribe otro equipo.
- **Llaves privadas:** en disco cifradas con AES-256-CBC + PBKDF2 (100 000 iteraciones); nunca salen del proceso ni viajan en el zip.

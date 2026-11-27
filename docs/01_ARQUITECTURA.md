# 1. Arquitectura (estándar v2.0)

## 1.1 Cómo se cubren los puntos del pizarrón

| Punto | Decisión en el nodo EQ03 |
| --- | --- |
| **Arquitectura de software** | Dos capas: `Nodo03.Core` (dominio: protocolo, criptografía, datos, proveedor RSA/ECC) y `Nodo03.Web` (transporte HTTP/UDP + interfaz). El núcleo no sabe que existe la web; se prueba solo. |
| **Bases de datos** | SQLite local (`datos/nodo03-v2.db`), modo WAL, consultas parametrizadas. Tablas `solicitudes`, `consultas`, `bitacora`, `nodos`, `llaves`, `peticiones`, `ajustes`. |
| **Lenguaje de programación** | C# 12 sobre .NET 8 (acuerdo del grupo). JavaScript estándar en el navegador. Herramientas de interoperabilidad en Python. |
| **APIs** | API REST del estándar v2.0 (`/api/status`, `/api/certificate`, `/api/algorithms`, `/api/requests/receive`, `/api/crypto/*`, `/api/jobs/*`, `/api/keys/*`) y API local de la interfaz (`/api/local/...`). |
| **Web services** | Servicios HTTP/JSON y `multipart/form-data` sobre Kestrel; errores `application/problem+json`; alertas en vivo por Server-Sent Events. |
| **Conectividad entre dispositivos** | Escucha en `0.0.0.0:5003`; anuncio UDP `CC-BEACON` en 5099 cada 30 s; escaneo /24 de respaldo; alta manual; directorio con huella fijada (TOFU). |

## 1.2 Los cuatro roles (sección 2)

| Rol | Clase | Qué hace |
| --- | --- | --- |
| **Receptor** | `ServicioRecepcion` | Valida (13.1) y registra en la bandeja *Solicitudes* |
| **Proveedor** | `ServicioProveedor` + `ProveedorLocal` | Atiende `/api/crypto/forward` e `/inverse` de RSA y ECC; trabajos asíncronos |
| **Solicitante** | `ServicioSolicitante` | Ejecuta cualquiera de los 21 algoritmos: local si es propio, delegado al dueño si no |
| **Emisor** | `ServicioEnvio` | Reempaqueta (9.6) y manda a la bandeja de otro nodo; ping-pong |

## 1.3 Componentes

```
                    ┌──────────────────────────────── Nodo03.Web ────────────────────────────────┐
 Otros nodos ─HTTP─▶│ ProtocoloEndpoints ─▶ ServicioRecepcion ─▶ MotorPingPong (cola)            │
                    │   /api/status          ServicioProveedor ─▶ ProveedorLocal (Core)          │
                    │   /api/certificate     (10 cupos, 30 s, jobs)                              │
                    │   /api/algorithms                                                          │
                    │   /api/requests/receive                                                    │
                    │   /api/crypto/*  /api/jobs/*  /api/keys/*                                  │
 Navegador ────────▶│ LocalEndpoints ─▶ ServicioSolicitante ─▶ ClienteNodos ─HTTP─▶ dueños        │
                    │   /api/local/...   ServicioEnvio ───────▶ (X-CC-Node, X-CC-Protocol…)       │
 UDP 5099 ◀───────▶ │ Descubrimiento ─▶ ServicioDirectorio (TOFU, escaneo, offline a los 90 s)   │
                    │ BusEventos (SSE) ─▶ alertas en vivo                                         │
                    └───────────────┬────────────────────────────────────────────────────────────┘
                                    │ usa
                    ┌───────────────▼──────────────────── Nodo03.Core ───────────────────────────┐
                    │ Servicios/ ProveedorLocal (forward, inverse, result, reenvío) · GestorLlaves│
                    │ Cripto/    IdentidadNodo · FirmaManifiesto · ParametrosCanonicos · SobreCc  │
                    │            CifradorRsa · CifradorEcc · Huellas                              │
                    │ Protocolo/ Diccionario · Identificadores · Manifiesto · NombrePaquete       │
                    │            EmpaquetadorZip · ValidadorPaquete · ErrorProtocolo (Anexo B)     │
                    │ Datos/     BaseDatos (SQLite P/Invoke) · RepositorioNodo                     │
                    └─────────────────────────────────────────────────────────────────────────────┘
```

Todas las piezas se registran como *singleton* en `NodoHost.Crear()`: un nodo = una identidad y una base.
`NodoHost` está separado de `Program.cs` para que las pruebas levanten varios nodos reales en el mismo proceso.

## 1.4 Flujos principales

**Recepción (bandeja, 13.1).** `POST /api/requests/receive` → E-SIZE (413) → `EmpaquetadorZip.Leer` (E-ZIP-*, E-MANIFEST)
→ `ValidadorPaquete.Validar` (E-VERSION … E-TIMESTAMP) → confianza (`E-CERT-UNTRUSTED` si está fijado con otra huella;
"Remitente no confirmado" si no está fijado) → E-DUPLICATE (409) → *Pendiente* → alerta SSE → 202.
Si falla una validación con el manifiesto legible, se guarda como evidencia con sello *Inválida*.

**Forward delegado (11.2).** Usuario elige AESGCM → `ServicioDirectorio.Proveedor` busca a EQ01 (en línea y con huella
fijada) → secretos en un sobre `CC-ENV-1` para EQ01 → `request` firmada RSA-PSS → `POST /api/crypto/forward` → 200 zip
(o 202 + `jobId`) → se valida como cualquier paquete → *Consultas (Generado)*.

**Inverse delegado (11.4).** Paquete en Consultas → se reempaqueta (9.6) para refrescar la fecha → `POST /api/crypto/inverse`
→ zip `result` → validación → se abre `resultEnvelope` con la llave de identidad → original → *Consultas (Resultado)*.

**Algoritmo propio (11.5).** RSA/ECC se ejecutan en `ProveedorLocal`; incluso en local se produce un `result` con
`CC-ENV-1` para mantener el formato idéntico al remoto.

**Ping-pong.** Pelota RSA/ECC en la bandeja → (automático o botón) Aceptar → inverse → forward con el mismo `keyId`
→ reenvío a `sourceIp`. El número de rebote (`hop`) y el `rallyId` viajan en `publicParameters` (opciones de EQ03).

## 1.5 Base de datos

```
solicitudes  id, packet_id (UNIQUE entre válidas), nodo_origen, nodo_productor, algoritmo_codigo, operacion_nombre,
             verificacion CHECK(Firma OK | Inválida | Remitente no confirmado), detalle, estado CHECK(Pendiente|Aceptada|Rechazada) …
consultas    id, solicitud_id (UNIQUE), consulta_origen_id, request_id, origen CHECK(Generado|Recibido|Resultado) …
nodos        node_id PK, equipo, ip, http_port, huella_fijada, huella_presentada, algoritmos, fuente, estado, visto_utc, alerta
llaves       key_id PK, algoritmo, publica_spki, privada_pem (PKCS#8 CIFRADO), permitidos (allowedNodes), creada_utc
peticiones   request_id PK  (E-DUPLICATE en /api/crypto/*)
bitacora     tipo, mensaje, rally_id, salto      (nunca secretos)
ajustes      clave, valor JSON
```

Los zips no van dentro de la base: `datos/paquetes/{recibidos|invalidos|generados|resultados|enviados}/<id>__<nombre>.zip`.

**¿Por qué SQLite por P/Invoke?** El proyecto no depende de NuGet: usa el SQLite del sistema (`winsqlite3.dll` en
Windows 10/11, `libsqlite3` en Linux/macOS).

## 1.6 API local (solo la interfaz; por defecto solo desde la misma máquina)

| Ruta | Uso |
| --- | --- |
| `GET /api/local/identidad`, `/certificado`, `/llaves`, `/bitacora`, `/eventos` | Panel, credencial, keyIds, bitácora, SSE |
| `GET /api/local/algoritmos`, `/perfil/{codigo}` | Los 21 algoritmos con disponibilidad y el perfil 10.4 del dueño |
| `POST /api/local/forward` | Forward local o delegado (multipart: algoritmo, modo, texto/archivo, opciones, secretos, keyId, cover) |
| `GET/POST /api/local/solicitudes[/{id}[/aceptar\|/rechazar]]` | Bandeja |
| `GET /api/local/consultas[/{id}[/zip]]` | Archivo |
| `POST /api/local/consultas/{id}/inverse\|enviar\|rebotar` | Inverse, envío a bandeja (9.6), ping-pong |
| `POST /api/local/verificar` | Verificador 13.1 |
| `GET/POST /api/local/nodos`, `POST /nodos/buscar`, `POST /nodos/{id}/confirmar`, `DELETE /nodos/{id}` | Directorio |
| `GET/PUT /api/local/ajustes` | Ajustes |

## 1.7 Seguridad de la aplicación

- **Administración protegida:** `/api/local/*` responde 403 a IPs que no sean la propia máquina (salvo "Administración remota").
- **Zips hostiles:** exactamente 3 entradas planas, sin rutas (`zip slip`), límite de 200 MB descomprimido y razón 100:1.
- **Secretos:** solo viajan en `CC-ENV-1`; se borran de memoria (`ZeroMemory`) y nunca van a la bitácora.
- **Llaves:** identidad y `keyId` en disco como PKCS#8 cifrado (AES-256-CBC, PBKDF2-SHA256 100 000 iteraciones).
- **Confianza:** TOFU con alerta si cambia la huella; `E-CERT-UNTRUSTED` si un remitente fijado presenta otra.
- **SQL y XSS:** consultas parametrizadas; la interfaz escapa todo texto que viene de otro equipo (`esc()`).
- **Límite de carga:** máximo 10 `/api/crypto/*` simultáneas (503 `E-BUSY`); validación de bandeja con semáforo.

# Nodo EQ03 · Oficialía de Partes Cifrada

Nodo del **Equipo 3** para el trabajo final de **Virología y Criptografía** (UPIICSA-IPN), conforme al
**Estándar de Comunicación entre Nodos del Centro de Ciberseguridad v2.0** (aprobado por el grupo 11–0).

- Es **proveedor** de los algoritmos #5 **RSA** y #6 **ECC** (`/api/crypto/forward` y `/inverse`, llaves por `keyId`).
- Es **emisor, receptor y solicitante**: ofrece los 21 algoritmos en su interfaz y delega los ajenos a su dueño.
- Identidad única X.509 RSA-2048 (`CN=EQ03`), firma RSA-PSS-SHA256, sobres `CC-ENV-1`, errores `problem+json`.
- Se descubre solo en la LAN (anuncio UDP 5099), con escaneo de respaldo y alta manual (TOFU).
- C# / .NET 8, interfaz web responsiva servida por el mismo nodo. **Sin paquetes NuGet** en el programa.

## Ejecutar

Requisito: [SDK de .NET 8](https://dotnet.microsoft.com/download/dotnet/8.0).

```bash
git clone https://github.com/AaronVelasco72/Nodo03.git
cd Nodo03
dotnet run --project src/Nodo03.Web
```

Abre **http://localhost:5003** (puerto = 5000 + número de equipo). La consola muestra la dirección de la LAN
(ej. `http://192.168.1.14:5003`) que ven los demás equipos.

> **Firewall (Windows):** la primera vez, marca **Redes privadas** y acepta. Si no aparece el aviso, en PowerShell
> como administrador:
> ```powershell
> New-NetFirewallRule -DisplayName "Nodo EQ03 HTTP" -Direction Inbound -Protocol TCP -LocalPort 5003 -Action Allow -Profile Private
> New-NetFirewallRule -DisplayName "Nodo EQ03 UDP"  -Direction Inbound -Protocol UDP -LocalPort 5099 -Action Allow -Profile Private
> ```

Pruebas (102 casos: unitarias, integración y concurrencia):

```bash
dotnet test
```

Dos nodos en la misma computadora (EQ03 en 5003 y un EQ13 de prueba en 5013):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo-dos-nodos.ps1   # Windows
bash scripts/demo-dos-nodos.sh                                        # Linux / macOS
```

Interoperabilidad desde otro lenguaje (`pip install cryptography`):

```bash
python herramientas/cliente_v2.py 127.0.0.1:5003 "Hola EQ03"      # hace de EQ99: forward + inverse + abre CC-ENV-1
python herramientas/verificar_paquete.py paquete.zip               # validaciones 1–13 de la sección 13.1
```

## Configuración

`src/Nodo03.Web/appsettings.json` o línea de comandos (`--Nodo:Clave=valor`):

| Clave | Por defecto | Para qué |
| --- | --- | --- |
| `Equipo` | `3` | Define el `nodeId` (`EQ03`), el CN del certificado y el puerto |
| `Puerto` | *(5000 + equipo)* | Puerto HTTP (5003) |
| `IpPublica` | *(auto)* | IP que se anuncia; ponla si se detecta la tarjeta equivocada (VirtualBox, WSL) |
| `Descubrimiento` / `PuertoUdp` | `true` / `5099` | Anuncio `CC-BEACON` cada 30 s |
| `CarpetaDatos` | `datos` | Base SQLite, identidad, llaves `keyId` y zips (**no se sube a GitHub**) |
| `ContrasenaLlaves` | *(cámbiala)* | Cifra en disco la llave de identidad y las llaves `keyId` |
| `LimiteZipMb` | `50` | Tamaño máximo (413 `E-SIZE`) |
| `TopeSincronoSegundos` | `30` | Después de esto `/api/crypto/*` responde 202 + `jobId` |

## API del estándar v2.0

| Método y ruta | Rol | Respuesta |
| --- | --- | --- |
| `GET /api/status` | Todos | `nodeId`, `teamNumber`, puertos, algoritmos, huella |
| `GET /api/certificate` | Todos | Certificado PEM de identidad |
| `GET /api/algorithms` | Proveedor | Perfil de RSA y ECC |
| `POST /api/requests/receive` | Receptor | 202 `{packetId, status:"Pendiente", receivedAtUtc}` |
| `POST /api/crypto/forward` | Proveedor | 200 zip `package` o 202 `jobId` |
| `POST /api/crypto/inverse` | Proveedor | 200 zip `result` (cifrado para el solicitante) o 202 |
| `GET /api/jobs/{jobId}[/result]` | Proveedor | Estado / resultado (solo para el solicitante) |
| `GET /api/keys/{keyId}` | Proveedor | Llave **pública** del `keyId` |

## Estructura

```
Nodo03.sln
├── src/
│   ├── Nodo03.Core/          Lógica sin interfaz (sin dependencias)
│   │   ├── Protocolo/        diccionario 4.1, identificadores, manifiesto, zip, validación 13.1, errores
│   │   ├── Cripto/           identidad X.509, firma RSA-PSS, sobre CC-ENV-1, RSA, ECC, huellas
│   │   ├── Datos/            SQLite (P/Invoke) y repositorio
│   │   └── Servicios/        ProveedorLocal (forward/inverse/reenvío) y GestorLlaves (keyId)
│   └── Nodo03.Web/           Servidor del nodo (ASP.NET Core)
│       ├── Endpoints/        API del estándar (/api/...) y API local de la UI (/api/local/...)
│       ├── Servicios/        receptor, proveedor, solicitante, emisor, directorio, UDP, ping-pong, alertas
│       └── wwwroot/          interfaz web (HTML + CSS + JS sin frameworks)
├── tests/Nodo03.Pruebas/     xUnit: Unitarias / Integracion / Concurrencia
├── herramientas/             cliente y verificador en Python (interoperabilidad)
├── scripts/                  demo con dos nodos
└── docs/                     documentación técnica
```

## Documentación

1. [Arquitectura](docs/01_ARQUITECTURA.md) · 2. [Protocolo e interoperabilidad](docs/02_PROTOCOLO_E_INTEROPERABILIDAD.md) ·
3. [Criptografía](docs/03_CRIPTOGRAFIA.md) · 4. [Pruebas](docs/04_PRUEBAS.md) · 5. [Manual de uso y demo](docs/05_MANUAL_DE_USO.md)

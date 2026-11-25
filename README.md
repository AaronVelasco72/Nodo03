# Nodo 03 · Oficialía de Partes Cifrada

Módulo del **Equipo 3** para el trabajo final de **Virología y Criptografía** (UPIICSA-IPN).
Cifra texto, imágenes o archivos con **RSA** o **ECC**, los sella con un certificado **X.509** dentro de un `.zip` estándar y los intercambia por IP con las demás células del grupo, incluido el ping-pong (recibir → descifrar → volver a cifrar → regresar).

- Lenguaje: C# / .NET 8 (requisito del grupo).
- Plataforma: web responsiva servida por el mismo nodo (funciona en PC y celular).
- Sin paquetes NuGet en el programa: compila sin internet. Las pruebas usan xUnit.

## Inicio rápido

Requisito: [SDK de .NET 8](https://dotnet.microsoft.com/download/dotnet/8.0).

```bash
dotnet run --project src/Nodo03.Web
```

Abre `http://localhost:5000`. La consola muestra la dirección de la LAN (ej. `http://192.168.1.14:5000`) que debes compartir con los demás equipos.

> **Windows:** la primera vez aparece el aviso del Firewall. Marca **Redes privadas** y acepta; si no, los otros equipos no podrán enviarte paquetes.

Dos nodos en la misma computadora (para practicar el ping-pong):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo-dos-nodos.ps1   # Windows
bash scripts/demo-dos-nodos.sh                                        # Linux / macOS
```

Configuración (archivo `src/Nodo03.Web/appsettings.json` o línea de comandos):

```bash
dotnet run --project src/Nodo03.Web -- --Nodo:Puerto=8080 --Nodo:NodoId=NODO-03 --Nodo:DireccionPublica=192.168.1.14:8080
```

| Clave | Por defecto | Para qué |
| --- | --- | --- |
| `NodoId` | `NODO-03` | Aparece en `sourceNode` y en el nombre del zip (`NODO03_...`) |
| `Puerto` | `5000` | Puerto HTTP |
| `DireccionPublica` | *(auto)* | IP:Puerto que se anuncia en `sourceIp`; ponla si se detecta la tarjeta de red equivocada |
| `CarpetaDatos` | `datos` | Base SQLite, llaves y zips |
| `ContrasenaLlaves` | *(cámbiala)* | Cifra las llaves privadas en disco |
| `LimiteZipMb` | `50` | Límite de recepción (413 si se excede) |

## Pruebas

```bash
dotnet test
```

110 pruebas: unitarias (cifrado, firma, zip, validación, base de datos), de integración (nodos reales por HTTP, ping-pong) y de concurrencia. Detalle en [docs/04_PRUEBAS.md](docs/04_PRUEBAS.md).

## Estructura

```
Nodo03.sln
├── src/
│   ├── Nodo03.Core/          Lógica sin interfaz (sin dependencias)
│   │   ├── Protocolo/        manifest.json, nombre del zip, empaquetado, validación
│   │   ├── Cripto/           identidad X.509, RSA, ECC, firma, huellas
│   │   ├── Datos/            SQLite (P/Invoke) y repositorio
│   │   └── Servicios/        armar / abrir paquetes
│   └── Nodo03.Web/           Servidor del nodo (ASP.NET Core)
│       ├── Endpoints/        API del protocolo (/api/...) y API local de la UI (/api/local/...)
│       ├── Servicios/        recepción, envío, ping-pong automático, alertas SSE
│       └── wwwroot/          interfaz web (HTML + CSS + JS sin frameworks)
├── tests/Nodo03.Pruebas/     xUnit: Unitarias / Integracion / Concurrencia
├── herramientas/             verificador y descifrador en Python (interoperabilidad)
├── scripts/                  demo con dos nodos
└── docs/                     documentación técnica
```

## Documentación

1. [Arquitectura](docs/01_ARQUITECTURA.md): capas, componentes, base de datos, API.
2. [Protocolo e interoperabilidad](docs/02_PROTOCOLO_E_INTEROPERABILIDAD.md): lo que los demás equipos necesitan para hablar con el Nodo 03.
3. [Criptografía](docs/03_CRIPTOGRAFIA.md): RSA, ECC, certificados y análisis de seguridad.
4. [Pruebas](docs/04_PRUEBAS.md): qué se prueba, cómo y resultados.
5. [Manual de uso y guion de demo](docs/05_MANUAL_DE_USO.md).

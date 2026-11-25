# 5. Manual de uso y guion de demo

## 5.1 Pantallas

| Pantalla | Para qué |
| --- | --- |
| **Panel** | Credencial del nodo (huellas de los certificados RSA y ECC, descarga de `.pem`), contadores, rallies de ping-pong y bitácora en vivo. |
| **Enviar** | Modo emisor en 3 pasos: contenido (frase, imagen o archivo) → algoritmo (RSA o ECC) → destino (IP:Puerto y para quién se cifra). Al final muestra el **acuse** con el nombre oficial del zip, el SHA-256 y el código HTTP del destino. |
| **Solicitudes** | Bandeja del modo receptor. Cada paquete aparece como un oficio con folio (SHA8), remitente, algoritmo y sello `X.509 OK` o `Inválida`. Botones **Aceptar** / **Rechazar** y **Detalle** con la verificación completa. |
| **Consultas** | Base de datos local. Al abrir un registro se despliega el panel lateral con **Descargar**, **Descifrar** (muestra el texto o la imagen), **Rebotar** (ping-pong) y **Reenviar** a otra IP. |
| **Verificador** | Arrastra cualquier `.zip` (de cualquier equipo) y ve el reporte sin registrarlo. |
| **Nodos** | Directorio de células: agrega IP:Puerto, prueba `/api/status` y guarda sus certificados. |
| **Ajustes** | Aceptar paquetes sí/no, algoritmos habilitados para descifrar, ping-pong automático (máximo de rebotes y pausa), administración remota, sonido y notificaciones del sistema. |

**Alertas.** Al llegar un paquete suena un timbre, aparece un aviso arriba a la derecha, sube el contador rojo de Solicitudes, cambia el título de la pestaña y, si diste permiso, sale una notificación del sistema aunque el navegador esté minimizado.

**Celular.** Abre `http://IP-de-la-PC:5000` desde el teléfono (misma red). Para aceptar o descifrar desde ahí activa *Ajustes → Administración remota*.

## 5.2 Preparación el día de la presentación

1. Todas las computadoras en la **misma red** (el mismo Wi-Fi o un hotspot del celular; algunas redes escolares aíslan a los clientes entre sí).
2. `dotnet run --project src/Nodo03.Web -c Release`. Si Windows pregunta, **permitir en redes privadas**.
3. Anotar la dirección que imprime la consola (`En la LAN: http://192.168.x.x:5000`). Si muestra una IP rara (VirtualBox, WSL), arrancar con `--Nodo:DireccionPublica=192.168.x.x:5000`.
4. En **Nodos**, registrar la IP:Puerto de cada equipo y confirmar "En línea".
5. Compartir las huellas de los certificados (Panel) con los demás equipos.

## 5.3 Guion de demo (8 minutos)

1. **Generar un archivo con certificado** (lo que pidió el profesor para todos los módulos). Enviar → Frase "CURP VERA040101HDFLMR09…" → RSA → *Para mí* + *Solo generar*. Descargar el zip, abrirlo y mostrar los 3 archivos. Abrir `certificado.pem` con doble clic en Windows: se lee en cualquier lado.
2. **Verificar desde otro lenguaje.** `python herramientas/verificar_paquete.py <zip>` → `X.509 OK`.
3. **Envío a otra célula.** Enviar → Imagen → ECC → destino IP del equipo vecino → *Para el nodo destino*. Mostrar el acuse "Entregado · 202".
4. **Recepción y alerta.** Que otro equipo nos envíe un paquete: suena la alerta, aparece en Solicitudes con su sello. Abrir Detalle → checklist SHA-256 / huella / firma.
5. **Ataque en vivo.** Abrir un zip recibido, cambiar un carácter de `datos.enc` con un editor y subirlo al Verificador (o enviarlo con curl): sello **Inválida**, error de integridad. Con curl el nodo responde **422**.
6. **Ping-pong.** Aceptar la pelota → Consultas → Descifrar (se ve el contenido) → **Rebotar**: se re-cifra con el certificado del emisor y regresa a su IP. En el Panel se ve el rally con los rebotes numerados.
7. **Ping-pong automático entre dos nodos** (los dos del Equipo 3 o con otro equipo que también use RSA/ECC): activar en Ajustes, enviar una pelota y ver cómo rebota sola hasta el máximo configurado.
8. **Pruebas.** `dotnet test` → 110 pruebas en verde, incluidas las de concurrencia.

## 5.4 Problemas comunes

| Síntoma | Causa probable | Solución |
| --- | --- | --- |
| "No se pudo conectar con el destino" | Firewall, IP equivocada o red con aislamiento de clientes | Permitir `dotnet` en el firewall; `ping` a la IP; usar hotspot |
| "El destino no publicó su certificado" | El otro nodo no implementa `/api/certificate` | Pedir su `.pem` y usar *Para un certificado que subo*, o cifrar *Para mí* si solo van a validar |
| 403 al abrir la interfaz desde el celular | La administración remota está apagada | Activarla en Ajustes desde la PC |
| "Este paquete fue cifrado para otro certificado" | Se intenta descifrar algo cifrado para otro nodo | Solo el destinatario puede descifrar; es el comportamiento correcto |
| Se perdieron las llaves al cambiar de carpeta | La identidad vive en `datos/identidad` | Copiar la carpeta `datos` completa; no subirla a GitHub |
| `DllNotFoundException: sqlite` en Linux | Falta la librería del sistema | `sudo apt install libsqlite3-0` |

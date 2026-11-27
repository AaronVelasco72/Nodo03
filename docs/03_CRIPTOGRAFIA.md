# 3. Criptografía (estándar v2.0)

En v2.0 hay **dos tipos de llaves** que no se deben confundir:

| | Llave de **identidad** (sección 7) | Llaves de **algoritmo** `keyId` (sección 12) |
| --- | --- | --- |
| Cuántas | Una por nodo | Una por cada `forward` sin `keyId` |
| Tipo | RSA-2048 + certificado X.509 autofirmado | RSA-2048 (algoritmo #5) o EC P-256 (algoritmo #6) |
| Para qué | Firmar manifiestos y peticiones (RSA-PSS) · abrir sobres `CC-ENV-1` | Cifrar/descifrar el contenido del usuario |
| Dónde | `datos/identidad/identidad.{cert,key}.pem` | Tabla `llaves` (privada como PKCS#8 cifrado) |
| Quién la usa | Solo el dueño | El dueño (EQ03), a petición de cualquier nodo |

## 3.1 Identidad X.509

`CN=EQ03, OU=Equipo 03, O=Centro de Ciberseguridad, C=MX` · emisor = sujeto · `sha256WithRSAEncryption` · 365 días ·
serie aleatoria de 128 bits (≥ 64 exigidos) · `keyUsage = digitalSignature, keyEncipherment` · huella = SHA-256 del DER
en MAYÚSCULAS. Si cambia el número de equipo o vence, se regenera (y los demás verán la alerta de huella).

**Modelo de confianza (TOFU).** No hay CA común. La primera vez que se ve un nodo, el usuario compara la huella que
muestra su Panel (en persona) y la confirma; a partir de ahí queda **fijada**. Si un nodo fijado presenta otra huella,
no se usa hasta reconfirmar y sus paquetes se rechazan con `403 E-CERT-UNTRUSTED`.

## 3.2 Firma RSA-PSS-SHA256 (8.2 y 8.4)

PSS con MGF1-SHA256 y sal de 32 bytes: cada firma es distinta aunque el texto sea igual. Se firma la **cadena 8.4**:

```text
version|packetType|packetId|sourceNode|producerNode|algorithmCode|operation|timestampUtc|encryptedSha256|publicParametersSha256|certificateThumbprintSha256
```

`publicParametersSha256` es el SHA-256 del texto canónico 8.5 (llaves ordenadas por bytes UTF-8, `k=v` unidas con `\n`).
Así la firma cubre algoritmo, operación, contenido y parámetros sin depender de cómo cada lenguaje serializa JSON.
Las peticiones `/api/crypto/*` se firman igual, sobre los **bytes exactos** de la parte `request`.

## 3.3 Sobre híbrido CC-ENV-1 (8.3)

```
CEK (32 B) y nonce (12 B) aleatorios
cifrado‖tag = AES-256-GCM(CEK, nonce, AAD = requestId | packetId)
wrappedKey  = RSA-OAEP-SHA256(CEK) con la llave pública del certificado del DESTINATARIO
```

Sirve para mandar secretos (ej. la clave de AESGCM) al dueño del algoritmo y para devolver resultados de `inverse` al
solicitante (`resultado.enc` + `resultEnvelope` sin `ciphertextBase64`). Si `recipientThumbprintSha256` no es nuestra
huella → `E-ENV-RECIPIENT`; si el tag no cuadra (alteración o AAD distinto) → `E-ENV-DECRYPT`.

## 3.4 RSA (algoritmo #5)

**Matemática.** `n = p·q`, `e = 65537`, `d = e⁻¹ mod φ(n)`; cifrar `c = mᵉ mod n`, descifrar `m = cᵈ mod n`.
La seguridad depende de lo difícil que es factorizar `n` (617 dígitos para 2048 bits).

**OAEP.** RSA "de libro" es determinista; OAEP mezcla el mensaje con aleatoriedad y SHA-256/MGF1: dos cifrados del
mismo texto son distintos y no se pueden manipular sin que se note.

**Híbrido.** Con 2048 bits y OAEP-SHA256 caben 190 bytes, y una imagen pesa MB. Por eso (tabla 4.2):

```
llave AES-256 aleatoria → AES-256-GCM(datos) = datos.enc  (+ nonceBase64, tagBase64)
wrappedKeyBase64 = RSA-OAEP-SHA256(llave AES) con la llave pública del keyId
```

## 3.5 ECC (algoritmo #6) — ECIES sobre P-256

**Matemática.** Puntos de la curva `y² = x³ − 3x + b (mod p)`, p de 256 bits. Llave privada `d`, pública `Q = d·G`.
Recuperar `d` desde `Q` es el problema del logaritmo discreto en curvas: P-256 da ~128 bits de seguridad, como RSA-3072,
con llaves mucho más cortas.

```
llave efímera (e, E = e·G) nueva en cada cifrado
secreto  = ECDH(e, Q_keyId)                 (coordenada x del punto compartido)
llave    = HKDF-SHA256(secreto, sal vacía, info "EQ03-ECIES-v1", 32 bytes)
datos.enc= AES-256-GCM(llave, nonce, datos)
publicParameters: ephemeralPublicKeyBase64 (SPKI de E), curve, scheme, kdf, hkdfInfo, nonceBase64, tagBase64
```

Para descifrar, EQ03 calcula `ECDH(d_keyId, E)` y obtiene el mismo secreto.

## 3.6 keyId (sección 12)

- `forward` sin `keyId` → par nuevo `EQ03-KEY-<uuid v4>`; va en `keyRef` y en `publicParameters.keyId`.
- `forward` con `keyId` → se reutiliza (útil para el ping-pong y para cifrar varios archivos con la misma llave).
- `inverse` → se toma del paquete; `E-KEY-NOT-FOUND` si no existe; `E-KEY-FORBIDDEN` si `allowedNodes` no incluye al solicitante.
- `GET /api/keys/{keyId}` → solo la pública (SPKI). La privada nunca sale del nodo.
- Se conservan hasta el cierre del semestre (no se borran automáticamente).

## 3.7 Análisis de seguridad

| Amenaza | Defensa |
| --- | --- |
| Alguien altera `datos.enc` en el camino | SHA-256 en el manifiesto (E-HASH) + tag GCM al descifrar |
| Alguien cambia el algoritmo, operación o parámetros | Están en la cadena firmada (E-SIGNATURE) y en el hash canónico (E-PARAMS-HASH) |
| Alguien firma con su propio certificado haciéndose pasar por otro | CN = `sourceNode` (E-CERT) y huella fijada (E-CERT-UNTRUSTED) |
| Repetición de un paquete o petición viejos | Ventana ±10 min (E-TIMESTAMP) y `packetId`/`requestId` únicos (E-DUPLICATE) |
| Robo de la clave de AESGCM en la red | Viaja dentro de `CC-ENV-1` solo para el dueño |
| Zip bomba / zip slip | Límite 200 MB y 100:1; solo 3 entradas planas |
| Saturación del proveedor | 10 peticiones simultáneas (E-BUSY) y trabajos asíncronos |
| Robo del disco | Llaves privadas cifradas con PBKDF2 (100 000 iteraciones) + AES-256 |
| Limitación honesta | Sin HTTPS los metadatos (nombres, tamaños) viajan en claro; el contenido y los secretos no |

# 2. Protocolo e interoperabilidad

Este documento es para **los demás equipos**: qué manda y qué acepta el Nodo 03, y qué decisiones de la propuesta conviene cerrar en grupo.

## 2.1 Lo que el Nodo 03 cumple tal cual de la propuesta

- Nombre: `<NODO>_<ALGORITMO>_<YYYYMMDD_HHMMSS>_<SHA8>.zip`, ej. `NODO03_RSA_20261124_201500_9F86D081.zip`.
- Zip con exactamente `datos.enc`, `certificado.pem`, `manifest.json` en la raíz.
- `manifest.json` con todos los campos de la sección 2.1, más `algorithmCode` (que la tabla 1.1 exige aunque el ejemplo JSON no lo traiga).
- `GET /api/status` y `POST /api/requests/receive` (multipart, campo `package`, cabeceras `X-Source-Node` y `X-Packet-Id`).
- Códigos 202, 400, 413 y 422 en los casos descritos. Límite de 50 MB.

## 2.2 Decisiones que la propuesta dejaba abiertas (y cómo las resolvió el Nodo 03)

> Recomendación: que el grupo adopte estas reglas para que todos los nodos coincidan.

| # | Punto abierto | Decisión del Nodo 03 | Tolerancia al recibir |
| --- | --- | --- | --- |
| 1 | ¿Qué se firma? "contenido canónico" **o** `sha\|huella\|fecha` | Firma `encryptedSha256 + "\|" + certificateThumbprintSha256 + "\|" + timestampUtc` en UTF-8 | También acepta el manifiesto canónico (sin `manifestSignatureBase64`, llaves en orden alfabético, sin espacios) |
| 2 | Formato de `timestampUtc` | `yyyy-MM-ddTHH:mm:ssZ` sin milisegundos | Se usa el texto tal cual para verificar |
| 3 | Mayúsculas de la huella | Hex en MAYÚSCULAS, SHA-256 de los bytes **DER** del certificado | Ignora mayúsculas, `:` y espacios |
| 4 | Formato de firma ECDSA | DER (lo que producen Java, OpenSSL, Node y Python) | También acepta `r‖s` de 64 bytes (formato por defecto de .NET) |
| 5 | Padding de firma RSA | RSA-PSS, MGF1-SHA256, salt de 32 bytes | También acepta PKCS#1 v1.5 (`SHA256withRSA`) |
| 6 | ¿Los paquetes con firma inválida aparecen en la bandeja? | Responde 422 y se guardan directamente como `Rechazada` con sello "Inválida" (evidencia) | — |
| 7 | Reenvío del mismo paquete | Idempotente: 202 con `duplicate: true`, no se duplica | — |
| 8 | Nodo apagado para recibir | 503 y `acceptingPackages: false` | — |
| 9 | Cómo obtener la llave pública del destino para cifrar con RSA/ECC | Extensión `GET /api/certificate?algorithm=RSA\|ECC` | Si el destino no la tiene, el usuario sube su `.pem` |
| 10 | `sourceNode` en el manifiesto vs. en el nombre | `NODO-03` en el manifiesto; `NODO03` (sin símbolos) en el nombre | — |

## 2.3 Ejemplo real de `manifest.json` (ECC)

```json
{
  "version": "1.0",
  "packetId": "5f78e239-13bf-4ed3-a46b-d65e9442ce5b",
  "sourceNode": "NODO-03",
  "sourceIp": "192.168.1.14:5000",
  "timestampUtc": "2026-11-25T02:29:46Z",
  "algorithm": "ECIES-P256-HKDF-SHA256-AES-256-GCM",
  "algorithmCode": "ECC",
  "payloadMode": "text",
  "originalFileName": "mensaje.txt",
  "originalExtension": ".txt",
  "originalSizeBytes": 13,
  "encryptedSha256": "6f583e1b75356ed88c1de14cf75ae3a142cb6c3561adb96d6cb5292b3924a744",
  "publicParameters": {
    "scheme": "ECIES-P256-HKDF-SHA256-AES-256-GCM",
    "curve": "P-256",
    "ephemeralPublicKeyBase64": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…",
    "kdf": "HKDF-SHA256",
    "hkdfInfo": "NODO03-ECIES-v1",
    "ivBase64": "…",
    "tagBase64": "…",
    "recipientThumbprintSha256": "F50B9F79…",
    "hop": 0,
    "rallyId": "5f78e239-13bf-4ed3-a46b-d65e9442ce5b"
  },
  "certificateThumbprintSha256": "4F102210C99169AFDE6FCB07E3A7E55BF10C1AC316B0E512D6B112160137F675",
  "signatureAlgorithm": "ECDSA-P256-SHA256",
  "manifestSignatureBase64": "MEUCIQ…"
}
```

`hop` y `rallyId` son extensiones del Equipo 3 para el ping-pong: `hop` cuenta los rebotes y `rallyId` agrupa todos los rebotes de una misma pelota. Otros nodos pueden ignorarlos.

## 2.4 Cómo verificar un paquete del Nodo 03 en tu lenguaje

```
1. Abrir el zip y comprobar que trae exactamente datos.enc, certificado.pem, manifest.json.
2. sha = SHA256(bytes de datos.enc) en hex minúsculas  → debe ser igual a encryptedSha256.
3. cert = leer certificado.pem (X.509)
   huella = SHA256(cert en DER) en hex mayúsculas       → igual a certificateThumbprintSha256.
4. mensaje = UTF8(encryptedSha256 + "|" + certificateThumbprintSha256 + "|" + timestampUtc)
   firma   = Base64Decode(manifestSignatureBase64)
   - Si la llave es RSA:  verificar RSA-PSS (MGF1-SHA256, salt 32) con SHA-256.
   - Si la llave es EC:   verificar ECDSA con SHA-256, firma en DER.
```

Equivalencias por lenguaje:

| | RSA-PSS | ECDSA DER |
| --- | --- | --- |
| Java | `Signature.getInstance("RSASSA-PSS")` + `PSSParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA256,32,1)` | `Signature.getInstance("SHA256withECDSA")` |
| Node.js | `crypto.verify('sha256', msg, {key, padding: RSA_PKCS1_PSS_PADDING, saltLength: 32}, sig)` | `crypto.verify('sha256', msg, key, sig)` |
| Python | `key.verify(sig, msg, PSS(MGF1(SHA256()), 32), SHA256())` | `key.verify(sig, msg, ECDSA(SHA256()))` |

Referencia ejecutable: [`herramientas/verificar_paquete.py`](../herramientas/verificar_paquete.py).

```bash
pip install cryptography
python herramientas/verificar_paquete.py NODO03_ECC_20261125_022946_6F583E1B.zip
```

## 2.5 Cómo descifrar lo que manda el Nodo 03

Solo el destinatario puede: hace falta su llave privada. Los pasos exactos por esquema están en [`herramientas/descifrar_paquete.py`](../herramientas/descifrar_paquete.py), que se probó descifrando paquetes generados por el nodo .NET (RSA directo, RSA híbrido y ECIES).

| `scheme` | Cómo se descifra |
| --- | --- |
| `RSA-OAEP-SHA256` | `datos.enc` es un bloque de 256 bytes: `RSA-OAEP(SHA-256, MGF1-SHA256).decrypt` |
| `RSA-OAEP-SHA256+AES-256-GCM` | `aes = RSA-OAEP.decrypt(encryptedKeyBase64)`; `AES-256-GCM(aes, ivBase64).decrypt(datos.enc, tagBase64)` |
| `ECIES-P256-HKDF-SHA256-AES-256-GCM` | `z = ECDH(mi privada P-256, ephemeralPublicKeyBase64 [SPKI DER])`; `k = HKDF-SHA256(z, salt vacío, info=hkdfInfo, 32 bytes)`; `AES-256-GCM(k, ivBase64).decrypt(datos.enc, tagBase64)` |

## 2.6 Pruebas rápidas con curl

```bash
# ¿Está vivo el nodo?
curl http://192.168.1.14:5000/api/status

# Obtener su certificado RSA
curl "http://192.168.1.14:5000/api/certificate?algorithm=RSA" -o nodo03_rsa.pem

# Enviarle un paquete
curl -F "package=@NODO01_AESGCM_20261116_212000_9F86D081.zip" \
     -H "X-Source-Node: NODO-01" http://192.168.1.14:5000/api/requests/receive
```

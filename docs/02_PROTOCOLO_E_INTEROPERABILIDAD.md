# 2. Protocolo e interoperabilidad (estándar v2.0)

Lo que los demás equipos necesitan para hablar con el **EQ03**. El nodo implementa el estándar completo;
aquí solo va lo específico de nuestros algoritmos y las decisiones que conviene conocer.

## 2.1 Datos del nodo

| Concepto | Valor |
| --- | --- |
| `nodeId` / `teamNumber` | `EQ03` / `3` |
| HTTP | `http://<IP>:5003` (HTTPS no se ofrece: `httpsPort = null`) |
| Anuncio UDP | `CC-BEACON` a `255.255.255.255:5099` y al broadcast de la subred, cada 30 s; `status: "offline"` al apagar |
| Certificado | RSA-2048, `CN=EQ03, OU=Equipo 03, O=Centro de Ciberseguridad, C=MX`, 365 días, serie aleatoria de 128 bits |
| Algoritmos que provee | `5 RSA` y `6 ECC` (llave por `keyId`) |

## 2.2 Perfil de RSA y ECC (`GET /api/algorithms`)

| | RSA (#5) | ECC (#6) |
| --- | --- | --- |
| `forward` / `inverse` | cifrar / descifrar | cifrar / descifrar |
| Secretos | ninguno (la llave la guarda EQ03) | ninguno |
| `keyId` en forward | opcional; sin él se genera `EQ03-KEY-<uuid>` | igual |
| `options` | `allowedNodes` (ej. `"EQ01,EQ05"`); extensiones `hop`, `rallyId` | igual |
| `publicParameters` | `keyId`, `scheme=RSA-OAEP-SHA256+A256GCM`, `wrappedKeyBase64`, `nonceBase64`, `tagBase64` | `keyId`, `curve=P-256`, `scheme=ECIES`, `ephemeralPublicKeyBase64`, `kdf=HKDF-SHA256`, `hkdfInfo=EQ03-ECIES-v1`, `nonceBase64`, `tagBase64` |
| `payloadModes` | `text`, `file`, `image` | igual |

Cualquier nodo con un paquete RSA/ECC puede pedir el `inverse` a EQ03 (el resultado regresa cifrado para él con `CC-ENV-1`),
salvo que el `forward` original haya usado `allowedNodes`.

## 2.3 Ejemplo de petición (otro equipo pide cifrar a EQ03)

```text
POST http://192.168.1.14:5003/api/crypto/forward
X-CC-Node: EQ05   X-CC-Protocol: 2.0   X-CC-Request-Id: 0b8d6c1e-…
multipart/form-data
  request               {"version":"2.0","requestId":"0b8d…","requesterNode":"EQ05","targetNode":"EQ03",
                         "timestampUtc":"2026-11-27T16:10:00Z","algorithmCode":"RSA","operation":"forward",
                         "payloadMode":"text","originalFileName":"mensaje.txt","options":{},"keyId":null,"secrets":null}
  requestSignature      Base64(RSA-PSS-SHA256(bytes exactos de request))
  requesterCertificate  PEM de EQ05
  payload               los bytes
→ 200 application/zip  EQ03_RSA_20261127_161000_9F86D081.zip
```

`herramientas/cliente_v2.py` hace exactamente esto desde Python (forward + inverse + apertura del sobre).

## 2.4 Cumplimiento de la lista 16.2

| Punto | Estado | Dónde se prueba |
| --- | --- | --- |
| `GET /api/status`, `/certificate`, `/algorithms` en 5003 | ✓ | `ProtocoloHttpTests.Status_*`, `Algorithms_*` |
| Anuncio UDP cada 30 s y detección de otros | ✓ | `DescubrimientoUdpTests` |
| Escaneo HTTP y alta manual | ✓ | `FlujoEntreNodosTests.Escaneo_*`, `NodoDePrueba.Conocer` |
| Certificado RSA-2048 autofirmado con CN = `nodeId` | ✓ | `IdentidadTests.Certificado_CumpleLaSeccion7` |
| Valida firma, hash y parámetros canónicos | ✓ | `ProtocoloTests` (ejemplo 8.5 del estándar incluido) |
| Rechaza 4 archivos, hash, firma, timestamp viejo, `packetId` repetido con el código correcto | ✓ | `ProtocoloTests` y `ProtocoloHttpTests.Bandeja_*` |
| `forward` e `inverse` remotos de RSA y ECC | ✓ | `ProtocoloHttpTests.ForwardEInverseRemotos_*` |
| Delegar al menos un algoritmo de cada otro equipo | ✓ (genérico) | `ServicioSolicitante`; se probará con los demás nodos en la demo |
| Sobre `CC-ENV-1` en ambos sentidos | ✓ | `SobreTests`, `cliente_v2.py` |

## 2.5 Decisiones que tomamos donde el estándar no es explícito (para comentar con el grupo)

1. **AAD de AESGCM/CHACHA20 vs. reenvío.** La tabla 4.2 dice AAD = `packetId`, pero 9.6 obliga a cambiar el `packetId`
   al reenviar. Un paquete AESGCM reenviado ya no se podría descifrar. Propuesta: que el dueño guarde el AAD usado en
   `publicParameters` (ej. `aadBase64`) o usar AAD vacío. En RSA y ECC usamos **AAD vacío** para que el reenvío funcione.
2. **Ventana de ±10 min en `inverse`.** Aplicada al `package` de un inverse, impediría descifrar paquetes de más de 10 min.
   EQ03 **como solicitante** siempre reempaqueta (9.6) antes del inverse (cumple aunque el proveedor sea estricto) y **como
   proveedor** no aplica la ventana al package (sí a la `request`, que está firmada y fechada).
3. **Solicitante no fijado en `/api/crypto/*`.** 13.2 dice "huella fijada o confirmable": se acepta; solo se rechaza (403)
   si está fijado con otra huella.
4. **Secciones 17 y 18** aparecen en el índice del documento pero no tienen contenido (repositorio compartido y redes escolares).
5. Opciones `hop` y `rallyId` de RSA/ECC: extensión para seguir el ping-pong; otros equipos pueden ignorarlas.

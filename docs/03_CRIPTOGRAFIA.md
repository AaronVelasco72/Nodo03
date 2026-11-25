# 3. Criptografía

## 3.1 Identidad del nodo: dos certificados X.509

Un certificado X.509 contiene **una** llave pública, el nombre del dueño (Subject), quién lo firmó (Issuer), vigencia y para qué sirve la llave (Key Usage). Como al Equipo 3 le tocaron RSA y ECC, el nodo tiene dos:

| | Certificado RSA | Certificado ECC |
| --- | --- | --- |
| Llave | RSA 2048 bits | EC P-256 (secp256r1) |
| Subject | `CN=NODO-03 RSA, OU=Equipo 3, O=Centro de Ciberseguridad UPIICSA, C=MX` | `CN=NODO-03 ECC, …` |
| Key Usage | DigitalSignature, KeyEncipherment | DigitalSignature, KeyAgreement |
| Autofirma | sha256WithRSAEncryption | ecdsa-with-SHA256 |
| Vigencia | 2 años | 2 años |
| Sirve para | Firmar manifiestos RSA-PSS · recibir datos cifrados con RSA-OAEP | Firmar manifiestos ECDSA · recibir datos cifrados con ECIES |

Se generan la primera vez que arranca el nodo (`IdentidadNodo.CargarOCrear`) y se guardan en `datos/identidad/`. Las llaves privadas se guardan como PKCS#8 **cifrado** (AES-256-CBC, PBKDF2-SHA256, 100 000 iteraciones). El certificado va en cada paquete como `certificado.pem`, en formato PEM estándar: por eso "se puede leer en cualquier lado" (OpenSSL, Java, Node, Python, el visor de certificados de Windows).

**Modelo de confianza.** Son certificados autofirmados: no hay una autoridad certificadora del grupo. La firma prueba que quien armó el paquete tiene la llave privada del certificado incluido y que nada se alteró; para saber que ese certificado es *de verdad* del Nodo 03, los equipos comparan la huella SHA-256 que muestra el panel (como se comparan huellas de llaves SSH). Una mejora para el grupo sería una CA común que firme el certificado de cada célula.

## 3.2 RSA (algoritmo #5)

**Matemática.** Se eligen dos primos grandes `p`, `q`; `n = p·q`; `e = 65537`; `d = e⁻¹ mod φ(n)`. Cifrar: `c = mᵉ mod n`. Descifrar: `m = cᵈ mod n`. La seguridad depende de lo difícil que es factorizar `n` (617 dígitos decimales para 2048 bits).

**OAEP.** RSA "de libro" es determinista e inseguro: el mismo mensaje siempre da el mismo cifrado. OAEP mezcla el mensaje con bytes aleatorios y dos funciones hash (SHA-256, MGF1-SHA256) antes de elevar a la potencia. Resultado: cifrar dos veces lo mismo da resultados distintos (hay una prueba de eso) y no se puede manipular el cifrado sin que se note.

**Límite de tamaño.** Con 2048 bits y OAEP-SHA256 caben `256 − 2·32 − 2 = 190` bytes. El nodo usa dos esquemas:

| Contenido | Esquema | `datos.enc` |
| --- | --- | --- |
| ≤ 190 bytes (una frase) | `RSA-OAEP-SHA256` directo | 256 bytes de bloque RSA |
| > 190 bytes (imagen, archivo, frase larga) | `RSA-OAEP-SHA256+AES-256-GCM` híbrido | Datos cifrados con AES-GCM; la llave AES (32 bytes aleatorios) va cifrada con RSA-OAEP en `encryptedKeyBase64` |

El esquema híbrido es el mismo principio de PGP, S/MIME y TLS: RSA es lento y limitado, AES es rápido y sin límite; RSA protege la llave, AES protege los datos.

**Firma RSA-PSS.** Para firmar se usa la llave privada: `s = H(m)ᵈ mod n` con relleno PSS (aleatorio, MGF1-SHA256, salt de 32 bytes). Cualquiera con la llave pública verifica `sᵉ mod n`.

## 3.3 ECC (algoritmo #6)

**Matemática.** La curva P-256 es el conjunto de puntos `(x, y)` que cumplen `y² = x³ − 3x + b (mod p)` con `p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1`. Hay un punto generador `G`. La llave privada es un número `d`; la pública es el punto `Q = d·G` (sumar `G` consigo mismo `d` veces). Obtener `d` a partir de `Q` es el problema del logaritmo discreto en curvas elípticas: con 256 bits ofrece seguridad comparable a RSA de 3072 bits.

**Cifrado ECIES** (ECDH + KDF + AES-GCM):

```
Emisor (conoce Q_B, la pública del destinatario)          Destinatario (conoce d_B)
  e    ← número aleatorio (llave efímera)
  E    = e·G                     ───── va en el manifiesto ─────▶  E
  Z    = e·Q_B = e·d_B·G                                             Z = d_B·E = d_B·e·G   (¡el mismo punto!)
  k    = HKDF-SHA256(Z.x, info="NODO03-ECIES-v1", 32 bytes)          k = HKDF-SHA256(Z.x, …)
  datos.enc, tag = AES-256-GCM(k, nonce, mensaje)          ────▶    mensaje = AES-256-GCM⁻¹(k, …)
```

Como `e` es nuevo en cada paquete, dos cifrados del mismo mensaje son distintos y robar la llave de un paquete no abre los demás.

**Firma ECDSA-P256-SHA256.** Se emite en formato DER (secuencia ASN.1 de `r` y `s`), que es el estándar de casi todas las librerías.

**Una llave para dos usos.** El certificado EC declara `DigitalSignature` y `KeyAgreement`: la misma llave P-256 firma (ECDSA) y recibe (ECDH). Es aceptable para un proyecto académico; en producción se recomiendan dos llaves separadas.

## 3.4 Integridad y autenticidad del paquete

```
datos.enc ──SHA-256──▶ encryptedSha256 ─┐
certificado.pem ──SHA-256(DER)──▶ huella ┼──▶ "sha|huella|fecha" ──firma con llave privada──▶ manifestSignatureBase64
timestampUtc ────────────────────────────┘
```

| Ataque | Qué lo detecta |
| --- | --- |
| Cambiar un bit de `datos.enc` | El SHA-256 ya no coincide → 422. Además AES-GCM falla al descifrar. |
| Cambiar `encryptedSha256` para que coincida con datos alterados | La firma deja de ser válida → 422 |
| Sustituir `certificado.pem` por el del atacante | La huella no coincide con el manifiesto → 422 |
| Rehacer todo el paquete con la llave del atacante | El paquete es válido, pero la huella del certificado no es la del Nodo 03: por eso se muestra la huella y se compara con la publicada |
| Reenviar un paquete viejo (repetición) | El `packetId` ya existe: se reconoce como duplicado |
| Leer el contenido en tránsito | Solo el dueño de la llave privada destinataria puede descifrar |

**Limitante conocida:** `publicParameters` no entra en la cadena firmada (así lo define la propuesta). Alterar el IV, el tag o la llave efímera no permite leer ni falsificar el contenido (AES-GCM falla), pero sí "romper" el paquete. Si el grupo quiere cerrarlo, basta con firmar el manifiesto canónico completo (el Nodo 03 ya sabe verificar esa variante).

## 3.5 Generación de aleatorios y manejo de secretos

- Toda la aleatoriedad viene de `RandomNumberGenerator` (CSPRNG del sistema operativo).
- Llaves AES temporales y secretos ECDH se borran de memoria con `CryptographicOperations.ZeroMemory` al terminar.
- `publicParameters` nunca contiene llaves privadas ni llaves AES en claro (hay una prueba que lo verifica).

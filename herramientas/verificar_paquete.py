#!/usr/bin/env python3
"""
verificar_paquete.py — Verificador INDEPENDIENTE de paquetes .zip del estándar v2.0.

Está escrito en Python (no en .NET) a propósito: demuestra que un paquete del EQ03 se valida
desde otro lenguaje, y sirve para que CUALQUIER equipo pruebe sus paquetes antes de la demo.

Requisitos:   pip install cryptography
Uso:          python verificar_paquete.py EQ03_RSA_20261127_120000_9F86D081.zip [otro.zip ...]
              python verificar_paquete.py --sin-tiempo viejo.zip     (no revisa la ventana de ±10 min)

Aplica las validaciones 1 a 13 de la sección 13.1 EN ORDEN y se detiene en la primera falla,
mostrando el código del Anexo B (E-ZIP-STRUCTURE, E-HASH, E-SIGNATURE, ...). La 14 (packetId
repetido) depende del receptor y no se puede revisar con un archivo suelto.
Código de salida: 0 si todos los paquetes son válidos, 1 si alguno falla.
"""
import base64
import datetime as dt
import hashlib
import io
import json
import re
import sys
import zipfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Tabla 4.1 (id → código)
TABLA = {1: "AESGCM", 2: "DES", 3: "TRIPLEDES", 4: "CHACHA20", 5: "RSA", 6: "ECC", 7: "DIFFIEHELLMAN",
         8: "CAESAR", 9: "VIGENERE", 10: "XORASM", 11: "LSBSTEGO", 12: "EUCLIDESAFFINE", 13: "MILLERRABIN",
         14: "FISHERYATES", 15: "HASHSHA", 16: "HMACSHA256", 17: "DIGITALSIG", 18: "QUANTUMPQC",
         19: "DFTSPECTRAL", 20: "LAGRANGESHAMIR", 21: "LORENZSZ40"}
OBLIGATORIOS = ["version", "packetType", "packetId", "requestId", "sourceNode", "sourceTeam", "sourceIp",
                "producerNode", "timestampUtc", "algorithmId", "algorithmCode", "algorithmName", "operation",
                "operationName", "payloadMode", "originalFileName", "originalExtension", "originalSizeBytes",
                "contentType", "encryptedSha256", "encryptedSizeBytes", "parts", "keyRef", "publicParameters",
                "publicParametersSha256", "certificateThumbprintSha256", "signatureAlgorithm", "manifestSignatureBase64"]
RE_NODO = re.compile(r"^EQ[0-9]{2}$")
RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
RE_FECHA = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
RE_HEX = re.compile(r"^[0-9a-f]{64}$")
RE_HUELLA = re.compile(r"^[0-9A-F]{64}$")
RE_NOMBRE = re.compile(r"^(RES_)?EQ[0-9]{2}_[A-Z0-9]+_\d{8}_\d{6}_[0-9A-F]{8}\.zip$")


class Falla(Exception):
    def __init__(self, codigo, detalle):
        super().__init__(detalle)
        self.codigo = codigo


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def texto_canonico(params: dict) -> str:
    """Sección 8.5: llaves ordenadas por bytes UTF-8, 'k=v' unidas con \\n, sin salto final."""
    return "\n".join(f"{k}={params[k]}" for k in sorted(params, key=lambda k: k.encode("utf-8")))


def cadena_firma(m: dict) -> str:
    """Sección 8.4."""
    campos = ["version", "packetType", "packetId", "sourceNode", "producerNode", "algorithmCode", "operation",
              "timestampUtc", "encryptedSha256", "publicParametersSha256", "certificateThumbprintSha256"]
    return "|".join(str(m[c]) for c in campos)


def validar(ruta: str, revisar_tiempo: bool = True) -> dict:
    datos = open(ruta, "rb").read()
    # 1. Tamaño
    if len(datos) > 50 * 1024 * 1024:
        raise Falla("E-SIZE", "El paquete supera 50 MB.")
    # 2. Zip válido
    try:
        z = zipfile.ZipFile(io.BytesIO(datos))
        entradas = z.infolist()
    except zipfile.BadZipFile:
        raise Falla("E-ZIP-INVALID", "No es un zip válido.")
    # 3. Estructura
    nombres = [e.filename for e in entradas]
    if any(e.flag_bits & 0x1 for e in entradas):
        raise Falla("E-ZIP-STRUCTURE", "El zip está protegido con contraseña.")
    if any("/" in n or "\\" in n or ".." in n or n.startswith(".") for n in nombres):
        raise Falla("E-ZIP-STRUCTURE", f"Hay carpetas, rutas o archivos ocultos: {nombres}")
    if len(nombres) != 3 or "certificado.pem" not in nombres or "manifest.json" not in nombres \
            or not ({"datos.enc", "resultado.enc"} & set(nombres)):
        raise Falla("E-ZIP-STRUCTURE", f"Se esperaban exactamente 3 archivos; hay: {nombres}")
    # 4. Bomba
    total = sum(e.file_size for e in entradas)
    comprimido = max(1, sum(e.compress_size for e in entradas))
    if total > 200 * 1024 * 1024 or total / comprimido > 100:
        raise Falla("E-ZIP-BOMB", f"Descomprimido {total} B, razón {total / comprimido:.0f}:1.")
    # 5. Manifiesto
    try:
        m = json.loads(z.read("manifest.json").decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as e:
        raise Falla("E-MANIFEST", f"manifest.json no es JSON: {e}")
    faltan = [c for c in OBLIGATORIOS if c not in m]
    if faltan:
        raise Falla("E-MANIFEST", f"Faltan campos: {faltan}")
    p = m["publicParameters"]
    if not isinstance(p, dict) or any(not isinstance(v, str) for v in p.values()):
        raise Falla("E-MANIFEST", "publicParameters debe ser un objeto plano de cadenas.")
    malos = [c for c, ok in [
        ("packetType", m["packetType"] in ("package", "result")),
        ("packetId", RE_UUID.match(str(m["packetId"]))),
        ("requestId", m["requestId"] is None or RE_UUID.match(str(m["requestId"]))),
        ("sourceNode", RE_NODO.match(str(m["sourceNode"]))),
        ("sourceTeam", RE_NODO.match(str(m["sourceNode"])) and int(str(m["sourceNode"])[2:]) == m["sourceTeam"]),
        ("producerNode", RE_NODO.match(str(m["producerNode"]))),
        ("timestampUtc", RE_FECHA.match(str(m["timestampUtc"]))),
        ("operation", m["operation"] in ("forward", "inverse")),
        ("payloadMode", m["payloadMode"] in ("text", "file", "image", "multipart")),
        ("encryptedSha256", RE_HEX.match(str(m["encryptedSha256"]))),
        ("publicParametersSha256", RE_HEX.match(str(m["publicParametersSha256"]))),
        ("certificateThumbprintSha256", RE_HUELLA.match(str(m["certificateThumbprintSha256"]))),
        ("signatureAlgorithm", m["signatureAlgorithm"] == "RSA-PSS-SHA256"),
    ] if not ok]
    if malos:
        raise Falla("E-MANIFEST", f"Formato inválido en: {malos}")
    # 6. Versión
    if m["version"] != "2.0":
        raise Falla("E-VERSION", f"version = {m['version']}")
    # 7. Algoritmo
    if TABLA.get(m["algorithmId"]) != m["algorithmCode"]:
        raise Falla("E-ALGORITHM", f"algorithmId {m['algorithmId']} ≠ {m['algorithmCode']} en la tabla 4.1")
    # 8. Hash del contenido
    archivo = "resultado.enc" if m["packetType"] == "result" else "datos.enc"
    if archivo not in nombres:
        raise Falla("E-ZIP-STRUCTURE", f"Un '{m['packetType']}' debe traer {archivo}.")
    contenido = z.read(archivo)
    if sha256(contenido) != m["encryptedSha256"] or len(contenido) != m["encryptedSizeBytes"]:
        raise Falla("E-HASH", f"SHA-256 o tamaño de {archivo} no coincide.")
    # 9. Parámetros canónicos
    if sha256(texto_canonico(p).encode("utf-8")) != m["publicParametersSha256"]:
        raise Falla("E-PARAMS-HASH", "publicParametersSha256 no coincide con el texto canónico 8.5.")
    # 10. Certificado
    try:
        cert = x509.load_pem_x509_certificate(z.read("certificado.pem"))
    except ValueError:
        raise Falla("E-CERT", "certificado.pem no es X.509 PEM.")
    llave = cert.public_key()
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    ahora = dt.datetime.now(dt.timezone.utc)
    if not isinstance(llave, rsa.RSAPublicKey) or llave.key_size != 2048:
        raise Falla("E-CERT", "La llave del certificado no es RSA-2048.")
    if not cn or cn[0].value != m["sourceNode"]:
        raise Falla("E-CERT", f"CN del certificado ({cn[0].value if cn else '—'}) ≠ sourceNode {m['sourceNode']}.")
    if not (cert.not_valid_before_utc <= ahora <= cert.not_valid_after_utc):
        raise Falla("E-CERT", "El certificado no está vigente.")
    # 11. Huella
    huella = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    if huella != m["certificateThumbprintSha256"]:
        raise Falla("E-CERT-THUMBPRINT", "La huella del certificado no coincide con el manifiesto.")
    # 12. Firma RSA-PSS-SHA256 (MGF1-SHA256, sal 32) sobre la cadena 8.4
    cadena = cadena_firma(m)
    try:
        llave.verify(base64.b64decode(m["manifestSignatureBase64"]), cadena.encode("utf-8"),
                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    except (InvalidSignature, ValueError):
        raise Falla("E-SIGNATURE", "La firma no corresponde a la cadena 8.4.")
    # 13. Ventana de tiempo
    if revisar_tiempo:
        t = dt.datetime.strptime(m["timestampUtc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        if abs((ahora - t).total_seconds()) > 600:
            raise Falla("E-TIMESTAMP", f"timestampUtc {m['timestampUtc']} fuera de ±10 min (usa --sin-tiempo para paquetes viejos).")
    return {"manifiesto": m, "huella": huella, "cadena": cadena, "canonico": texto_canonico(p), "sujeto": cert.subject.rfc4514_string()}


def main(argv):
    revisar_tiempo = "--sin-tiempo" not in argv
    rutas = [a for a in argv if not a.startswith("--")]
    if not rutas:
        print(__doc__)
        return 1
    fallas = 0
    for ruta in rutas:
        print(f"\n== {ruta}")
        nombre = ruta.replace("\\", "/").split("/")[-1].split("__")[-1]  # quita el prefijo con el que el nodo guarda en disco
        if not RE_NOMBRE.match(nombre):
            print("   ! El nombre no sigue [RES_]EQnn_ALG_YYYYMMDD_HHMMSS_SHA8.zip (es informativo)")
        try:
            r = validar(ruta, revisar_tiempo)
            m = r["manifiesto"]
            print(f"   ✓ VÁLIDO · {m['packetType']} {m['algorithmCode']} {m['operationName']} · de {m['sourceNode']} "
                  f"(productor {m['producerNode']}) · {r['sujeto']}")
            print(f"   huella   {r['huella']}")
            print(f"   cadena   {r['cadena']}")
            print(f"   canónico {r['canonico']!r}")
            if m.get("keyRef"):
                print(f"   keyRef   {m['keyRef']}")
        except Falla as f:
            fallas += 1
            print(f"   ✕ {f.codigo}: {f}")
    return 0 if fallas == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

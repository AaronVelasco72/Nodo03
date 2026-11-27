#!/usr/bin/env python3
"""
cliente_v2.py — Cliente INDEPENDIENTE del estándar v2.0 escrito en Python.

Hace de "otro equipo" (por defecto EQ99) y le pide al EQ03 que cifre y descifre con RSA o ECC
por /api/crypto/forward y /api/crypto/inverse. Demuestra que cualquier lenguaje puede:
  * generar su identidad RSA-2048 (sección 7) y firmar la petición con RSA-PSS-SHA256 (8.2),
  * validar el paquete que regresa (cadena 8.4, parámetros canónicos 8.5),
  * abrir el resultado CC-ENV-1 (RSA-OAEP-SHA256 + AES-256-GCM, 8.3) con su llave privada,
  * mandar el paquete a una bandeja (/api/requests/receive).

Requisitos:   pip install cryptography
Uso:          python cliente_v2.py 192.168.1.14:5003 "Hola EQ03"               (RSA)
              python cliente_v2.py 127.0.0.1:5003 "Hola" --alg ECC --equipo 12
              python cliente_v2.py 127.0.0.1:5003 "Hola" --bandeja 127.0.0.1:5013
"""
import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verificar_paquete import validar, Falla  # noqa: E402


def ahora():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def identidad(equipo: int):
    """Certificado autofirmado de la sección 7 (en memoria, solo para la prueba)."""
    nodo = f"EQ{equipo:02d}"
    llave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nodo),
                        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Equipo {equipo:02d}"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Centro de Ciberseguridad"),
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX")])
    t = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(sujeto).issuer_name(sujeto).public_key(llave.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(t - dt.timedelta(minutes=10))
            .not_valid_after(t + dt.timedelta(days=365))
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
            .sign(llave, hashes.SHA256()))
    return nodo, llave, cert


def multipart(campos):
    """campos: lista de (nombre, nombre_archivo|None, tipo, bytes)."""
    limite = uuid.uuid4().hex
    cuerpo = io.BytesIO()
    for nombre, archivo, tipo, datos in campos:
        cuerpo.write(f"--{limite}\r\n".encode())
        disp = f'form-data; name="{nombre}"' + (f'; filename="{archivo}"' if archivo else "")
        cuerpo.write(f"Content-Disposition: {disp}\r\nContent-Type: {tipo}\r\n\r\n".encode())
        cuerpo.write(datos)
        cuerpo.write(b"\r\n")
    cuerpo.write(f"--{limite}--\r\n".encode())
    return cuerpo.getvalue(), f"multipart/form-data; boundary={limite}"


def post(url, campos, nodo, request_id):
    cuerpo, tipo = multipart(campos)
    req = urllib.request.Request(url, data=cuerpo, method="POST", headers={
        "Content-Type": tipo, "X-CC-Node": nodo, "X-CC-Protocol": "2.0", "X-CC-Request-Id": request_id})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read()


def pedir(base, operacion, alg, nodo, llave, cert, payload=None, package=None, destino="EQ03"):
    peticion = {
        "version": "2.0", "requestId": str(uuid.uuid4()), "requesterNode": nodo, "targetNode": destino,
        "timestampUtc": ahora(), "algorithmCode": alg, "operation": operacion, "payloadMode": "text",
        "originalFileName": "mensaje.txt", "options": {}, "keyId": None, "secrets": None,
    }
    bytes_req = json.dumps(peticion, ensure_ascii=False).encode("utf-8")
    firma = llave.sign(bytes_req, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    campos = [("request", None, "application/json", bytes_req),
              ("requestSignature", None, "text/plain", base64.b64encode(firma)),
              ("requesterCertificate", None, "application/x-pem-file", cert.public_bytes(serialization.Encoding.PEM))]
    if payload is not None:
        campos.append(("payload", "mensaje.txt", "text/plain", payload))
    if package is not None:
        campos.append(("package", "paquete.zip", "application/zip", package))
    estado, tipo, cuerpo = post(f"{base}/api/crypto/{operacion}", campos, nodo, peticion["requestId"])
    if estado != 200 or "zip" not in tipo:
        raise SystemExit(f"{operacion} falló: HTTP {estado} {cuerpo.decode('utf-8', 'replace')}")
    return cuerpo, peticion["requestId"]


def abrir_resultado(zip_bytes, llave, nodo):
    """Sección 8.3: CEK = RSA-OAEP-SHA256(wrappedKey); AES-256-GCM(CEK, nonce, AAD = packetId)."""
    z = zipfile.ZipFile(io.BytesIO(zip_bytes))
    m = json.loads(z.read("manifest.json"))
    sobre = m["resultEnvelope"]
    assert sobre["envelope"] == "CC-ENV-1" and sobre["recipientNode"] == nodo, "El sobre no es para mí"
    cek = llave.decrypt(base64.b64decode(sobre["wrappedKeyBase64"]),
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    cifrado = z.read("resultado.enc") + base64.b64decode(sobre["tagBase64"])
    return AESGCM(cek).decrypt(base64.b64decode(sobre["nonceBase64"]), cifrado, m["packetId"].encode("utf-8"))


def guardar_tmp(nombre, datos):
    ruta = os.path.join(os.path.dirname(os.path.abspath(__file__)), nombre)
    open(ruta, "wb").write(datos)
    return ruta


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("eq03", help="IP:puerto del EQ03 (ej. 192.168.1.14:5003)")
    ap.add_argument("texto")
    ap.add_argument("--alg", default="RSA", choices=["RSA", "ECC"])
    ap.add_argument("--equipo", type=int, default=99)
    ap.add_argument("--bandeja", help="IP:puerto de un nodo al que mandar el paquete (opcional)")
    a = ap.parse_args()
    base = "http://" + a.eq03.replace("http://", "")

    with urllib.request.urlopen(f"{base}/api/status", timeout=5) as r:
        estado = json.loads(r.read())
    print(f"1) status: {estado['nodeId']} · v{estado['protocolVersion']} · {[x['algorithmCode'] for x in estado['algorithms']]}")

    nodo, llave, cert = identidad(a.equipo)
    print(f"2) identidad {nodo}: {hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()[:16]}…")

    paquete, rid = pedir(base, "forward", a.alg, nodo, llave, cert, payload=a.texto.encode("utf-8"))
    ruta = guardar_tmp("_forward.zip", paquete)
    try:
        v = validar(ruta)
    except Falla as f:
        raise SystemExit(f"El paquete del EQ03 NO es válido: {f.codigo} {f}")
    m = v["manifiesto"]
    print(f"3) forward OK · {m['algorithmCode']} {m['operationName']} · keyId {m['keyRef']['keyId']} · firma verificada en Python")

    resultado, _ = pedir(base, "inverse", a.alg, nodo, llave, cert, package=paquete)
    validar(guardar_tmp("_resultado.zip", resultado))
    original = abrir_resultado(resultado, llave, nodo).decode("utf-8")
    print(f"4) inverse OK · sobre CC-ENV-1 abierto con la llave de {nodo}: {original!r}")
    assert original == a.texto, "¡El original no coincide!"

    if a.bandeja:
        estado, _, cuerpo = post(f"http://{a.bandeja}/api/requests/receive",
                                 [("package", "paquete.zip", "application/zip", paquete)], nodo, m["packetId"])
        print(f"5) bandeja {a.bandeja}: HTTP {estado} {cuerpo.decode('utf-8', 'replace')}")
    for f in ("_forward.zip", "_resultado.zip"):
        try:
            os.remove(os.path.join(os.path.dirname(os.path.abspath(__file__)), f))
        except OSError:
            pass
    print("Interoperabilidad Python ↔ .NET: OK")


if __name__ == "__main__":
    main()

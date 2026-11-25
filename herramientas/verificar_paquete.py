#!/usr/bin/env python3
"""
verificar_paquete.py — Verificador INDEPENDIENTE de paquetes .zip del estándar del grupo.

Está escrito en Python (no en .NET) a propósito: demuestra que un paquete generado por el
Nodo 03 se puede validar desde otro lenguaje, que es justo lo que necesitan los demás equipos.
También sirve para que cualquier equipo pruebe SUS paquetes antes de la demo.

Requisitos:   pip install cryptography
Uso:          python verificar_paquete.py NODO03_RSA_20261124_201500_9F86D081.zip [otro.zip ...]

Revisa, en el mismo orden que el receptor del Nodo 03:
  1. Estructura: exactamente datos.enc, certificado.pem y manifest.json en la raíz.
  2. Nombre:     NODO_ALGORITMO_YYYYMMDD_HHMMSS_SHA8.zip (aviso si no cumple).
  3. Integridad: SHA-256(datos.enc) == manifest.encryptedSha256.
  4. Huella:     SHA-256(certificado DER) == manifest.certificateThumbprintSha256.
  5. Firma:      manifestSignatureBase64 sobre "encryptedSha256|certificateThumbprintSha256|timestampUtc"
                 con RSA-PSS-SHA256 (o PKCS#1) o ECDSA-SHA256 (DER o r||s).
Código de salida: 0 si todos los paquetes son válidos, 1 si alguno falla.
"""
import base64
import hashlib
import json
import re
import sys
import zipfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

OBLIGATORIOS = {"datos.enc", "certificado.pem", "manifest.json"}
PATRON_NOMBRE = re.compile(r"^([A-Z0-9]+)_([A-Z0-9]+)_(\d{8})_(\d{6})_([0-9A-F]{8})\.zip$")


def verificar_firma(cert, mensaje: bytes, firma: bytes) -> str | None:
    """Devuelve una descripción del método si la firma es válida; None si no."""
    llave = cert.public_key()
    if isinstance(llave, rsa.RSAPublicKey):
        intentos = [
            ("RSA-PSS-SHA256", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)),
            ("RSA-PSS-SHA256 (salt auto)", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO)),
            ("RSA-PKCS1-SHA256", padding.PKCS1v15()),
        ]
        for nombre, relleno in intentos:
            try:
                llave.verify(firma, mensaje, relleno, hashes.SHA256())
                return nombre
            except InvalidSignature:
                pass
    elif isinstance(llave, ec.EllipticCurvePublicKey):
        try:
            llave.verify(firma, mensaje, ec.ECDSA(hashes.SHA256()))
            return "ECDSA-SHA256 (DER)"
        except (InvalidSignature, ValueError):
            pass
        if len(firma) % 2 == 0:  # formato r||s (IEEE P1363)
            mitad = len(firma) // 2
            der = encode_dss_signature(int.from_bytes(firma[:mitad], "big"), int.from_bytes(firma[mitad:], "big"))
            try:
                llave.verify(der, mensaje, ec.ECDSA(hashes.SHA256()))
                return "ECDSA-SHA256 (r||s)"
            except InvalidSignature:
                pass
    return None


def verificar(ruta: str) -> bool:
    print(f"\n=== {ruta}")
    nombre = ruta.replace("\\", "/").split("/")[-1]
    m = PATRON_NOMBRE.match(nombre)
    print(f"  [{'OK' if m else 'AVISO'}] nombre {'cumple' if m else 'NO cumple'} el formato oficial")

    try:
        with zipfile.ZipFile(ruta) as z:
            nombres = set(z.namelist())
            if nombres != OBLIGATORIOS:
                print(f"  [FALLA] estructura: se esperaba {sorted(OBLIGATORIOS)}, hay {sorted(nombres)}")
                return False
            datos = z.read("datos.enc")
            cert_pem = z.read("certificado.pem")
            manifest_bytes = z.read("manifest.json")
    except zipfile.BadZipFile:
        print("  [FALLA] no es un .zip válido")
        return False
    print("  [OK] estructura: 3 archivos en la raíz")

    manifest = json.loads(manifest_bytes.decode("utf-8-sig"))
    ok = True

    sha = hashlib.sha256(datos).hexdigest()
    if sha == manifest.get("encryptedSha256", "").lower():
        print(f"  [OK] SHA-256 datos.enc = {sha[:16]}…")
    else:
        print("  [FALLA] SHA-256 de datos.enc no coincide")
        ok = False
    if m and not sha.upper().startswith(m.group(5)):
        print("  [AVISO] el SHA8 del nombre no coincide")

    cert = x509.load_pem_x509_certificate(cert_pem)
    huella = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    declarada = re.sub(r"[^0-9A-Fa-f]", "", manifest.get("certificateThumbprintSha256", "")).upper()
    if huella == declarada:
        print(f"  [OK] huella del certificado = {huella[:16]}…  ({cert.subject.rfc4514_string()})")
    else:
        print("  [FALLA] la huella del certificado no coincide con el manifiesto")
        ok = False

    mensaje = f"{manifest['encryptedSha256']}|{manifest['certificateThumbprintSha256']}|{manifest['timestampUtc']}".encode()
    metodo = verificar_firma(cert, mensaje, base64.b64decode(manifest.get("manifestSignatureBase64", "")))
    if metodo:
        print(f"  [OK] firma válida: {metodo}")
    else:
        print("  [FALLA] firma inválida")
        ok = False

    print(f"  => {'X.509 OK' if ok else 'Inválida'}  · algoritmo {manifest.get('algorithmCode')} · modo {manifest.get('payloadMode')}")
    return ok


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    resultados = [verificar(r) for r in sys.argv[1:]]
    sys.exit(0 if all(resultados) else 1)

#!/usr/bin/env python3
"""
descifrar_paquete.py — Descifra un paquete RSA o ECC del Nodo 03 desde PYTHON.

Sirve como "especificación ejecutable": si otro equipo quiere descifrar lo que manda el
Nodo 03 en Java/Node/Python, este archivo muestra paso a paso qué hacer con
publicParameters. Si funciona aquí, el esquema es reproducible fuera de .NET.

Requisitos:  pip install cryptography
Uso:         python descifrar_paquete.py paquete.zip llave_privada.pem CONTRASENA
             (rsa.key.pem o ecc.key.pem de la carpeta datos/identidad del nodo DESTINATARIO)
"""
import base64
import json
import sys
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64(p, k):
    return base64.b64decode(p[k])


def main(ruta_zip, ruta_llave, contrasena):
    with zipfile.ZipFile(ruta_zip) as z:
        datos = z.read("datos.enc")
        m = json.loads(z.read("manifest.json").decode("utf-8-sig"))
    p = m["publicParameters"]
    llave = serialization.load_pem_private_key(open(ruta_llave, "rb").read(), contrasena.encode())
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    if p["scheme"] == "RSA-OAEP-SHA256":
        # RSA directo: datos.enc es el bloque RSA de 256 bytes.
        plano = llave.decrypt(datos, oaep)
    elif p["scheme"] == "RSA-OAEP-SHA256+AES-256-GCM":
        # Híbrido: RSA-OAEP abre la llave AES; AES-GCM abre los datos (cifrado || tag).
        aes = llave.decrypt(b64(p, "encryptedKeyBase64"), oaep)
        plano = AESGCM(aes).decrypt(b64(p, "ivBase64"), datos + b64(p, "tagBase64"), None)
    elif p["scheme"] == "ECIES-P256-HKDF-SHA256-AES-256-GCM":
        # ECIES: ECDH(mi privada, pública efímera) -> HKDF-SHA256(salt vacío, info) -> AES-256-GCM.
        efimera = serialization.load_der_public_key(b64(p, "ephemeralPublicKeyBase64"))
        secreto = llave.exchange(ec.ECDH(), efimera)
        aes = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=p["hkdfInfo"].encode()).derive(secreto)
        plano = AESGCM(aes).decrypt(b64(p, "ivBase64"), datos + b64(p, "tagBase64"), None)
    else:
        raise SystemExit(f"Esquema no soportado: {p['scheme']}")

    if m.get("payloadMode") == "text":
        print(plano.decode("utf-8"))
    else:
        salida = "descifrado_" + m.get("originalFileName", "contenido.bin")
        open(salida, "wb").write(plano)
        print(f"Guardado en {salida} ({len(plano)} bytes)")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    main(*sys.argv[1:])

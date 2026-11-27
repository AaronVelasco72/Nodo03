using System.Security.Cryptography;
using System.Text;

namespace Nodo03.Core.Cripto;

/// <summary>
/// Algoritmo #6 <c>ECC</c> (dueño: EQ03). Esquema ECIES sobre la curva P-256.
/// </summary>
/// <remarks>
/// <code>
/// 1. Par efímero e, E = e·G (nuevo en cada paquete)
/// 2. Z = e·Q  (Q = llave pública del keyId; el dueño obtiene lo mismo con d·E)
/// 3. k = HKDF-SHA256(Z.x, sal vacía, info = "EQ03-ECIES-v1", 32 bytes)
/// 4. AES-256-GCM(k, nonce) → datos.enc + tag
/// publicParameters = { keyId, curve=P-256, scheme=ECIES, ephemeralPublicKeyBase64 (SPKI DER),
///                      kdf=HKDF-SHA256, hkdfInfo, nonceBase64, tagBase64 }
/// </code>
/// <para>Los dos primeros nombres y los de la tabla 4.2 son el mínimo; <c>kdf</c> y <c>hkdfInfo</c>
/// se agregan para que el esquema quede documentado en el propio paquete.</para>
/// </remarks>
public static class CifradorEcc
{
    public const string Esquema = "ECIES";
    public const string Curva = "P-256";
    public const string InfoHkdf = "EQ03-ECIES-v1";
    public const string Nombre = "ECIES P-256 (ECDH + HKDF-SHA256 + AES-256-GCM)";

    public static (byte[] Datos, Dictionary<string, string> Parametros) Cifrar(ReadOnlySpan<byte> plano, ECParameters publica, string keyId)
    {
        using var destino = ECDiffieHellman.Create(publica);
        using var efimera = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var secreto = efimera.DeriveRawSecretAgreement(destino.PublicKey);
        var llave = Derivar(secreto);
        CryptographicOperations.ZeroMemory(secreto);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cifrado = new byte[plano.Length];
        try
        {
            using var gcm = new AesGcm(llave, 16);
            gcm.Encrypt(nonce, plano, cifrado, tag);
        }
        finally { CryptographicOperations.ZeroMemory(llave); }

        return (cifrado, new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["keyId"] = keyId,
            ["curve"] = Curva,
            ["scheme"] = Esquema,
            ["ephemeralPublicKeyBase64"] = Convert.ToBase64String(efimera.ExportSubjectPublicKeyInfo()),
            ["kdf"] = "HKDF-SHA256",
            ["hkdfInfo"] = InfoHkdf,
            ["nonceBase64"] = Convert.ToBase64String(nonce),
            ["tagBase64"] = Convert.ToBase64String(tag),
        });
    }

    public static byte[] Descifrar(byte[] cifrado, IReadOnlyDictionary<string, string> p, ECDiffieHellman privada)
    {
        if (p.GetValueOrDefault("scheme") != Esquema || p.GetValueOrDefault("curve") != Curva)
            throw new CryptographicException("Se esperaba scheme=ECIES y curve=P-256.");
        using var efimera = ECDiffieHellman.Create();
        efimera.ImportSubjectPublicKeyInfo(CifradorRsa.Leer64(p, "ephemeralPublicKeyBase64"), out _);
        var secreto = privada.DeriveRawSecretAgreement(efimera.PublicKey);
        var llave = Derivar(secreto);
        CryptographicOperations.ZeroMemory(secreto);
        try
        {
            var plano = new byte[cifrado.Length];
            using var gcm = new AesGcm(llave, 16);
            gcm.Decrypt(CifradorRsa.Leer64(p, "nonceBase64"), cifrado, CifradorRsa.Leer64(p, "tagBase64"), plano);
            return plano;
        }
        finally { CryptographicOperations.ZeroMemory(llave); }
    }

    private static byte[] Derivar(byte[] secreto) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, secreto, 32, salt: [], info: Encoding.UTF8.GetBytes(InfoHkdf));
}

using System.Security.Cryptography;

namespace Nodo03.Core.Cripto;

/// <summary>
/// Algoritmo #5 <c>RSA</c> (dueño: EQ03). Esquema de la tabla 4.2: <c>RSA-OAEP-SHA256+A256GCM</c>.
/// </summary>
/// <remarks>
/// <para>RSA-2048 con OAEP-SHA256 solo puede cifrar 190 bytes a la vez, así que el estándar pide
/// el esquema híbrido: una llave AES-256 aleatoria cifra el contenido con GCM y RSA-OAEP cifra
/// esa llave con la llave pública del <c>keyId</c>.</para>
/// <code>
/// publicParameters = { keyId, scheme, wrappedKeyBase64, nonceBase64, tagBase64 }
/// datos.enc        = texto cifrado AES-256-GCM (mismo tamaño que el original)
/// </code>
/// <para>AAD vacío: el paquete puede reenviarse (9.6) con otro packetId y debe seguir
/// descifrándose, así que el cifrado no se ata al packetId.</para>
/// </remarks>
public static class CifradorRsa
{
    public const string Esquema = "RSA-OAEP-SHA256+A256GCM";
    public const string Nombre = "RSA-OAEP-SHA256 + AES-256-GCM";

    public static (byte[] Datos, Dictionary<string, string> Parametros) Cifrar(ReadOnlySpan<byte> plano, RSA publica, string keyId)
    {
        var llaveAes = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cifrado = new byte[plano.Length];
        try
        {
            using (var gcm = new AesGcm(llaveAes, 16)) gcm.Encrypt(nonce, plano, cifrado, tag);
            return (cifrado, new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["keyId"] = keyId,
                ["scheme"] = Esquema,
                ["wrappedKeyBase64"] = Convert.ToBase64String(publica.Encrypt(llaveAes, RSAEncryptionPadding.OaepSHA256)),
                ["nonceBase64"] = Convert.ToBase64String(nonce),
                ["tagBase64"] = Convert.ToBase64String(tag),
            });
        }
        finally { CryptographicOperations.ZeroMemory(llaveAes); }
    }

    public static byte[] Descifrar(byte[] cifrado, IReadOnlyDictionary<string, string> p, RSA privada)
    {
        if (p.GetValueOrDefault("scheme") != Esquema) throw new CryptographicException($"scheme debe ser {Esquema}.");
        var llaveAes = privada.Decrypt(Leer64(p, "wrappedKeyBase64"), RSAEncryptionPadding.OaepSHA256);
        try
        {
            var plano = new byte[cifrado.Length];
            using var gcm = new AesGcm(llaveAes, 16);
            gcm.Decrypt(Leer64(p, "nonceBase64"), cifrado, Leer64(p, "tagBase64"), plano); // falla si hubo alteración
            return plano;
        }
        finally { CryptographicOperations.ZeroMemory(llaveAes); }
    }

    internal static byte[] Leer64(IReadOnlyDictionary<string, string> p, string nombre) =>
        Convert.FromBase64String(p.TryGetValue(nombre, out var v) ? v : throw new CryptographicException($"Falta publicParameters.{nombre}"));
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Nodo03.Core.Protocolo;

namespace Nodo03.Core.Cripto;

/// <summary>
/// Cifrado RSA con relleno OAEP (SHA-256). Algoritmo #5 de la tabla, código <c>RSA</c>.
/// </summary>
/// <remarks>
/// <para><b>Limitante de RSA "puro".</b> RSA-2048 con OAEP-SHA256 solo puede cifrar
/// <c>256 - 2·32 - 2 = 190</c> bytes de una vez. Una frase corta cabe; una imagen no.</para>
///
/// <para>Por eso el cifrador tiene dos esquemas (se anota cuál se usó en
/// <c>publicParameters.scheme</c>):</para>
/// <list type="number">
///   <item><b>RSA-OAEP-SHA256</b> (directo): si el contenido cabe en 190 bytes, se cifra
///   directamente con la llave pública. Es RSA "de libro".</item>
///   <item><b>RSA-OAEP-SHA256+AES-256-GCM</b> (híbrido): se genera una llave AES aleatoria de
///   32 bytes, con ella se cifra el contenido (rápido, sin límite de tamaño) y esa llave AES
///   se cifra con RSA-OAEP. Es como funcionan PGP, S/MIME y TLS: RSA protege la llave,
///   AES protege los datos. AES-GCM además detecta cualquier alteración (tag de 16 bytes).</item>
/// </list>
///
/// <para>Formato en el manifiesto (todo Base64 estándar):</para>
/// <code>
/// "publicParameters": {
///   "scheme": "RSA-OAEP-SHA256+AES-256-GCM",
///   "encryptedKeyBase64": "...",   // llave AES cifrada con RSA-OAEP (256 bytes)
///   "ivBase64": "...",             // nonce GCM de 12 bytes
///   "tagBase64": "...",            // tag GCM de 16 bytes
///   "recipientThumbprintSha256": "..." // a quién va dirigido
/// }
/// </code>
/// </remarks>
public sealed class CifradorRsa : ICifradorAsimetrico
{
    public const string EsquemaDirecto = "RSA-OAEP-SHA256";
    public const string EsquemaHibrido = "RSA-OAEP-SHA256+AES-256-GCM";

    /// <summary>Relleno usado en todo el nodo. SHA-256 tanto para el hash como para MGF1.</summary>
    public static readonly RSAEncryptionPadding Relleno = RSAEncryptionPadding.OaepSHA256;

    public string Codigo => CodigosAlgoritmo.Rsa;

    /// <summary>Máximo de bytes que RSA-OAEP-SHA256 cifra directamente con esa llave.</summary>
    public static int MaximoDirecto(RSA rsa) => rsa.KeySize / 8 - 2 * 32 - 2;

    public ResultadoCifrado Cifrar(ReadOnlySpan<byte> plano, X509Certificate2 certificadoDestino)
    {
        using var publica = certificadoDestino.GetRSAPublicKey()
            ?? throw new CryptographicException("El certificado destino no tiene llave RSA.");

        var parametros = new JsonObject
        {
            ["recipientThumbprintSha256"] = Huellas.HuellaCertificado(certificadoDestino),
        };

        // ---- Esquema 1: RSA directo (contenidos pequeños) ----
        if (plano.Length <= MaximoDirecto(publica))
        {
            parametros["scheme"] = EsquemaDirecto;
            var cifradoDirecto = publica.Encrypt(plano.ToArray(), Relleno);
            return new ResultadoCifrado(cifradoDirecto, parametros, EsquemaDirecto);
        }

        // ---- Esquema 2: híbrido RSA + AES-256-GCM ----
        var llaveAes = RandomNumberGenerator.GetBytes(32);   // llave de sesión, de un solo uso
        var nonce = RandomNumberGenerator.GetBytes(12);      // IV/nonce GCM estándar de 96 bits
        var tag = new byte[16];
        var cifrado = new byte[plano.Length];
        try
        {
            using (var gcm = new AesGcm(llaveAes, tag.Length))
                gcm.Encrypt(nonce, plano, cifrado, tag);

            parametros["scheme"] = EsquemaHibrido;
            parametros["encryptedKeyBase64"] = Convert.ToBase64String(publica.Encrypt(llaveAes, Relleno));
            parametros["ivBase64"] = Convert.ToBase64String(nonce);
            parametros["tagBase64"] = Convert.ToBase64String(tag);
            return new ResultadoCifrado(cifrado, parametros, EsquemaHibrido);
        }
        finally
        {
            // Borramos la llave de sesión de la memoria en cuanto ya no se ocupa.
            CryptographicOperations.ZeroMemory(llaveAes);
        }
    }

    public byte[] Descifrar(byte[] cifrado, JsonObject parametrosPublicos, IdentidadNodo identidad)
    {
        var esquema = parametrosPublicos["scheme"]?.ToString() ?? EsquemaHibrido;
        using var privada = identidad.CrearRsaPrivada();

        if (esquema == EsquemaDirecto)
            return privada.Decrypt(cifrado, Relleno);

        if (esquema != EsquemaHibrido)
            throw new CryptographicException($"Esquema RSA desconocido: {esquema}");

        var llaveAes = privada.Decrypt(Leer64(parametrosPublicos, "encryptedKeyBase64"), Relleno);
        try
        {
            var nonce = Leer64(parametrosPublicos, "ivBase64");
            var tag = Leer64(parametrosPublicos, "tagBase64");
            var plano = new byte[cifrado.Length];
            using var gcm = new AesGcm(llaveAes, tag.Length);
            // Si datos.enc, el IV o el tag fueron modificados, esto lanza AuthenticationTagMismatchException.
            gcm.Decrypt(nonce, cifrado, tag, plano);
            return plano;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(llaveAes);
        }
    }

    /// <summary>Lee un parámetro Base64 obligatorio.</summary>
    internal static byte[] Leer64(JsonObject p, string nombre) =>
        Convert.FromBase64String(p[nombre]?.ToString()
            ?? throw new CryptographicException($"Falta publicParameters.{nombre}"));
}

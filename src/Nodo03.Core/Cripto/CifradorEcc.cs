using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Nodo03.Core.Protocolo;

namespace Nodo03.Core.Cripto;

/// <summary>
/// Cifrado de curva elíptica ECIES sobre P-256. Algoritmo #6 de la tabla, código <c>ECC</c>.
/// </summary>
/// <remarks>
/// <para>Las curvas elípticas no "cifran" directamente como RSA: lo que hacen es ponerse de
/// acuerdo en un secreto (ECDH). ECIES combina tres piezas:</para>
/// <list type="number">
///   <item><b>ECDH efímero.</b> El emisor genera un par de llaves P-256 NUEVO para este
///   paquete. Multiplica su privada efímera por la pública del destinatario y obtiene un
///   punto secreto compartido. El destinatario obtiene el MISMO punto multiplicando su
///   privada por la pública efímera (que viaja en el manifiesto).
///   Matemáticamente: <c>e·(d·G) = d·(e·G)</c>.</item>
///   <item><b>HKDF-SHA256.</b> Convierte la coordenada X del punto compartido en una llave
///   AES de 32 bytes con buena distribución.</item>
///   <item><b>AES-256-GCM.</b> Cifra los datos y genera un tag que detecta alteraciones.</item>
/// </list>
///
/// <para>Como la llave efímera cambia en cada envío, cifrar dos veces el mismo mensaje da
/// resultados distintos y comprometer un paquete no compromete los demás.</para>
///
/// <para>Formato en el manifiesto (para que otro lenguaje lo reproduzca):</para>
/// <code>
/// "publicParameters": {
///   "scheme": "ECIES-P256-HKDF-SHA256-AES-256-GCM",
///   "curve": "P-256",
///   "ephemeralPublicKeyBase64": "...", // SubjectPublicKeyInfo DER de la llave efímera
///   "kdf": "HKDF-SHA256",
///   "hkdfInfo": "NODO03-ECIES-v1",     // salt vacío, info = este texto en UTF-8, 32 bytes
///   "ivBase64": "...", "tagBase64": "...",
///   "recipientThumbprintSha256": "..."
/// }
/// </code>
/// </remarks>
public sealed class CifradorEcc : ICifradorAsimetrico
{
    public const string Esquema = "ECIES-P256-HKDF-SHA256-AES-256-GCM";
    public const string InfoHkdf = "NODO03-ECIES-v1";

    public string Codigo => CodigosAlgoritmo.Ecc;

    public ResultadoCifrado Cifrar(ReadOnlySpan<byte> plano, X509Certificate2 certificadoDestino)
    {
        // 1) Llave pública del destinatario (sale de su certificado EC).
        using var ecdsaDestino = certificadoDestino.GetECDsaPublicKey()
            ?? throw new CryptographicException("El certificado destino no tiene llave de curva elíptica.");
        var publicaDestino = ecdsaDestino.ExportParameters(false);
        using var destino = ECDiffieHellman.Create(publicaDestino);

        // 2) Par efímero, misma curva que el destinatario (P-256).
        using var efimera = ECDiffieHellman.Create(publicaDestino.Curve);

        // 3) Secreto compartido (coordenada X del punto) -> llave AES con HKDF.
        var secreto = efimera.DeriveRawSecretAgreement(destino.PublicKey);
        var llaveAes = DerivarLlave(secreto);
        CryptographicOperations.ZeroMemory(secreto);

        // 4) AES-256-GCM.
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cifrado = new byte[plano.Length];
        try
        {
            using var gcm = new AesGcm(llaveAes, tag.Length);
            gcm.Encrypt(nonce, plano, cifrado, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(llaveAes);
        }

        var parametros = new JsonObject
        {
            ["scheme"] = Esquema,
            ["curve"] = "P-256",
            // SubjectPublicKeyInfo DER: formato universal (Java X509EncodedKeySpec,
            // Python load_der_public_key, Node crypto.createPublicKey({format:'der',type:'spki'})).
            ["ephemeralPublicKeyBase64"] = Convert.ToBase64String(efimera.ExportSubjectPublicKeyInfo()),
            ["kdf"] = "HKDF-SHA256",
            ["hkdfInfo"] = InfoHkdf,
            ["ivBase64"] = Convert.ToBase64String(nonce),
            ["tagBase64"] = Convert.ToBase64String(tag),
            ["recipientThumbprintSha256"] = Huellas.HuellaCertificado(certificadoDestino),
        };
        return new ResultadoCifrado(cifrado, parametros, Esquema);
    }

    public byte[] Descifrar(byte[] cifrado, JsonObject parametrosPublicos, IdentidadNodo identidad)
    {
        var esquema = parametrosPublicos["scheme"]?.ToString();
        if (esquema is not null && esquema != Esquema)
            throw new CryptographicException($"Esquema ECC desconocido: {esquema}");

        // Llave pública efímera del emisor.
        using var efimera = ECDiffieHellman.Create();
        efimera.ImportSubjectPublicKeyInfo(CifradorRsa.Leer64(parametrosPublicos, "ephemeralPublicKeyBase64"), out _);

        // Mi llave privada EC (la misma del certificado) en modo ECDH.
        using var yo = identidad.CrearEcdhPrivada();
        var secreto = yo.DeriveRawSecretAgreement(efimera.PublicKey);
        var llaveAes = DerivarLlave(secreto);
        CryptographicOperations.ZeroMemory(secreto);
        try
        {
            var nonce = CifradorRsa.Leer64(parametrosPublicos, "ivBase64");
            var tag = CifradorRsa.Leer64(parametrosPublicos, "tagBase64");
            var plano = new byte[cifrado.Length];
            using var gcm = new AesGcm(llaveAes, tag.Length);
            gcm.Decrypt(nonce, cifrado, tag, plano);
            return plano;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(llaveAes);
        }
    }

    /// <summary>HKDF-SHA256(ikm = secreto, salt = vacío, info = "NODO03-ECIES-v1", 32 bytes).</summary>
    private static byte[] DerivarLlave(byte[] secreto) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, secreto, 32, salt: [], info: Encoding.UTF8.GetBytes(InfoHkdf));
}

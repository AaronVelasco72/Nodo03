using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Nodo03.Core.Protocolo;

namespace Nodo03.Core.Cripto;

/// <summary>
/// Firma del manifiesto según las secciones 8.2, 8.4 y 8.5 del estándar v2.0.
/// </summary>
/// <remarks>
/// <para><b>Qué se firma (8.4):</b> los bytes UTF-8 de esta cadena, campos unidos con "|":</para>
/// <code>version|packetType|packetId|sourceNode|producerNode|algorithmCode|operation|timestampUtc|encryptedSha256|publicParametersSha256|certificateThumbprintSha256</code>
/// <para>Así la firma cubre el contenido (encryptedSha256), los parámetros (publicParametersSha256),
/// quién lo produjo, con qué algoritmo y operación, y con qué certificado.</para>
/// <para><b>Cómo (8.2):</b> RSA-PSS con SHA-256, MGF1-SHA256 y sal de 32 bytes, con la llave de
/// IDENTIDAD del nodo (RSA-2048). En .NET, <see cref="RSASignaturePadding.Pss"/> usa exactamente
/// sal = tamaño del hash = 32 bytes.</para>
/// </remarks>
public static class FirmaManifiesto
{
    public const string Algoritmo = "RSA-PSS-SHA256";

    /// <summary>Cadena de firma 8.4.</summary>
    public static string Cadena(Manifiesto m) => string.Join('|',
        m.Version, m.PacketType, m.PacketId, m.SourceNode, m.ProducerNode, m.AlgorithmCode, m.Operation,
        m.TimestampUtc, m.EncryptedSha256, m.PublicParametersSha256, m.CertificateThumbprintSha256);

    /// <summary>Calcula publicParametersSha256, la huella del certificado y la firma.</summary>
    public static void Firmar(Manifiesto m, IdentidadNodo yo)
    {
        m.PublicParametersSha256 = ParametrosCanonicos.Hash(m.PublicParameters);
        m.CertificateThumbprintSha256 = yo.Huella;
        m.SignatureAlgorithm = Algoritmo;
        m.ManifestSignatureBase64 = Convert.ToBase64String(yo.Firmar(Encoding.UTF8.GetBytes(Cadena(m))));
    }

    /// <summary>Verifica la firma con la llave pública del certificado.</summary>
    public static bool Verificar(Manifiesto m, X509Certificate2 certificado)
    {
        byte[] firma;
        try { firma = Convert.FromBase64String(m.ManifestSignatureBase64 ?? ""); }
        catch (FormatException) { return false; }
        return VerificarBytes(Encoding.UTF8.GetBytes(Cadena(m)), firma, certificado);
    }

    /// <summary>RSA-PSS-SHA256 sobre bytes arbitrarios (también se usa para la firma de peticiones 10.6).</summary>
    public static bool VerificarBytes(byte[] datos, byte[] firma, X509Certificate2 certificado)
    {
        using var rsa = certificado.GetRSAPublicKey();
        return rsa is not null && firma.Length > 0 && rsa.VerifyData(datos, firma, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }
}

/// <summary>
/// Hash canónico de <c>publicParameters</c> (sección 8.5): como cada lenguaje serializa JSON
/// distinto, no se hashea el JSON sino líneas <c>llave=valor</c> ordenadas por bytes UTF-8
/// y unidas con "\n" sin salto final.
/// </summary>
public static class ParametrosCanonicos
{
    /// <summary>Texto canónico. Ej.: {"hashAlgorithm":"SHA-256","digestHex":"ab12"} → "digestHex=ab12\nhashAlgorithm=SHA-256".</summary>
    public static string Texto(IReadOnlyDictionary<string, string> parametros) =>
        string.Join('\n', parametros
            .OrderBy(p => Encoding.UTF8.GetBytes(p.Key), ComparadorBytes.Instancia)
            .Select(p => $"{p.Key}={p.Value}"));

    /// <summary>SHA-256 hex minúsculas del texto canónico (vacío → e3b0c442…b855).</summary>
    public static string Hash(IReadOnlyDictionary<string, string> parametros) =>
        Huellas.Sha256Hex(Encoding.UTF8.GetBytes(Texto(parametros)));

    /// <summary>Orden ordinal de bytes UTF-8 (lo que pide el estándar, independiente del lenguaje).</summary>
    private sealed class ComparadorBytes : IComparer<byte[]>
    {
        public static readonly ComparadorBytes Instancia = new();
        public int Compare(byte[]? x, byte[]? y) => x.AsSpan().SequenceCompareTo(y);
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Nodo03.Core.Cripto;

/// <summary>Huellas en el formato exacto del estándar (sección 3).</summary>
public static class Huellas
{
    /// <summary>SHA-256 hex MINÚSCULAS (hash de contenido).</summary>
    public static string Sha256Hex(ReadOnlySpan<byte> datos) =>
        Convert.ToHexString(SHA256.HashData(datos)).ToLowerInvariant();

    /// <summary>SHA-256 del certificado en DER, hex MAYÚSCULAS sin separadores.</summary>
    public static string HuellaCertificado(X509Certificate2 certificado) =>
        Convert.ToHexString(SHA256.HashData(certificado.RawData));

    /// <summary>Comparación exacta y en tiempo constante (13.3) de dos cadenas.</summary>
    public static bool IgualesConstante(string? a, string? b) =>
        a is not null && b is not null &&
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}

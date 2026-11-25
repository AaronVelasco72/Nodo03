using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Nodo03.Core.Cripto;

/// <summary>
/// Funciones de huella (hash) usadas por el protocolo.
/// Se centralizan aquí para que TODO el sistema use el mismo formato de hexadecimal.
/// </summary>
public static class Huellas
{
    /// <summary>
    /// SHA-256 en hexadecimal MINÚSCULAS (64 caracteres).
    /// Es el formato exigido para <c>encryptedSha256</c> en manifest.json.
    /// </summary>
    public static string Sha256Hex(ReadOnlySpan<byte> datos) =>
        Convert.ToHexString(SHA256.HashData(datos)).ToLowerInvariant();

    /// <summary>
    /// Huella SHA-256 del certificado: hash de sus bytes DER (no del texto PEM),
    /// en hexadecimal MAYÚSCULAS, igual que el ejemplo "A1B2C3D4..." de la propuesta.
    /// Al comparar huellas de otros equipos se ignoran mayúsculas/minúsculas y ":" o espacios.
    /// </summary>
    public static string HuellaCertificado(X509Certificate2 certificado) =>
        Convert.ToHexString(SHA256.HashData(certificado.RawData));

    /// <summary>Compara dos huellas hexadecimales de forma tolerante (mayúsculas, ':' y espacios).</summary>
    public static bool HuellasIguales(string? a, string? b)
    {
        static string Limpiar(string? s) =>
            new string((s ?? "").Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        var la = Limpiar(a);
        var lb = Limpiar(b);
        // Comparación en tiempo constante: buena práctica aunque aquí no sea un secreto.
        return la.Length > 0 && CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(la), System.Text.Encoding.ASCII.GetBytes(lb));
    }
}

using System.Globalization;
using System.Text.RegularExpressions;

namespace Nodo03.Core.Protocolo;

/// <summary>
/// Nomenclatura de la sección 9.2:
/// <code>
/// package: EQ03_RSA_20261125_154700_9F86D081.zip
/// result:  RES_EQ03_RSA_20261125_154700_9F86D081.zip
/// </code>
/// El nombre es informativo: el receptor valida contra el manifiesto, no contra el nombre.
/// </summary>
public static partial class NombrePaquete
{
    [GeneratedRegex(@"^(RES_)?(EQ[0-9]{2})_([A-Z0-9]+)_(\d{8})_(\d{6})_([0-9A-F]{8})\.zip$")]
    private static partial Regex Patron();

    /// <summary>Arma el nombre. <paramref name="sha256"/> = encryptedSha256 (se toman 8 en MAYÚSCULAS).</summary>
    public static string Construir(string tipo, string nodo, string algoritmo, string timestampUtc, string sha256)
    {
        var fecha = Identificadores.LeerFecha(timestampUtc) ?? throw new ArgumentException("timestampUtc inválido");
        var nombre = $"{nodo}_{algoritmo}_{fecha.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture)}_{sha256[..8].ToUpperInvariant()}.zip";
        return tipo == TiposPaquete.Result ? "RES_" + nombre : nombre;
    }

    public static bool EsValido(string? nombre) => nombre is not null && Patron().IsMatch(nombre);
}

/// <summary>Valores de <c>packetType</c>.</summary>
public static class TiposPaquete
{
    public const string Package = "package";
    public const string Result = "result";
}

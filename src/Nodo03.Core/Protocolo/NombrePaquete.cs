using System.Globalization;
using System.Text.RegularExpressions;

namespace Nodo03.Core.Protocolo;

/// <summary>
/// Construye y valida el nombre estándar del .zip (sección 1 de la propuesta):
/// <code>&lt;NODO_ORIGEN&gt;_&lt;ALGORITMO&gt;_&lt;YYYYMMDD_HHMMSS&gt;_&lt;SHA8&gt;.zip</code>
/// Ejemplo: <c>NODO03_RSA_20261124_201500_9F86D081.zip</c>
/// </summary>
public static partial class NombrePaquete
{
    /// <summary>
    /// Expresión regular del nombre oficial:
    ///   grupo 1: nodo (A-Z y 0-9)        grupo 2: algoritmo (A-Z y 0-9)
    ///   grupo 3: fecha YYYYMMDD           grupo 4: hora HHMMSS
    ///   grupo 5: SHA8 (8 hex en mayúsculas)
    /// </summary>
    [GeneratedRegex(@"^([A-Z0-9]+)_([A-Z0-9]+)_(\d{8})_(\d{6})_([0-9A-F]{8})\.zip$")]
    private static partial Regex Patron();

    /// <summary>
    /// "NODO-03" -> "NODO03". La propuesta pide el nodo en mayúsculas y sin espacios;
    /// quitamos también guiones y cualquier símbolo para que la regex siempre empate.
    /// </summary>
    public static string NormalizarNodo(string nodo) =>
        new string(nodo.ToUpperInvariant().Where(char.IsAsciiLetterOrDigit).ToArray());

    /// <summary>Arma el nombre a partir de sus piezas.</summary>
    /// <param name="nodo">Id del nodo emisor (se normaliza).</param>
    /// <param name="codigoAlgoritmo">Código corto oficial, ej. "RSA".</param>
    /// <param name="fechaUtc">Momento del empaquetado (se usa en UTC).</param>
    /// <param name="sha256Hex">SHA-256 de datos.enc (se toman los primeros 8 caracteres).</param>
    public static string Construir(string nodo, string codigoAlgoritmo, DateTime fechaUtc, string sha256Hex)
    {
        var utc = fechaUtc.Kind == DateTimeKind.Utc ? fechaUtc : fechaUtc.ToUniversalTime();
        return $"{NormalizarNodo(nodo)}_{codigoAlgoritmo.ToUpperInvariant()}_" +
               $"{utc.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture)}_" +
               $"{sha256Hex[..8].ToUpperInvariant()}.zip";
    }

    /// <summary>¿El nombre cumple el formato?</summary>
    public static bool EsValido(string? nombre) => nombre is not null && Patron().IsMatch(nombre);

    /// <summary>
    /// Descompone un nombre válido. Útil para verificar que el SHA8 del nombre coincide
    /// con el SHA-256 real de datos.enc y que el algoritmo coincide con el manifiesto.
    /// </summary>
    public static bool TryParse(string? nombre, out PartesNombre partes)
    {
        partes = default;
        if (nombre is null) return false;
        var m = Patron().Match(nombre);
        if (!m.Success) return false;
        partes = new PartesNombre(m.Groups[1].Value, m.Groups[2].Value,
            $"{m.Groups[3].Value}_{m.Groups[4].Value}", m.Groups[5].Value);
        return true;
    }
}

/// <summary>Piezas de un nombre de paquete válido.</summary>
public readonly record struct PartesNombre(string Nodo, string Algoritmo, string Marca, string Sha8);

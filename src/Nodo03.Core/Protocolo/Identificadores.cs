using System.Globalization;
using System.Text.RegularExpressions;

namespace Nodo03.Core.Protocolo;

/// <summary>
/// Identificadores de la sección 3 del estándar v2.0 y sus expresiones regulares.
/// Las comparaciones son SIEMPRE exactas (sensibles a mayúsculas).
/// </summary>
public static partial class Identificadores
{
    public const string VersionProtocolo = "2.0";

    [GeneratedRegex(@"^EQ[0-9]{2}$")] public static partial Regex NodeId();
    [GeneratedRegex(@"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")] public static partial Regex Uuid4();
    [GeneratedRegex(@"^EQ[0-9]{2}-KEY-[0-9a-f-]{36}$")] public static partial Regex KeyId();
    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")] public static partial Regex Timestamp();
    [GeneratedRegex(@"^[0-9A-F]{64}$")] public static partial Regex Huella();
    [GeneratedRegex(@"^[0-9a-f]{64}$")] public static partial Regex HashContenido();

    /// <summary>3 → "EQ03".</summary>
    public static string NodoDeEquipo(int equipo) =>
        equipo is >= 1 and <= 99 ? $"EQ{equipo:D2}" : throw new ArgumentOutOfRangeException(nameof(equipo), "El equipo va de 1 a 99.");

    /// <summary>"EQ03" → 3 (o null si el formato no es válido).</summary>
    public static int? EquipoDeNodo(string? nodo) =>
        nodo is not null && NodeId().IsMatch(nodo) && int.TryParse(nodo.AsSpan(2), out var n) && n > 0 ? n : null;

    /// <summary>UUID v4 en minúsculas (Guid.NewGuid de .NET es v4).</summary>
    public static string NuevoUuid() => Guid.NewGuid().ToString("D");

    /// <summary>Fecha en el formato exacto del estándar: 2026-11-25T15:47:00Z.</summary>
    public static string FormatoFecha(DateTime utc) =>
        utc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>Lee una fecha del estándar; null si no cumple el formato.</summary>
    public static DateTime? LeerFecha(string? texto) =>
        texto is not null && Timestamp().IsMatch(texto) &&
        DateTime.TryParseExact(texto, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;

    /// <summary>Ventana anti repetición de ±10 minutos (sección 13).</summary>
    public static readonly TimeSpan VentanaTiempo = TimeSpan.FromMinutes(10);

    public static bool DentroDeVentana(string? fecha, DateTime ahoraUtc) =>
        LeerFecha(fecha) is { } d && (d - ahoraUtc).Duration() <= VentanaTiempo;
}

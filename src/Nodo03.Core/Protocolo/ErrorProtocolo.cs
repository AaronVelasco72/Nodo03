namespace Nodo03.Core.Protocolo;

/// <summary>
/// Error del estándar v2.0 con su código del catálogo (Anexo B) y su estado HTTP.
/// Cualquier capa del nodo lanza esta excepción; los endpoints la convierten en una
/// respuesta <c>application/problem+json</c> (sección 14).
/// </summary>
public sealed class ErrorProtocolo : Exception
{
    /// <summary>Código del Anexo B, ej. "E-HASH".</summary>
    public string Codigo { get; }

    /// <summary>Estado HTTP asociado al código.</summary>
    public int Status { get; }

    /// <summary>Título corto en español del código.</summary>
    public string Titulo { get; }

    public ErrorProtocolo(string codigo, string detalle) : base(detalle)
    {
        Codigo = codigo;
        (Status, Titulo) = CatalogoErrores.Buscar(codigo);
    }
}

/// <summary>Anexo B: código → (HTTP, título).</summary>
public static class CatalogoErrores
{
    private static readonly Dictionary<string, (int, string)> Tabla = new(StringComparer.Ordinal)
    {
        ["E-SIZE"] = (413, "Paquete demasiado grande"),
        ["E-ZIP-INVALID"] = (400, "No es un zip válido"),
        ["E-ZIP-STRUCTURE"] = (400, "Estructura del zip inválida"),
        ["E-ZIP-BOMB"] = (400, "Posible bomba zip"),
        ["E-MANIFEST"] = (400, "Manifiesto inválido"),
        ["E-VERSION"] = (400, "Versión no soportada"),
        ["E-ALGORITHM"] = (400, "Algoritmo inválido"),
        ["E-PARAMS"] = (400, "Parámetros inválidos"),
        ["E-REQUEST"] = (400, "Petición mal formada"),
        ["E-REQUEST-SIGNATURE"] = (401, "Firma de la petición inválida"),
        ["E-ENV-RECIPIENT"] = (401, "El sobre no es para este nodo"),
        ["E-ENV-DECRYPT"] = (401, "No se pudo abrir el sobre"),
        ["E-CERT-UNTRUSTED"] = (403, "Huella no confiable"),
        ["E-ALGORITHM-NOT-PROVIDED"] = (404, "Algoritmo no provisto"),
        ["E-KEY-NOT-FOUND"] = (404, "keyId desconocido"),
        ["E-KEY-FORBIDDEN"] = (403, "keyId no permitido"),
        ["E-JOB-NOT-FOUND"] = (404, "Trabajo desconocido"),
        ["E-DUPLICATE"] = (409, "Identificador repetido"),
        ["E-UNSUPPORTED-MEDIA"] = (415, "Tipo de contenido no soportado"),
        ["E-HASH"] = (422, "Integridad inválida"),
        ["E-PARAMS-HASH"] = (422, "Hash de parámetros inválido"),
        ["E-CERT"] = (422, "Certificado inválido"),
        ["E-CERT-THUMBPRINT"] = (422, "Huella del certificado no coincide"),
        ["E-SIGNATURE"] = (422, "Firma inválida"),
        ["E-TIMESTAMP"] = (422, "Fecha fuera de la ventana"),
        ["E-VERIFY-FAILED"] = (422, "Verificación fallida"),
        ["E-INTERNAL"] = (500, "Error interno"),
        ["E-BUSY"] = (503, "Nodo ocupado"),
        ["E-TIMEOUT"] = (504, "Tiempo agotado"),
    };

    public static (int Status, string Titulo) Buscar(string codigo) =>
        Tabla.TryGetValue(codigo, out var v) ? v : (500, "Error");

    public static IEnumerable<string> Codigos => Tabla.Keys;
}

using Nodo03.Core.Protocolo;

namespace Nodo03.Web.Endpoints;

/// <summary>Respuestas de error <c>application/problem+json</c> (sección 14, RFC 9457).</summary>
public static class Problemas
{
    public static IResult De(ErrorProtocolo e, string nodeId, string? requestId = null) => Results.Json(new
    {
        type = $"https://centrociber.local/errors/{e.Codigo}",
        title = e.Titulo,
        status = e.Status,
        code = e.Codigo,
        detail = e.Message,
        nodeId,
        requestId,
        timestampUtc = Identificadores.FormatoFecha(DateTime.UtcNow),
    }, statusCode: e.Status, contentType: "application/problem+json");

    public static IResult De(string codigo, string detalle, string nodeId, string? requestId = null) =>
        De(new ErrorProtocolo(codigo, detalle), nodeId, requestId);
}

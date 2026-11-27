using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Nodo03.Core.Protocolo;

namespace Nodo03.Web.Servicios;

/// <summary>Algoritmo anunciado en <c>GET /api/status</c>.</summary>
public sealed record AlgoritmoAnunciado(
    [property: JsonPropertyName("algorithmId")] int AlgorithmId,
    [property: JsonPropertyName("algorithmCode")] string AlgorithmCode);

/// <summary>Respuesta de <c>GET /api/status</c> (sección 10.3).</summary>
public sealed record EstadoRemoto(
    [property: JsonPropertyName("nodeId")] string? NodeId,
    [property: JsonPropertyName("teamNumber")] int TeamNumber,
    [property: JsonPropertyName("protocolVersion")] string? ProtocolVersion,
    [property: JsonPropertyName("status")] string? Status,
    [property: JsonPropertyName("acceptingPackages")] bool AcceptingPackages,
    [property: JsonPropertyName("httpPort")] int HttpPort,
    [property: JsonPropertyName("httpsPort")] int? HttpsPort,
    [property: JsonPropertyName("algorithms")] List<AlgoritmoAnunciado>? Algorithms,
    [property: JsonPropertyName("certificateThumbprintSha256")] string? CertificateThumbprintSha256,
    [property: JsonPropertyName("serverTimeUtc")] string? ServerTimeUtc);

/// <summary>Respuesta HTTP de otro nodo. <c>Codigo = 0</c> = no hubo conexión.</summary>
public sealed record RespuestaNodo(int Codigo, string? TipoContenido, byte[] Cuerpo, string? NombreArchivo = null)
{
    public bool EsZip => Codigo == 200 && (TipoContenido?.Contains("zip", StringComparison.OrdinalIgnoreCase) ?? false);
    public string Texto => System.Text.Encoding.UTF8.GetString(Cuerpo);

    /// <summary>code/detail del problem+json (o el texto crudo si no es JSON).</summary>
    public (string? Codigo, string Detalle) Problema()
    {
        try
        {
            using var doc = JsonDocument.Parse(Cuerpo);
            var r = doc.RootElement;
            var codigo = r.TryGetProperty("code", out var c) ? c.GetString() : null;
            var detalle = r.TryGetProperty("detail", out var d) ? d.GetString() : r.TryGetProperty("message", out var mm) ? mm.GetString() : null;
            return (codigo, detalle ?? Texto);
        }
        catch (JsonException) { return (null, Texto.Length > 300 ? Texto[..300] : Texto); }
    }

    public override string ToString()
    {
        if (Codigo == 0) return "Sin conexión";
        if (Codigo is 200 or 202) return Codigo.ToString();
        var (c, d) = Problema();
        return c is null ? $"{Codigo} {d}" : $"{Codigo} {c}: {d}";
    }
}

/// <summary>
/// Cliente HTTP hacia OTROS nodos (roles Emisor y Solicitante). Agrega a TODAS las peticiones
/// los encabezados de la sección 10.1: <c>X-CC-Node</c>, <c>X-CC-Protocol</c>, <c>X-CC-Request-Id</c>.
/// </summary>
/// <remarks>Una sola instancia de <see cref="HttpClient"/> para toda la aplicación (singleton).</remarks>
public sealed class ClienteNodos(HttpClient http, OpcionesNodo opciones)
{
    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// "192.168.1.14:5008" → http://192.168.1.14:5008/. Sin puerto se asume 5000 + equipo si se
    /// conoce; si no, se exige el puerto.
    /// </summary>
    public static Uri UrlBase(string direccion)
    {
        var d = direccion.Trim().TrimEnd('/');
        if (!d.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !d.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            d = "http://" + d;
        if (!Uri.TryCreate(d, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
            throw new ArgumentException($"Dirección inválida: '{direccion}'. Usa el formato IP:Puerto (ej. 192.168.1.14:5008).");
        if (uri.IsDefaultPort && !direccion.Replace("://", "").Contains(':'))
            throw new ArgumentException($"Falta el puerto en '{direccion}'. En v2.0 es 5000 + número de equipo (ej. :5008).");
        return new Uri(uri.GetLeftPart(UriPartial.Authority) + "/");
    }

    private HttpRequestMessage Peticion(HttpMethod metodo, string direccion, string ruta, string? idPeticion = null)
    {
        var p = new HttpRequestMessage(metodo, new Uri(UrlBase(direccion), ruta));
        p.Headers.Add("X-CC-Node", opciones.NodoId);
        p.Headers.Add("X-CC-Protocol", Identificadores.VersionProtocolo);
        p.Headers.Add("X-CC-Request-Id", idPeticion ?? Identificadores.NuevoUuid());
        return p;
    }

    private async Task<RespuestaNodo> Mandar(HttpRequestMessage p, TimeSpan limite, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(limite);
        try
        {
            using var r = await http.SendAsync(p, cts.Token);
            var cuerpo = await r.Content.ReadAsByteArrayAsync(cts.Token);
            return new RespuestaNodo((int)r.StatusCode, r.Content.Headers.ContentType?.MediaType, cuerpo,
                r.Content.Headers.ContentDisposition?.FileNameStar ?? r.Content.Headers.ContentDisposition?.FileName?.Trim('"'));
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            return new RespuestaNodo(0, null, System.Text.Encoding.UTF8.GetBytes(ex.Message));
        }
        finally { p.Dispose(); }
    }

    // ------------------------------------------------------------------ Descubrimiento

    /// <summary><c>GET /api/status</c>. Null si no responde a tiempo o no es un nodo v2.0.</summary>
    public async Task<EstadoRemoto?> Estado(string direccion, TimeSpan? limite = null, CancellationToken ct = default)
    {
        var r = await Mandar(Peticion(HttpMethod.Get, direccion, "api/status"), limite ?? TimeSpan.FromSeconds(3), ct);
        if (r.Codigo != 200) return null;
        try { return JsonSerializer.Deserialize<EstadoRemoto>(r.Cuerpo, JsonWeb); }
        catch (JsonException) { return null; }
    }

    /// <summary><c>GET /api/certificate</c> → PEM o null.</summary>
    public async Task<string?> Certificado(string direccion, CancellationToken ct = default)
    {
        var r = await Mandar(Peticion(HttpMethod.Get, direccion, "api/certificate"), TimeSpan.FromSeconds(5), ct);
        return r.Codigo == 200 && r.Texto.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal) ? r.Texto : null;
    }

    /// <summary><c>GET /api/algorithms</c> → JSON crudo del perfil o null.</summary>
    public async Task<JsonDocument?> Perfil(string direccion, CancellationToken ct = default)
    {
        var r = await Mandar(Peticion(HttpMethod.Get, direccion, "api/algorithms"), TimeSpan.FromSeconds(5), ct);
        if (r.Codigo != 200) return null;
        try { return JsonDocument.Parse(r.Cuerpo); }
        catch (JsonException) { return null; }
    }

    // ------------------------------------------------------------------ Emisor

    /// <summary><c>POST /api/requests/receive</c> con el .zip en el campo <c>package</c>.</summary>
    public Task<RespuestaNodo> EnviarABandeja(string direccion, string nombreZip, byte[] zip, string packetId, CancellationToken ct = default)
    {
        var contenido = new MultipartFormDataContent();
        var archivo = new ByteArrayContent(zip);
        archivo.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        contenido.Add(archivo, "package", nombreZip);
        var p = Peticion(HttpMethod.Post, direccion, "api/requests/receive", packetId);
        p.Content = contenido;
        // Si el destino rechaza por tamaño (413) lo dice antes de subir todo.
        p.Headers.ExpectContinue = true;
        return Mandar(p, TimeSpan.FromSeconds(60), ct);
    }

    // ------------------------------------------------------------------ Solicitante

    /// <summary>
    /// <c>POST /api/crypto/forward|inverse</c> (10.6). <paramref name="request"/> son los bytes
    /// EXACTOS que se firmaron.
    /// </summary>
    public Task<RespuestaNodo> Cripto(string direccion, string operacion, byte[] request, string firmaBase64, string certificadoPem,
        IEnumerable<(string Parte, string Nombre, string Tipo, byte[] Bytes)> archivos, string requestId, CancellationToken ct = default)
    {
        var contenido = new MultipartFormDataContent();
        var req = new ByteArrayContent(request);
        req.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        contenido.Add(req, "request");
        contenido.Add(new StringContent(firmaBase64), "requestSignature");
        var cert = new StringContent(certificadoPem);
        cert.Headers.ContentType = new MediaTypeHeaderValue("application/x-pem-file");
        contenido.Add(cert, "requesterCertificate");
        foreach (var a in archivos)
        {
            var parte = new ByteArrayContent(a.Bytes);
            parte.Headers.ContentType = new MediaTypeHeaderValue(a.Tipo);
            contenido.Add(parte, a.Parte, a.Nombre);
        }
        var p = Peticion(HttpMethod.Post, direccion, $"api/crypto/{operacion}", requestId);
        p.Content = contenido;
        // Tope síncrono del proveedor = 30 s; damos margen para la subida.
        return Mandar(p, TimeSpan.FromSeconds(75), ct);
    }

    /// <summary>
    /// Si el proveedor respondió 202 + jobId, consulta <c>/api/jobs/{id}</c> hasta que termine
    /// (máx. 5 min) y descarga el resultado.
    /// </summary>
    public async Task<RespuestaNodo> EsperarTrabajo(string direccion, RespuestaNodo aceptado, string requestId, CancellationToken ct = default)
    {
        string jobId; int espera;
        try
        {
            using var doc = JsonDocument.Parse(aceptado.Cuerpo);
            jobId = doc.RootElement.GetProperty("jobId").GetString()!;
            espera = doc.RootElement.TryGetProperty("retryAfterSeconds", out var s) && s.TryGetInt32(out var n) ? n : 2;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return new RespuestaNodo(502, "text/plain", "La respuesta 202 no trae jobId."u8.ToArray());
        }
        espera = Math.Clamp(espera, 1, 5);
        var limite = DateTime.UtcNow.AddMinutes(5);
        while (DateTime.UtcNow < limite)
        {
            await Task.Delay(TimeSpan.FromSeconds(espera), ct);
            var r = await Mandar(Peticion(HttpMethod.Get, direccion, $"api/jobs/{jobId}", requestId), TimeSpan.FromSeconds(10), ct);
            if (r.Codigo != 200) return r;
            using var doc = JsonDocument.Parse(r.Cuerpo);
            var estado = doc.RootElement.GetProperty("state").GetString();
            if (estado == "failed")
                return new RespuestaNodo(500, "application/problem+json", r.Cuerpo);
            if (estado == "done")
            {
                var url = doc.RootElement.TryGetProperty("resultUrl", out var u) && u.ValueKind == JsonValueKind.String
                    ? u.GetString()!.TrimStart('/') : $"api/jobs/{jobId}/result";
                return await Mandar(Peticion(HttpMethod.Get, direccion, url, requestId), TimeSpan.FromSeconds(60), ct);
            }
        }
        return new RespuestaNodo(504, "text/plain", "El trabajo asíncrono no terminó en 5 minutos."u8.ToArray());
    }
}

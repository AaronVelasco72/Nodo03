using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace Nodo03.Web.Servicios;

/// <summary>Respuesta de <c>GET /api/status</c> (sección 3.1).</summary>
public sealed record EstadoNodoRemoto(
    [property: JsonPropertyName("nodeId")] string? NodeId,
    [property: JsonPropertyName("protocolVersion")] string? ProtocolVersion,
    [property: JsonPropertyName("status")] string? Status,
    [property: JsonPropertyName("acceptingPackages")] bool AcceptingPackages);

/// <summary>Resultado de un POST de paquete a otro nodo.</summary>
public sealed record RespuestaEnvio(int Codigo, string Descripcion, string Cuerpo)
{
    public bool Exitoso => Codigo == 202;
    public override string ToString() => $"{Codigo} {Descripcion}";
}

/// <summary>
/// Cliente HTTP hacia OTROS nodos (Modo Emisor). Es lo que hace la "conectividad entre dispositivos".
/// </summary>
/// <remarks>
/// Se usa una sola instancia de <see cref="HttpClient"/> para toda la aplicación (registrada
/// como singleton): crear uno por petición agota los sockets del sistema.
/// </remarks>
public sealed class ClienteNodos(HttpClient http)
{
    /// <summary>
    /// Convierte lo que escriba el usuario en una URL base.
    /// "192.168.1.14:5000" -> "http://192.168.1.14:5000/"; "http://x:8080" se respeta.
    /// Si no trae puerto se asume 5000 (el recomendado por la propuesta).
    /// </summary>
    public static Uri UrlBase(string direccion)
    {
        var d = direccion.Trim().TrimEnd('/');
        if (!d.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !d.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            d = "http://" + d;
        if (!Uri.TryCreate(d, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
            throw new ArgumentException($"Dirección inválida: '{direccion}'. Usa el formato IP:Puerto.");
        if (uri.IsDefaultPort && !direccion.Contains(':', StringComparison.Ordinal))
            uri = new UriBuilder(uri) { Port = 5000 }.Uri;
        return new Uri(uri.GetLeftPart(UriPartial.Authority) + "/");
    }

    /// <summary>"Ping" de descubrimiento. Null si el nodo no responde en 3 segundos.</summary>
    public async Task<EstadoNodoRemoto?> ConsultarEstado(string direccion, CancellationToken ct = default)
    {
        using var limite = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limite.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            return await http.GetFromJsonAsync<EstadoNodoRemoto>(new Uri(UrlBase(direccion), "api/status"), limite.Token);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Pide el certificado público del destino (<c>GET /api/certificate?algorithm=RSA|ECC</c>).
    /// Es una EXTENSIÓN propuesta por el Equipo 3: sin la llave pública del destino no se
    /// puede cifrar para él. Si el otro nodo no la implementa, el usuario puede subir su .pem.
    /// </summary>
    public async Task<string?> ObtenerCertificado(string direccion, string codigo, CancellationToken ct = default)
    {
        using var limite = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limite.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            using var r = await http.GetAsync(new Uri(UrlBase(direccion), $"api/certificate?algorithm={codigo}"), limite.Token);
            if (!r.IsSuccessStatusCode) return null;
            var pem = await r.Content.ReadAsStringAsync(limite.Token);
            return pem.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal) ? pem : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return null;
        }
    }

    /// <summary>
    /// Envía el .zip con <c>POST /api/requests/receive</c> como multipart/form-data en el campo
    /// <c>package</c>, con las cabeceras recomendadas X-Source-Node y X-Packet-Id.
    /// </summary>
    public async Task<RespuestaEnvio> EnviarPaquete(string direccion, string nombreZip, byte[] zip,
        string nodoOrigen, string packetId, CancellationToken ct = default)
    {
        using var contenido = new MultipartFormDataContent();
        var archivo = new ByteArrayContent(zip);
        archivo.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        contenido.Add(archivo, "package", nombreZip);

        using var peticion = new HttpRequestMessage(HttpMethod.Post, new Uri(UrlBase(direccion), "api/requests/receive"))
        {
            Content = contenido,
        };
        // Si el destino rechaza por tamaño (413) lo dice antes de que subamos todo el zip,
        // y recibimos el 413 en lugar de un "conexión interrumpida".
        peticion.Headers.ExpectContinue = true;
        peticion.Headers.Add("X-Source-Node", nodoOrigen);
        peticion.Headers.Add("X-Packet-Id", packetId);

        try
        {
            using var r = await http.SendAsync(peticion, ct);
            var cuerpo = await r.Content.ReadAsStringAsync(ct);
            return new RespuestaEnvio((int)r.StatusCode, r.ReasonPhrase ?? "", cuerpo);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            // 0 = no hubo respuesta HTTP (nodo apagado, firewall, IP equivocada).
            return new RespuestaEnvio(0, "Sin conexión", ex.Message);
        }
    }
}

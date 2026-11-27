using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Nodo03.Core.Cripto;
using Nodo03.Core.Protocolo;

namespace Nodo03.Web.Servicios;

/// <summary>
/// AUTODESCUBRIMIENTO UDP (sección 6.1): anuncia este nodo cada 30 s en el puerto 5099 y
/// escucha los anuncios de los demás.
/// </summary>
/// <remarks>
/// <code>
/// Envío:    al iniciar y cada 30 s → 255.255.255.255:5099 y el broadcast de cada subred
///           (ej. 192.168.1.255:5099), con la IP de la interfaz por la que sale.
/// Escucha:  0.0.0.0:5099 (con ReuseAddress para correr varios nodos en una PC).
///           Ignora los propios y los que no sean CC-BEACON / 2.0.
/// Apagado:  último anuncio con "status": "offline".
/// Además:   cada 30 s marca offline los nodos sin señal en 90 s.
/// </code>
/// </remarks>
public sealed class Descubrimiento(
    OpcionesNodo opciones, IdentidadNodo yo, DireccionPropia direccion,
    ServicioDirectorio directorio, ILogger<Descubrimiento> log) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    /// <summary>Anuncios procesados (se muestra en el panel).</summary>
    public int Recibidos => _recibidos;
    private int _recibidos;

    public bool Activo { get; private set; }

    /// <summary>JSON del anuncio (≤ 1024 bytes).</summary>
    public byte[] Anuncio(string ip, string estado = "online") => JsonSerializer.SerializeToUtf8Bytes(new
    {
        type = "CC-BEACON",
        protocolVersion = Identificadores.VersionProtocolo,
        nodeId = yo.NodoId,
        teamNumber = yo.Equipo,
        ip,
        httpPort = direccion.PuertoReal(),
        httpsPort = (int?)null,
        status = estado,
        algorithms = Diccionario.ProvistosPor(yo.Equipo).Select(a => a.Codigo).ToArray(),
        certificateThumbprintSha256 = yo.Huella,
        timestampUtc = Identificadores.FormatoFecha(DateTime.UtcNow),
    });

    protected override async Task ExecuteAsync(CancellationToken detener)
    {
        if (!opciones.Descubrimiento) return;
        await Task.Yield();

        using var socket = new UdpClient(AddressFamily.InterNetwork);
        try
        {
            socket.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.EnableBroadcast = true;
            socket.Client.Bind(new IPEndPoint(IPAddress.Any, opciones.PuertoUdp));
            Activo = true;
        }
        catch (SocketException ex)
        {
            log.LogWarning("No se pudo abrir UDP {Puerto} para descubrimiento: {Error}. Usa 'Buscar nodos' o el alta manual.", opciones.PuertoUdp, ex.Message);
            return;
        }

        var escucha = Escuchar(socket, detener);
        var proximoAnuncio = DateTime.MinValue;
        try
        {
            while (!detener.IsCancellationRequested)
            {
                if (DateTime.UtcNow >= proximoAnuncio)
                {
                    await Anunciar(socket, "online");
                    proximoAnuncio = DateTime.UtcNow.AddSeconds(Math.Max(1, opciones.IntervaloAnuncioSegundos));
                    try { await directorio.RevisarOffline(detener); } catch (Exception ex) when (ex is not OperationCanceledException) { log.LogDebug(ex, "RevisarOffline"); }
                }
                await Task.Delay(1000, detener);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            // 6.1: al apagarse DEBERÍA enviar un último anuncio "offline".
            try { await Anunciar(socket, "offline"); } catch (Exception) { }
            Activo = false;
        }
        await escucha.ContinueWith(_ => { });
    }

    /// <summary>Envía el anuncio a 255.255.255.255, al broadcast de cada subred y a los destinos extra.</summary>
    private async Task Anunciar(UdpClient socket, string estado)
    {
        var interfaces = DireccionPropia.Interfaces();
        var principal = direccion.Ip();
        var envios = new List<(IPEndPoint Destino, string Ip)> { (new IPEndPoint(IPAddress.Broadcast, opciones.PuertoUdp), principal) };
        envios.AddRange(interfaces.Select(i => (new IPEndPoint(i.Broadcast, opciones.PuertoUdp), i.Ip.ToString())));
        foreach (var extra in opciones.DestinosAnuncioExtra)
            if (IPAddress.TryParse(extra, out var ip)) envios.Add((new IPEndPoint(ip, opciones.PuertoUdp), IPAddress.IsLoopback(ip) ? "127.0.0.1" : principal));

        foreach (var (destino, ipAnunciada) in envios.DistinctBy(e => e.Destino.ToString()))
        {
            try { await socket.SendAsync(Anuncio(ipAnunciada, estado), destino); }
            catch (SocketException ex) { log.LogDebug("Anuncio a {Destino} falló: {Error}", destino, ex.Message); }
        }
    }

    private async Task Escuchar(UdpClient socket, CancellationToken detener)
    {
        while (!detener.IsCancellationRequested)
        {
            UdpReceiveResult r;
            try { r = await socket.ReceiveAsync(detener); }
            catch (OperationCanceledException) { break; }
            catch (SocketException) { continue; }
            catch (ObjectDisposedException) { break; }

            var anuncio = Interpretar(r.Buffer, yo.NodoId);
            if (anuncio is null) continue;
            Interlocked.Increment(ref _recibidos);
            // No bloqueamos la escucha mientras se verifica por HTTP.
            _ = Task.Run(async () =>
            {
                try { await directorio.ProcesarAnuncio(anuncio, detener); }
                catch (Exception ex) when (ex is not OperationCanceledException) { log.LogDebug(ex, "Anuncio de {Nodo}", anuncio.NodeId); }
            }, detener);
        }
    }

    /// <summary>
    /// Valida un datagrama: ≤ 1024 bytes, JSON, type CC-BEACON, protocolVersion 2.0, formatos de la
    /// sección 3 y que no sea el propio. Null = se ignora.
    /// </summary>
    public static Anuncio? Interpretar(byte[] datos, string miNodo)
    {
        if (datos.Length is 0 or > 1024) return null;
        try
        {
            var a = JsonSerializer.Deserialize<Anuncio>(datos, JsonWeb);
            if (a is null || a.Type != "CC-BEACON" || a.ProtocolVersion != Identificadores.VersionProtocolo) return null;
            if (a.NodeId == miNodo || !Identificadores.NodeId().IsMatch(a.NodeId ?? "")) return null;
            if (Identificadores.EquipoDeNodo(a.NodeId) != a.TeamNumber) return null;
            if (!IPAddress.TryParse(a.Ip, out _) || a.HttpPort is < 1 or > 65535) return null;
            if (!Identificadores.Huella().IsMatch(a.CertificateThumbprintSha256 ?? "")) return null;
            return a with { Algorithms = a.Algorithms ?? [], Status = a.Status ?? "online" };
        }
        catch (JsonException) { return null; }
    }
}

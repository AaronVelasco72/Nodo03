using System.Collections.Concurrent;
using System.Threading.Channels;

namespace Nodo03.Web.Servicios;

/// <summary>Evento que se empuja a la interfaz en tiempo real.</summary>
/// <param name="Tipo">solicitud | decision | envio | rebote | error</param>
/// <param name="Datos">Objeto que se serializa a JSON.</param>
public sealed record EventoUi(string Tipo, object Datos);

/// <summary>
/// ALERTAMIENTO en tiempo real hacia los navegadores abiertos, usando Server-Sent Events (SSE).
/// </summary>
/// <remarks>
/// <para>Cada pestaña del navegador abre <c>GET /api/local/eventos</c> y se queda escuchando.
/// Cuando llega un paquete, el receptor llama <see cref="Publicar"/> y el evento aparece al
/// instante en todas las pestañas: suena la alerta, sale la notificación del sistema y se
/// actualiza el contador de la bandeja.</para>
/// <para>SSE se eligió sobre WebSockets porque el flujo es de una sola vía (servidor -> navegador),
/// funciona sobre HTTP normal y el navegador reconecta solo si se cae.</para>
/// <para><b>Concurrencia:</b> cada suscriptor tiene su propio canal acotado (100 eventos). Si un
/// navegador lento se atrasa, se descartan sus eventos más viejos en lugar de frenar al
/// receptor de paquetes.</para>
/// </remarks>
public sealed class BusEventos
{
    private readonly ConcurrentDictionary<Guid, Channel<EventoUi>> _suscriptores = new();

    /// <summary>Número de pestañas conectadas (se muestra en el panel).</summary>
    public int Conectados => _suscriptores.Count;

    public (Guid id, ChannelReader<EventoUi> lector) Suscribir()
    {
        var canal = Channel.CreateBounded<EventoUi>(new BoundedChannelOptions(100)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });
        var id = Guid.NewGuid();
        _suscriptores[id] = canal;
        return (id, canal.Reader);
    }

    public void Desuscribir(Guid id)
    {
        if (_suscriptores.TryRemove(id, out var canal)) canal.Writer.TryComplete();
    }

    /// <summary>Envía el evento a todos los suscriptores. Nunca bloquea.</summary>
    public void Publicar(string tipo, object datos)
    {
        var evento = new EventoUi(tipo, datos);
        foreach (var canal in _suscriptores.Values) canal.Writer.TryWrite(evento);
    }
}

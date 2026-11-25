using System.Threading.Channels;
using Nodo03.Core.Datos;

namespace Nodo03.Web.Servicios;

/// <summary>
/// Ping-pong AUTOMÁTICO: trabajador en segundo plano que regresa las pelotas solo.
/// </summary>
/// <remarks>
/// <para>Cuando "Rebotar automáticamente" está encendido en Ajustes, el receptor mete el id
/// de la solicitud en una cola (<see cref="Channel{T}"/>). Este servicio la saca y hace,
/// sin intervención humana: Aceptar → Descifrar → Re-cifrar → Enviar de regreso.</para>
/// <para>¿Por qué una cola y no hacerlo dentro de la petición HTTP? Porque el emisor está
/// esperando la respuesta 202; si en ese momento le mandáramos el rebote, los dos nodos
/// quedarían esperándose. Con la cola, el receptor responde 202 de inmediato y el rebote
/// sale un momento después.</para>
/// <para>El límite <c>MaxRebotes</c> corta el rally para que dos nodos automáticos no jueguen
/// para siempre.</para>
/// </remarks>
public sealed class MotorPingPong(IServiceProvider servicios, ILogger<MotorPingPong> log) : BackgroundService
{
    private readonly Channel<string> _cola = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true });

    /// <summary>Mete una solicitud a la cola de rebotes. No bloquea.</summary>
    public void Encolar(string solicitudId) => _cola.Writer.TryWrite(solicitudId);

    protected override async Task ExecuteAsync(CancellationToken detener)
    {
        await foreach (var id in _cola.Reader.ReadAllAsync(detener))
        {
            try
            {
                var ajustes = servicios.GetRequiredService<AjustesNodo>();
                var repo = servicios.GetRequiredService<RepositorioNodo>();
                var envio = servicios.GetRequiredService<ServicioEnvio>();
                var bus = servicios.GetRequiredService<BusEventos>();

                await Task.Delay(ajustes.Actual.PausaRebotesMs, detener);

                // Aceptar de forma atómica: si el usuario ya la aceptó/rechazó a mano, se respeta.
                var consulta = repo.Aceptar(id);
                if (consulta is null) continue;
                bus.Publicar("decision", new { id, estado = EstadosSolicitud.Aceptada, automatico = true });

                var r = await envio.Rebotar(consulta.Id, detener);
                if (!r.Ok) log.LogWarning("Rebote automático falló: {Mensaje}", r.Mensaje);
            }
            catch (OperationCanceledException) when (detener.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // Un rebote fallido nunca debe tumbar al trabajador.
                log.LogError(ex, "Error en rebote automático de {Id}", id);
                servicios.GetRequiredService<RepositorioNodo>().Registrar("error", "Rebote automático falló: " + ex.Message);
            }
        }
    }
}

using System.Text.Json;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;

namespace Nodo03.Web.Servicios;

/// <summary>Lo que el endpoint de recepción necesita para responder.</summary>
public sealed record ResultadoRecepcion(
    int CodigoHttp, string Mensaje, Solicitud? Solicitud, ResultadoValidacion? Validacion, bool Duplicado = false);

/// <summary>
/// MODO RECEPTOR: valida un .zip entrante y lo registra en la bandeja "Solicitudes".
/// </summary>
/// <remarks>
/// <para>Implementa las 5 "Validaciones automáticas al recibir" de la sección 3.2:</para>
/// <code>
/// 1. ¿Es zip y no excede el límite?          no -> 400 / 413   (el 413 lo da el endpoint)
/// 2. ¿Trae exactamente los 3 archivos?        no -> 400
/// 3. ¿SHA-256 de datos.enc coincide?          no -> 422
/// 4. ¿Firma X.509 válida?                     no -> 422
/// 5. Registrar en Solicitudes como Pendiente  -> 202
/// </code>
/// <para><b>Decisión de diseño:</b> los paquetes que fallan en 3 o 4 (422) también se guardan,
/// pero directamente como <c>Rechazada</c> y con sello "Inválida", para que quede evidencia
/// y el usuario vea el intento en la bandeja. Nunca llegan a "Pendiente".</para>
///
/// <para><b>Concurrencia:</b></para>
/// <list type="bullet">
///   <item>Un <see cref="SemaphoreSlim"/> limita cuántos paquetes se validan a la vez (2 × núcleos).
///   Si llegan 200 al mismo tiempo, los demás esperan su turno en lugar de saturar la memoria.</item>
///   <item>Los duplicados (mismo packetId) se resuelven con el índice UNIQUE de la base: aunque
///   lleguen 20 copias simultáneas, solo una se inserta; las demás reciben 202 con
///   <c>duplicate: true</c> (operación idempotente: reintentar es seguro).</item>
/// </list>
/// </remarks>
public sealed class ServicioRecepcion(
    RepositorioNodo repo, AlmacenPaquetes almacen, BusEventos bus, AjustesNodo ajustes,
    IdentidadNodo identidad, MotorPingPong pingPong, ILogger<ServicioRecepcion> log)
{
    private static readonly SemaphoreSlim Turnos = new(Environment.ProcessorCount * 2);

    /// <summary>El detalle se guarda en camelCase, igual que lo entrega la API a la interfaz.</summary>
    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    public async Task<ResultadoRecepcion> Recibir(byte[] zip, string nombreZip, string ipRemota, CancellationToken ct = default)
    {
        if (!ajustes.Actual.AceptandoPaquetes)
            return new ResultadoRecepcion(503, "El nodo no está aceptando paquetes en este momento.", null, null);

        await Turnos.WaitAsync(ct);
        try
        {
            return Procesar(zip, nombreZip, ipRemota);
        }
        finally
        {
            Turnos.Release();
        }
    }

    private ResultadoRecepcion Procesar(byte[] zip, string nombreZip, string ipRemota)
    {
        // ---- Pasos 1 y 2: estructura ----
        PaqueteLeido paquete;
        try
        {
            paquete = EmpaquetadorZip.Leer(zip);
        }
        catch (PaqueteMalformadoException ex)
        {
            log.LogWarning("Paquete malformado de {Ip}: {Motivo}", ipRemota, ex.Message);
            repo.Registrar("error", $"Paquete malformado de {ipRemota}: {ex.Message}");
            bus.Publicar("error", new { mensaje = $"Paquete malformado de {ipRemota}", detalle = ex.Message });
            return new ResultadoRecepcion(400, ex.Message, null, null);
        }

        var m = paquete.Manifiesto;

        // ¿Ya lo tenemos? (reintento del emisor). Respuesta idempotente.
        if (repo.ObtenerSolicitudPorPaquete(m.PacketId) is { } existente)
            return new ResultadoRecepcion(202, "Paquete ya recibido anteriormente.", existente, null, Duplicado: true);

        // ---- Pasos 3 y 4: integridad y firma ----
        var validacion = ValidadorPaquete.Validar(paquete, nombreZip);

        // ---- Paso 5: registrar ----
        var s = new Solicitud
        {
            PacketId = m.PacketId,
            NombreZip = AlmacenPaquetes.NombreSeguro(nombreZip),
            OrigenIp = ipRemota,
            NodoOrigen = string.IsNullOrWhiteSpace(m.SourceNode) ? "desconocido" : m.SourceNode,
            DireccionRespuesta = m.SourceIp ?? "",
            AlgoritmoCodigo = m.AlgorithmCode ?? "",
            Algoritmo = m.Algorithm ?? "",
            Modo = ModosCarga.Normalizar(m.PayloadMode),
            NombreOriginal = m.OriginalFileName ?? "",
            TamanoOriginal = m.OriginalSizeBytes,
            Sha256 = validacion.Sha256Calculado,
            Verificacion = validacion.Etiqueta,
            DetalleJson = JsonSerializer.Serialize(validacion, JsonWeb),
            Estado = validacion.Valido ? EstadosSolicitud.Pendiente : EstadosSolicitud.Rechazada,
            DecididoUtc = validacion.Valido ? null : DateTime.UtcNow,
            Salto = m.ParametroEntero(ServicioPaquetes.ParamSalto),
            RallyId = m.Parametro(ServicioPaquetes.ParamRally) ?? m.PacketId,
        };
        s.RutaZip = almacen.Guardar(validacion.Valido ? "recibidos" : "invalidos", s.Id, s.NombreZip, zip);

        if (!repo.InsertarSolicitud(s))
        {
            // Otra petición idéntica ganó la carrera entre nuestra consulta y el INSERT.
            almacen.Borrar(s.RutaZip);
            return new ResultadoRecepcion(202, "Paquete ya recibido anteriormente.",
                repo.ObtenerSolicitudPorPaquete(m.PacketId), null, Duplicado: true);
        }

        var resumen = $"{s.NodoOrigen} ({ipRemota}) envió {s.NombreZip} · {s.AlgoritmoCodigo} · {s.Verificacion}";
        repo.Registrar(validacion.Valido ? "recepcion" : "rechazo-automatico", resumen, s.RallyId, s.Salto);
        bus.Publicar("solicitud", new
        {
            id = s.Id, nodo = s.NodoOrigen, ip = ipRemota, zip = s.NombreZip, algoritmo = s.AlgoritmoCodigo,
            verificacion = s.Verificacion, estado = s.Estado, salto = s.Salto, rallyId = s.RallyId,
            pendientes = repo.ContarPendientes(),
        });
        log.LogInformation("Recibido {Zip} de {Ip}: {Etiqueta}", s.NombreZip, ipRemota, s.Verificacion);

        if (!validacion.Valido)
            return new ResultadoRecepcion(422, "Integridad o firma inválida: " + string.Join(" ", validacion.Errores), s, validacion);

        // ¿Pelota de ping-pong que hay que regresar sola?
        var a = ajustes.Actual;
        if (a.RebotarAutomatico
            && CodigosAlgoritmo.LoImplementaEsteNodo(s.AlgoritmoCodigo)
            && ajustes.PuedeDescifrar(s.AlgoritmoCodigo)
            && identidad.EsMiHuella(m.Parametro("recipientThumbprintSha256"))
            && s.Salto < a.MaxRebotes
            && !string.IsNullOrWhiteSpace(s.DireccionRespuesta))
        {
            pingPong.Encolar(s.Id);
        }

        return new ResultadoRecepcion(202, "Solicitud recibida; pendiente de aprobación.", s, validacion);
    }
}

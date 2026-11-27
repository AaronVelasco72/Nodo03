using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;

namespace Nodo03.Web.Servicios;

/// <summary>
/// ROL RECEPTOR: valida un .zip entrante (sección 13.1) y lo registra en la bandeja Solicitudes.
/// </summary>
/// <remarks>
/// <code>
///  1  E-SIZE (413)            ← lo revisa el endpoint antes de leer el cuerpo
///  2-5 E-ZIP-INVALID / E-ZIP-STRUCTURE / E-ZIP-BOMB / E-MANIFEST (400)   ← EmpaquetadorZip.Leer
///  6-13 E-VERSION … E-TIMESTAMP (400/422)                                ← ValidadorPaquete.Validar
///  confianza: fijado y otra huella → 403 E-CERT-UNTRUSTED
///             no fijado → se acepta como "Remitente no confirmado"
///  14 E-DUPLICATE (409)       ← índice UNIQUE de la base (también resuelve carreras)
///  → 202 { packetId, status: "Pendiente", receivedAtUtc }
/// </code>
/// <para><b>Evidencia:</b> si el manifiesto se pudo leer pero falló una validación de 6 a 13 o la
/// confianza, el zip se guarda en <c>invalidos/</c> y aparece en la bandeja como "Inválida"
/// (Rechazada). Así el usuario ve el intento y el motivo.</para>
/// <para><b>Concurrencia:</b> un <see cref="SemaphoreSlim"/> limita cuántos paquetes se
/// validan a la vez (2 × núcleos); los demás esperan turno.</para>
/// </remarks>
public sealed class ServicioRecepcion(
    RepositorioNodo repo, AlmacenPaquetes almacen, BusEventos bus, AjustesNodo ajustes, OpcionesNodo opciones,
    ServicioDirectorio directorio, MotorPingPong pingPong, ILogger<ServicioRecepcion> log)
{
    private readonly SemaphoreSlim Turnos = new(Environment.ProcessorCount * 2);

    /// <summary>Procesa el paquete. Lanza <see cref="ErrorProtocolo"/> con el código del Anexo B.</summary>
    public async Task<Solicitud> Recibir(byte[] zip, string nombreZip, string ipRemota, CancellationToken ct = default)
    {
        if (!ajustes.Actual.AceptandoPaquetes)
            throw new ErrorProtocolo("E-BUSY", $"{opciones.NodoId} no está aceptando paquetes en este momento.");

        await Turnos.WaitAsync(ct);
        try { return Procesar(zip, nombreZip, ipRemota); }
        finally { Turnos.Release(); }
    }

    private Solicitud Procesar(byte[] zip, string nombreZip, string ipRemota)
    {
        // ---- 2 a 5: zip y manifiesto ----
        PaqueteLeido p;
        try { p = EmpaquetadorZip.Leer(zip); }
        catch (ErrorProtocolo e)
        {
            repo.Registrar("error", $"Paquete de {ipRemota} rechazado: {e.Codigo} {e.Message}");
            bus.Publicar("error", new { mensaje = $"Paquete de {ipRemota} rechazado ({e.Codigo})", detalle = e.Message });
            throw;
        }
        var m = p.Manifiesto;
        var s = NuevaSolicitud(m, nombreZip, ipRemota);

        // ---- 6 a 13 y confianza ----
        try
        {
            var info = ValidadorPaquete.Validar(p, DateTime.UtcNow);
            s.Verificacion = directorio.ConfianzaDe(m.SourceNode, info.Huella);
            s.Detalle = s.Verificacion == Verificaciones.NoConfirmado
                ? $"Firma válida, pero {m.SourceNode} no está fijado en el directorio (confirma su huella en Nodos)."
                : $"Firma de {m.SourceNode} verificada con la huella confirmada.";
        }
        catch (ErrorProtocolo e)
        {
            // Evidencia en la bandeja como "Inválida" (Rechazada).
            s.Verificacion = Verificaciones.Invalida;
            s.Detalle = $"{e.Codigo}: {e.Message}";
            s.Estado = EstadosSolicitud.Rechazada;
            s.DecididoUtc = DateTime.UtcNow;
            s.RutaZip = almacen.Guardar("invalidos", s.Id, s.NombreZip, zip);
            repo.InsertarSolicitud(s);
            Avisar(s, "rechazo-automatico");
            throw;
        }

        // ---- 14: duplicado ----
        if (repo.ExistePaquete(m.PacketId))
            throw new ErrorProtocolo("E-DUPLICATE", $"El packetId {m.PacketId} ya se había recibido.");
        s.RutaZip = almacen.Guardar("recibidos", s.Id, s.NombreZip, zip);
        if (!repo.InsertarSolicitud(s))
        {
            // Otra copia idéntica ganó la carrera entre la consulta y el INSERT.
            almacen.Borrar(s.RutaZip);
            throw new ErrorProtocolo("E-DUPLICATE", $"El packetId {m.PacketId} ya se había recibido.");
        }
        Avisar(s, "recepcion");

        // ¿Pelota de ping-pong que hay que regresar sola? Solo RSA/ECC: no necesitan secretos del
        // usuario (la llave la guarda EQ03 con keyId), así que el rebote puede ser automático.
        var a = ajustes.Actual;
        if (a.RebotarAutomatico && Diccionario.Implementados.Contains(s.AlgoritmoCodigo)
            && m.PacketType == TiposPaquete.Package && m.KeyRef is not null
            && s.Salto < a.MaxRebotes && !string.IsNullOrWhiteSpace(s.DireccionRespuesta))
            pingPong.Encolar(s.Id);

        return s;
    }

    private static Solicitud NuevaSolicitud(Manifiesto m, string nombreZip, string ip)
    {
        var alg = Diccionario.PorCodigo(m.AlgorithmCode);
        return new Solicitud
        {
            PacketId = m.PacketId,
            NombreZip = AlmacenPaquetes.NombreSeguro(nombreZip),
            OrigenIp = ip,
            NodoOrigen = m.SourceNode,
            NodoProductor = m.ProducerNode,
            DireccionRespuesta = m.SourceIp,
            AlgoritmoCodigo = m.AlgorithmCode,
            AlgoritmoNombre = string.IsNullOrWhiteSpace(m.AlgorithmName) ? alg?.Nombre ?? "" : m.AlgorithmName,
            Operacion = m.Operation,
            OperacionNombre = string.IsNullOrWhiteSpace(m.OperationName) ? alg?.NombreOperacion(m.Operation) ?? "" : m.OperationName,
            Modo = m.PayloadMode,
            NombreOriginal = m.OriginalFileName,
            TamanoOriginal = m.OriginalSizeBytes,
            Sha256 = m.EncryptedSha256,
            Salto = int.TryParse(m.Parametro("hop"), out var h) ? h : 0,
            RallyId = m.Parametro("rallyId") ?? m.PacketId,
        };
    }

    private void Avisar(Solicitud s, string tipo)
    {
        var resumen = $"{s.NodoOrigen} ({s.OrigenIp}) envió {s.NombreZip} · {s.AlgoritmoCodigo} {s.OperacionNombre} · {s.Verificacion}";
        repo.Registrar(tipo, resumen, s.RallyId, s.Salto);
        bus.Publicar("solicitud", new
        {
            id = s.Id, nodo = s.NodoOrigen, ip = s.OrigenIp, zip = s.NombreZip, algoritmo = s.AlgoritmoCodigo,
            operacion = s.OperacionNombre, verificacion = s.Verificacion, estado = s.Estado, salto = s.Salto,
            rallyId = s.RallyId, pendientes = repo.ContarPendientes(),
        });
        log.LogInformation("Bandeja: {Resumen}", resumen);
    }
}

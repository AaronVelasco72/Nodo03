using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;

namespace Nodo03.Web.Servicios;

/// <summary>Lo que se le muestra al usuario después de mandar a una bandeja.</summary>
public sealed record ResultadoEnvio(bool Ok, string Mensaje, string? ConsultaId = null, string? NombreZip = null, int? CodigoHttp = null);

/// <summary>
/// ROL EMISOR: manda paquetes de Consultas a la bandeja de otro nodo
/// (<c>POST /api/requests/receive</c>, sección 11.3) y juega PING-PONG.
/// </summary>
/// <remarks>
/// <para>Siempre se REEMPAQUETA (9.6) antes de mandar: se conservan datos.enc,
/// publicParameters, keyRef, producerNode y algoritmo; cambian packetId, timestampUtc,
/// sourceNode (= EQ03) y la firma. Así el receptor ve quién lo manda, quién lo produjo, y la
/// fecha siempre cae dentro de su ventana de ±10 min aunque el paquete sea viejo.</para>
/// </remarks>
public sealed class ServicioEnvio(
    IdentidadNodo yo, RepositorioNodo repo, AlmacenPaquetes almacen, ClienteNodos cliente, BusEventos bus,
    ProveedorLocal proveedor, ServicioSolicitante solicitante, DireccionPropia direccion, ILogger<ServicioEnvio> log)
{
    /// <summary>
    /// Manda el paquete de una Consulta a la bandeja de <paramref name="destino"/>
    /// (nodeId del directorio, ej. "EQ05", o "IP:puerto").
    /// </summary>
    public async Task<ResultadoEnvio> EnviarABandeja(string consultaId, string destino, CancellationToken ct = default)
    {
        var c = repo.ObtenerConsulta(consultaId) ?? throw new ErrorOperacionException("No existe ese registro.");
        var (nodoRemoto, dir) = Resolver(destino);
        var leido = EmpaquetadorZip.Leer(almacen.Leer(c.RutaZip));
        var nuevo = proveedor.Reempaquetar(leido, direccion.Obtener());
        almacen.Guardar("enviados", Guid.NewGuid().ToString("N"), nuevo.NombreZip, nuevo.Zip);

        var r = await cliente.EnviarABandeja(dir, nuevo.NombreZip, nuevo.Zip, nuevo.Manifiesto.PacketId, ct);
        var ok = r.Codigo == 202;
        repo.ActualizarEnvio(c.Id, nodoRemoto, dir, r.ToString());
        var tipo = c.Salto > 0 ? "rebote" : "envio";
        repo.Registrar(tipo, $"{nuevo.NombreZip} (producido por {nuevo.Manifiesto.ProducerNode}) → {nodoRemoto} {dir}: {r}", c.RallyId, c.Salto);
        bus.Publicar(tipo, new { zip = nuevo.NombreZip, destino = $"{nodoRemoto} {dir}", resultado = r.ToString(), ok, salto = c.Salto, rallyId = c.RallyId, algoritmo = c.AlgoritmoCodigo });
        log.LogInformation("{Tipo} {Zip} a {Destino}: {Resultado}", tipo, nuevo.NombreZip, dir, r);
        return new ResultadoEnvio(ok, ok ? $"Entregado: quedó Pendiente en la bandeja de {nodoRemoto}." : Fallo(r, nodoRemoto), c.Id, nuevo.NombreZip, r.Codigo);
    }

    /// <summary>
    /// PING-PONG: recibo la pelota → inverse (descifrar) → forward con el mismo algoritmo y la
    /// misma llave → la regreso a la bandeja de quien me la mandó (manifest.sourceIp).
    /// </summary>
    public async Task<ResultadoEnvio> Rebotar(string consultaId, Dictionary<string, string>? secretos, CancellationToken ct = default)
    {
        var c = repo.ObtenerConsulta(consultaId) ?? throw new ErrorOperacionException("No existe ese registro.");
        if (c.Origen != OrigenesConsulta.Recibido) throw new ErrorOperacionException("Solo se puede rebotar una pelota que se RECIBIÓ en la bandeja.");
        var m = EmpaquetadorZip.Leer(almacen.Leer(c.RutaZip)).Manifiesto;
        if (m.PacketType != TiposPaquete.Package) throw new ErrorOperacionException("Solo se rebota un paquete 'package'.");
        if (string.IsNullOrWhiteSpace(m.SourceIp)) throw new ErrorOperacionException("El paquete no indica sourceIp: no hay a dónde regresarlo.");

        // 1) inverse (local si la llave es mía; si no, delegado al dueño)
        var abierto = await solicitante.Inverse(c.Id, secretos, ct);
        // 2) forward con el mismo algoritmo (y la misma llave si usa keyId)
        var salto = c.Salto + 1;
        var alg = Diccionario.PorCodigo(m.AlgorithmCode)!;
        var nuevo = await solicitante.Forward(new EntradaForward(m.AlgorithmCode, abierto.Original!, m.PayloadMode, m.OriginalFileName,
            new Dictionary<string, string>(StringComparer.Ordinal), secretos, alg.UsaKeyId ? m.KeyRef?.KeyId : null), ct, salto, c.RallyId, c.Id);
        // 3) regresar
        var r = await EnviarABandeja(nuevo.Consulta.Id, m.SourceIp, ct);
        return r with { Mensaje = r.Ok ? $"Pelota regresada a {m.SourceNode} (rebote #{salto})." : r.Mensaje };
    }

    private (string Nodo, string Direccion) Resolver(string destino)
    {
        destino = destino.Trim();
        if (Identificadores.NodeId().IsMatch(destino))
        {
            var n = repo.ObtenerNodo(destino) ?? throw new ErrorOperacionException($"{destino} no está en el directorio.");
            if (n.Alerta) throw new ErrorOperacionException($"{destino} presenta una huella distinta a la confirmada. Revísala en Nodos.");
            return (n.NodeId, n.Direccion);
        }
        var url = ClienteNodos.UrlBase(destino);
        var dir = $"{url.Host}:{url.Port}";
        var conocido = repo.ListarNodos().FirstOrDefault(n => n.Direccion == dir);
        if (conocido?.Alerta == true) throw new ErrorOperacionException($"{conocido.NodeId} presenta una huella distinta a la confirmada.");
        return (conocido?.NodeId ?? dir, dir);
    }

    private string Fallo(RespuestaNodo r, string destino)
    {
        if (r.Codigo == 0) return $"No se pudo conectar con {destino}. ¿Está encendido, en la misma red y con el puerto abierto?";
        var (codigo, detalle) = r.Problema();
        return codigo switch
        {
            "E-DUPLICATE" => $"{destino} ya tenía ese paquete (409).",
            "E-CERT-UNTRUSTED" => $"{destino} tiene fijada otra huella para {yo.NodoId} (403). Pídele que vuelva a confirmar la huella de {yo.NodoId}.",
            "E-BUSY" => $"{destino} no está aceptando paquetes (503).",
            "E-SIZE" => $"{destino} dice que el paquete es muy grande (413).",
            _ => $"{destino} respondió {r.Codigo} {codigo}: {detalle}",
        };
    }
}

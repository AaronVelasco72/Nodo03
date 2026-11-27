using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Web.Servicios;

namespace Nodo03.Web.Endpoints;

/// <summary>
/// API PRIVADA que usa la interfaz web (todo bajo <c>/api/local</c>). No es parte del estándar.
/// </summary>
/// <remarks>
/// Protegida por <see cref="ProtegerAdministracion"/>: por defecto solo responde a peticiones de
/// la misma máquina, para que otro nodo de la LAN no pueda aceptar, rechazar o descifrar
/// nuestras solicitudes.
/// </remarks>
public static class LocalEndpoints
{
    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    /// <summary>Middleware: bloquea /api/local desde otras máquinas salvo que Ajustes lo permita.</summary>
    public static void ProtegerAdministracion(WebApplication app)
    {
        app.Use(async (ctx, siguiente) =>
        {
            if (ctx.Request.Path.StartsWithSegments("/api/local"))
            {
                var ajustes = ctx.RequestServices.GetRequiredService<AjustesNodo>();
                if (!ajustes.Actual.AdminRemoto && !EsLocal(ctx.Connection.RemoteIpAddress))
                {
                    ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await ctx.Response.WriteAsJsonAsync(new
                    {
                        error = "La administración del nodo solo está permitida desde la misma computadora. Actívala en Ajustes > Administración remota.",
                    });
                    return;
                }
            }
            await siguiente(ctx);
        });
    }

    /// <summary>¿La petición viene de esta misma máquina?</summary>
    public static bool EsLocal(IPAddress? ip) => ip is null || IPAddress.IsLoopback(ip);

    public static void Mapear(WebApplication app)
    {
        var api = app.MapGroup("/api/local");

        // ------------------------------------------------------------------ Identidad / panel

        api.MapGet("/identidad", (IdentidadNodo yo, DireccionPropia dir, BusEventos bus, RepositorioNodo repo,
            OpcionesNodo op, Descubrimiento udp) => new
        {
            nodoId = yo.NodoId,
            equipo = yo.Equipo,
            protocolo = Identificadores.VersionProtocolo,
            direccion = dir.Obtener(),
            puerto = dir.PuertoReal(),
            provee = Diccionario.ProvistosPor(yo.Equipo).Select(a => a.Codigo),
            pendientes = repo.ContarPendientes(),
            consultas = repo.ContarConsultas(),
            llaves = repo.ContarLlaves(),
            nodos = repo.ListarNodos().Count(n => n.Estado == "online"),
            pestanasConectadas = bus.Conectados,
            udp = new { activo = udp.Activo, puerto = op.PuertoUdp, recibidos = udp.Recibidos, intervalo = op.IntervaloAnuncioSegundos },
            certificado = new
            {
                sujeto = yo.Certificado.Subject,
                huella = yo.Huella,
                serie = yo.Certificado.SerialNumber,
                desde = yo.Certificado.NotBefore.ToUniversalTime(),
                hasta = yo.Certificado.NotAfter.ToUniversalTime(),
                llave = "RSA-2048",
                firmaCertificado = "sha256WithRSAEncryption",
                firmaManifiestos = FirmaManifiesto.Algoritmo,
            },
        });

        api.MapGet("/certificado", (IdentidadNodo yo) =>
            Results.File(Encoding.ASCII.GetBytes(yo.CertificadoPem), "application/x-pem-file", $"{yo.NodoId}_certificado.pem"));

        api.MapGet("/llaves", (RepositorioNodo repo) => repo.ListarLlaves().Select(k => new
        {
            k.KeyId, k.Algoritmo, k.CreadaUtc, restringida = k.Permitidos.Length > 0, permitidos = k.Permitidos,
        }));

        api.MapGet("/bitacora", (RepositorioNodo repo, int? limite) => repo.ListarBitacora(limite ?? 80));

        // ------------------------------------------------------------------ Alertas en tiempo real (SSE)

        api.MapGet("/eventos", async (HttpContext ctx, BusEventos bus) =>
        {
            ctx.Response.Headers.ContentType = "text/event-stream";
            ctx.Response.Headers.CacheControl = "no-cache";
            ctx.Response.Headers["X-Accel-Buffering"] = "no";
            var (id, lector) = bus.Suscribir();
            try
            {
                await ctx.Response.WriteAsync(": conectado\n\n", ctx.RequestAborted);
                await ctx.Response.Body.FlushAsync(ctx.RequestAborted);
                while (!ctx.RequestAborted.IsCancellationRequested)
                {
                    // Espera un evento o 15 s; si no hay, manda un "latido" para que no se cierre la conexión.
                    using var latido = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
                    latido.CancelAfter(TimeSpan.FromSeconds(15));
                    try
                    {
                        var e = await lector.ReadAsync(latido.Token);
                        await ctx.Response.WriteAsync($"event: {e.Tipo}\ndata: {JsonSerializer.Serialize(e.Datos, JsonWeb)}\n\n", ctx.RequestAborted);
                    }
                    catch (OperationCanceledException) when (!ctx.RequestAborted.IsCancellationRequested)
                    {
                        await ctx.Response.WriteAsync(": latido\n\n", ctx.RequestAborted);
                    }
                    await ctx.Response.Body.FlushAsync(ctx.RequestAborted);
                }
            }
            catch (OperationCanceledException) { /* el navegador cerró la pestaña */ }
            finally { bus.Desuscribir(id); }
        });

        // ------------------------------------------------------------------ Los 21 algoritmos

        api.MapGet("/algoritmos", (IdentidadNodo yo, ServicioDirectorio dir, AjustesNodo ajustes) =>
            Diccionario.Todos.Select(a =>
            {
                var propio = Diccionario.ProvistosPor(yo.Equipo).Contains(a);
                var (n, motivo) = propio ? (null, "") : dir.Proveedor(a);
                return new
                {
                    id = a.Id, codigo = a.Codigo, nombre = a.Nombre, categoria = a.Categoria,
                    dueno = a.NodoDueno ?? "reservado", forward = a.Forward, inverse = a.Inverse,
                    llave = a.Llave.ToString(), secretos = a.Secretos,
                    propio, habilitado = !propio || ajustes.Habilitado(a.Codigo),
                    disponible = propio ? ajustes.Habilitado(a.Codigo) : n is not null,
                    ejecutor = propio ? yo.NodoId : n?.NodeId,
                    motivo = propio ? (ajustes.Habilitado(a.Codigo) ? "Local (este nodo)" : "Deshabilitado en Ajustes") : n is null ? motivo : $"Delegado a {n.NodeId} · {n.Direccion}",
                };
            }));

        // Perfil 10.4 del dueño (para armar el formulario de parámetros).
        api.MapGet("/perfil/{codigo}", async (string codigo, IdentidadNodo yo, ServicioDirectorio dir, ClienteNodos cliente, HttpContext ctx) =>
        {
            var alg = Diccionario.PorCodigo(codigo);
            if (alg is null) return Results.NotFound(new { error = "Algoritmo desconocido." });
            string direccion;
            if (Diccionario.ProvistosPor(yo.Equipo).Contains(alg)) direccion = $"127.0.0.1:{ctx.RequestServices.GetRequiredService<DireccionPropia>().PuertoReal()}";
            else
            {
                var (n, motivo) = dir.Proveedor(alg);
                if (n is null) return Results.Ok(new { disponible = false, motivo, perfil = (JsonNode?)null });
                direccion = n.Direccion;
            }
            using var doc = await cliente.Perfil(direccion, ctx.RequestAborted);
            var perfil = doc?.RootElement.TryGetProperty("algorithms", out var lista) == true
                ? lista.EnumerateArray().FirstOrDefault(x => x.TryGetProperty("algorithmCode", out var c) && c.GetString() == alg.Codigo)
                : default;
            return Results.Ok(new
            {
                disponible = true,
                motivo = "",
                perfil = perfil.ValueKind == JsonValueKind.Object ? JsonNode.Parse(perfil.GetRawText()) : null,
            });
        });

        // ------------------------------------------------------------------ forward (cifrar / hash / firmar / ocultar…)

        api.MapPost("/forward", async (HttpRequest req, ServicioSolicitante solicitante, CancellationToken ct) =>
        {
            if (!req.HasFormContentType) return Results.BadRequest(new { error = "Se esperaba un formulario." });
            var f = await req.ReadFormAsync(ct);
            var modo = ModosCarga.Normalizar(f["modo"]);
            byte[] contenido; string nombre;
            if (modo == ModosCarga.Texto)
            {
                contenido = Encoding.UTF8.GetBytes(f["texto"].ToString());
                nombre = "mensaje.txt";
            }
            else
            {
                var archivo = f.Files.GetFile("archivo");
                if (archivo is null) return Results.BadRequest(new { error = "Falta el archivo o imagen." });
                contenido = await Bytes(archivo, ct);
                nombre = Path.GetFileName(archivo.FileName);
            }
            var cover = f.Files.GetFile("cover") is { } cf ? await Bytes(cf, ct) : null;
            return await Ejecutar(async () =>
            {
                var r = await solicitante.Forward(new EntradaForward(
                    f["algoritmo"].ToString().Trim().ToUpperInvariant(), contenido, modo, nombre,
                    ADiccionario(f["opciones"]), ADiccionario(f["secretos"]), Nulo(f["keyId"]), cover), ct,
                    nodoForzado: Nulo(f["nodo"]));
                return new { consulta = r.Consulta, ejecutor = r.Ejecutor, delegado = r.Delegado };
            });
        });

        // ------------------------------------------------------------------ Solicitudes (bandeja)

        api.MapGet("/solicitudes", (RepositorioNodo repo, string? estado) =>
            repo.ListarSolicitudes(string.IsNullOrWhiteSpace(estado) ? null : estado));

        api.MapGet("/solicitudes/{id}", (string id, RepositorioNodo repo, AlmacenPaquetes almacen) =>
        {
            var s = repo.ObtenerSolicitud(id);
            if (s is null) return Results.NotFound();
            JsonNode? manifiesto = null;
            try { manifiesto = JsonNode.Parse(EmpaquetadorZip.Leer(almacen.Leer(s.RutaZip)).ManifiestoJson); } catch (ErrorProtocolo) { }
            return Results.Ok(new { solicitud = s, manifiesto });
        });

        api.MapPost("/solicitudes/{id}/aceptar", (string id, RepositorioNodo repo, BusEventos bus) =>
        {
            var s = repo.ObtenerSolicitud(id);
            if (s is null) return Results.NotFound(new { error = "No existe la solicitud." });
            var c = repo.Aceptar(id);
            if (c is null) return Results.Conflict(new { error = $"La solicitud ya estaba {s.Estado}." });
            repo.Registrar("aceptada", $"Aceptada {s.NombreZip} de {s.NodoOrigen} → Consultas (Recibido)", s.RallyId, s.Salto);
            bus.Publicar("decision", new { id, estado = EstadosSolicitud.Aceptada, consultaId = c.Id, pendientes = repo.ContarPendientes() });
            return Results.Ok(new { consultaId = c.Id });
        });

        api.MapPost("/solicitudes/{id}/rechazar", (string id, RepositorioNodo repo, BusEventos bus, AlmacenPaquetes almacen) =>
        {
            var s = repo.ObtenerSolicitud(id);
            if (s is null) return Results.NotFound(new { error = "No existe la solicitud." });
            if (!repo.Rechazar(id)) return Results.Conflict(new { error = $"La solicitud ya estaba {s.Estado}." });
            repo.Registrar("rechazada", $"Rechazada {s.NombreZip} de {s.NodoOrigen}", s.RallyId, s.Salto);
            bus.Publicar("decision", new { id, estado = EstadosSolicitud.Rechazada, pendientes = repo.ContarPendientes() });
            return Results.Ok();
        });

        // ------------------------------------------------------------------ Consultas

        api.MapGet("/consultas", (RepositorioNodo repo) => repo.ListarConsultas());

        api.MapGet("/consultas/{id}", (string id, RepositorioNodo repo, AlmacenPaquetes almacen, IdentidadNodo yo) =>
        {
            var c = repo.ObtenerConsulta(id);
            if (c is null) return Results.NotFound();
            var zip = almacen.Leer(c.RutaZip);
            var leido = EmpaquetadorZip.Leer(zip);
            var m = leido.Manifiesto;
            // Se revisa integridad, certificado y firma; la ventana de ±10 min no aplica a lo ya archivado.
            var v = ValidadorPaquete.Revisar(zip, Identificadores.LeerFecha(m.TimestampUtc) ?? DateTime.UtcNow);
            var alg = Diccionario.PorCodigo(m.AlgorithmCode);
            return Results.Ok(new
            {
                consulta = c,
                manifiesto = JsonNode.Parse(leido.ManifiestoJson),
                validacion = new { v.Valido, v.Codigo, v.Detalle, v.Certificado },
                cadenaFirma = FirmaManifiesto.Cadena(m),
                parametrosCanonicos = ParametrosCanonicos.Texto(m.PublicParameters),
                certificadoPem = Encoding.UTF8.GetString(leido.CertificadoPem),
                esResultado = m.PacketType == TiposPaquete.Result,
                paraMi = m.ResultEnvelope?.RecipientNode == yo.NodoId,
                ejecutorInverse = m.PacketType == TiposPaquete.Result ? yo.NodoId
                    : alg?.UsaKeyId == true ? m.KeyRef?.OwnerNode ?? alg.NodoDueno : alg?.NodoDueno,
                secretos = m.PacketType == TiposPaquete.Result ? Array.Empty<string>() : alg?.Secretos ?? Array.Empty<string>(),
                llave = alg?.Llave.ToString(),
            });
        });

        api.MapGet("/consultas/{id}/zip", (string id, RepositorioNodo repo, AlmacenPaquetes almacen) =>
            repo.ObtenerConsulta(id) is { } c ? Results.File(almacen.Leer(c.RutaZip), "application/zip", c.NombreZip) : Results.NotFound());

        // inverse (descifrar / verificar / extraer…) local o delegado; en un "Resultado" solo abre el sobre.
        api.MapPost("/consultas/{id}/inverse", async (string id, PeticionSecretos p, ServicioSolicitante solicitante, CancellationToken ct) =>
            await Ejecutar(async () =>
            {
                var r = await solicitante.Inverse(id, p.Secretos, ct, Nulo(p.Nodo));
                var c = r.Consulta;
                var nombre = string.IsNullOrWhiteSpace(c.NombreOriginal) ? "resultado.bin" : c.NombreOriginal;
                return new
                {
                    resultadoId = c.Id, ejecutor = r.Ejecutor, delegado = r.Delegado,
                    modo = c.Modo, nombre, mime = ModosCarga.Mime(nombre, c.Modo), tamano = r.Original?.Length ?? 0,
                    texto = c.Modo == ModosCarga.Texto && r.Original is not null ? Encoding.UTF8.GetString(r.Original) : null,
                    base64 = r.Original is null ? null : Convert.ToBase64String(r.Original),
                    verificacion = r.Verificacion,
                };
            }));

        api.MapPost("/consultas/{id}/enviar", async (string id, PeticionDestino p, ServicioEnvio envio, CancellationToken ct) =>
            await Ejecutar(() => envio.EnviarABandeja(id, p.Destino, ct)));

        api.MapPost("/consultas/{id}/rebotar", async (string id, PeticionSecretos p, ServicioEnvio envio, CancellationToken ct) =>
            await Ejecutar(() => envio.Rebotar(id, p.Secretos, ct)));

        // ------------------------------------------------------------------ Verificador (13.1 completo)

        api.MapPost("/verificar", async (HttpRequest req, ServicioDirectorio dir, CancellationToken ct) =>
        {
            if (!req.HasFormContentType) return Results.BadRequest(new { error = "Sube un .zip." });
            var f = await req.ReadFormAsync(ct);
            var archivo = f.Files.FirstOrDefault();
            if (archivo is null) return Results.BadRequest(new { error = "Sube un .zip." });
            var zip = await Bytes(archivo, ct);
            var v = ValidadorPaquete.Revisar(zip, DateTime.UtcNow);
            string? confianza = null;
            if (v.Valido)
            {
                try { confianza = dir.ConfianzaDe(v.Manifiesto!.SourceNode, v.Certificado!.Huella); }
                catch (ErrorProtocolo e) { confianza = $"{e.Codigo}: {e.Message}"; }
            }
            return Results.Ok(new
            {
                nombre = archivo.FileName,
                nombreValido = NombrePaquete.EsValido(archivo.FileName),
                v.Valido, v.Codigo, v.Status, v.Detalle, v.Certificado, confianza,
                manifiesto = v.Manifiesto is null ? null : JsonNode.Parse(v.Manifiesto.ABytes()),
                cadenaFirma = v.Manifiesto is null ? null : FirmaManifiesto.Cadena(v.Manifiesto),
                parametrosCanonicos = v.Manifiesto is null ? null : ParametrosCanonicos.Texto(v.Manifiesto.PublicParameters),
            });
        });

        // ------------------------------------------------------------------ Directorio de nodos

        api.MapGet("/nodos", (RepositorioNodo repo) => repo.ListarNodos().Select(n => new
        {
            n.NodeId, n.Equipo, n.Ip, n.HttpPort, n.HttpsPort, n.Direccion, n.HuellaFijada, n.HuellaPresentada,
            algoritmos = n.ListaAlgoritmos, n.Fuente, n.Estado, n.VistoUtc, n.Alerta, n.Confiable,
        }));

        api.MapPost("/nodos", async (PeticionDestino p, ServicioDirectorio dir, CancellationToken ct) =>
        {
            try
            {
                var r = await dir.AltaManual(p.Destino, ct);
                return r.Ok ? Results.Ok(new { mensaje = r.Mensaje, nodo = r.Nodo!.NodeId }) : Results.BadRequest(new { error = r.Mensaje });
            }
            catch (ArgumentException ex) { return Results.BadRequest(new { error = ex.Message }); }
        });

        api.MapPost("/nodos/buscar", async (ServicioDirectorio dir, CancellationToken ct) =>
        {
            var n = await dir.Escanear(null, ct);
            return n < 0 ? Results.Conflict(new { error = "Ya hay una búsqueda en curso." }) : Results.Ok(new { encontrados = n });
        });

        api.MapPost("/nodos/{nodeId}/confirmar", (string nodeId, ServicioDirectorio dir) =>
            dir.Confirmar(nodeId) is { } n ? Results.Ok(new { n.NodeId, n.HuellaFijada }) : Results.NotFound(new { error = "No existe o no tiene huella." }));

        api.MapDelete("/nodos/{nodeId}", (string nodeId, RepositorioNodo repo) =>
        {
            repo.EliminarNodo(nodeId);
            repo.Registrar("directorio", $"{nodeId} eliminado del directorio.");
            return Results.Ok();
        });

        // ------------------------------------------------------------------ Ajustes

        api.MapGet("/ajustes", (AjustesNodo a) => a.Actual);
        api.MapPut("/ajustes", (ValoresAjustes v, AjustesNodo a, RepositorioNodo repo) =>
        {
            var guardado = a.Guardar(v);
            repo.Registrar("ajustes", "Se actualizaron los ajustes del nodo.");
            return guardado;
        });
    }

    /// <summary>Cuerpo JSON con un destino (nodeId o "IP:puerto").</summary>
    public sealed record PeticionDestino(string Destino);

    /// <summary>Cuerpo JSON con secretos (se cifran en CC-ENV-1 para el dueño; nunca se guardan).</summary>
    public sealed record PeticionSecretos(Dictionary<string, string>? Secretos, string? Nodo);

    /// <summary>Convierte errores de negocio en respuestas 400 legibles.</summary>
    private static async Task<IResult> Ejecutar<T>(Func<Task<T>> accion)
    {
        try { return Results.Ok(await accion()); }
        catch (ErrorOperacionException ex) { return Results.BadRequest(new { error = ex.Message }); }
        catch (ErrorProtocolo ex) { return Results.BadRequest(new { error = $"{ex.Codigo}: {ex.Message}" }); }
        catch (ArgumentException ex) { return Results.BadRequest(new { error = ex.Message }); }
        catch (System.Security.Cryptography.CryptographicException ex) { return Results.BadRequest(new { error = ex.Message }); }
    }

    private static async Task<byte[]> Bytes(IFormFile f, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        await f.CopyToAsync(ms, ct);
        return ms.ToArray();
    }

    /// <summary>JSON {"k":"v"} del formulario → diccionario de cadenas (vacío si no viene).</summary>
    private static Dictionary<string, string> ADiccionario(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new(StringComparer.Ordinal);
        try
        {
            var d = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json) ?? [];
            return d.Where(kv => kv.Value.ValueKind != JsonValueKind.Null)
                .ToDictionary(kv => kv.Key, kv => kv.Value.ValueKind == JsonValueKind.String ? kv.Value.GetString()! : kv.Value.GetRawText(), StringComparer.Ordinal)
                .Where(kv => kv.Value.Length > 0).ToDictionary(StringComparer.Ordinal);
        }
        catch (JsonException) { throw new ErrorOperacionException("Los parámetros no son un JSON válido."); }
    }

    private static string? Nulo(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}

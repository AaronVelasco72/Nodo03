using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;
using Nodo03.Web.Servicios;

namespace Nodo03.Web.Endpoints;

/// <summary>
/// API PRIVADA que usa la interfaz web (todo bajo <c>/api/local</c>).
/// No forma parte del protocolo entre equipos.
/// </summary>
/// <remarks>
/// Protegida por <see cref="ProtegerAdministracion"/>: por defecto solo responde a peticiones
/// desde la misma máquina, para que otro nodo de la LAN no pueda aceptar, rechazar o
/// descifrar nuestras solicitudes.
/// </remarks>
public static class LocalEndpoints
{
    /// <summary>Middleware: bloquea /api/local desde otras máquinas salvo que Ajustes lo permita.</summary>
    public static void ProtegerAdministracion(WebApplication app)
    {
        app.Use(async (ctx, siguiente) =>
        {
            if (ctx.Request.Path.StartsWithSegments("/api/local"))
            {
                var ajustes = ctx.RequestServices.GetRequiredService<AjustesNodo>();
                var ip = ctx.Connection.RemoteIpAddress;
                if (!ajustes.Actual.AdminRemoto && !EsLocal(ip))
                {
                    ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await ctx.Response.WriteAsJsonAsync(new
                    {
                        error = "La administración del nodo solo está permitida desde la misma computadora. " +
                                "Actívala en Ajustes > Administración remota.",
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

        api.MapGet("/identidad", (IdentidadNodo id, DireccionPropia dir, BusEventos bus, RepositorioNodo repo) => new
        {
            nodoId = id.NodoId,
            direccion = dir.Obtener(),
            pendientes = repo.ContarPendientes(),
            consultas = repo.ContarConsultas(),
            pestanasConectadas = bus.Conectados,
            certificados = new[] { CodigosAlgoritmo.Rsa, CodigosAlgoritmo.Ecc }.Select(c =>
            {
                var cert = id.Certificado(c);
                return new
                {
                    codigo = c,
                    huella = id.Huella(c),
                    sujeto = cert.Subject,
                    desde = cert.NotBefore.ToUniversalTime(),
                    hasta = cert.NotAfter.ToUniversalTime(),
                    llave = c == CodigosAlgoritmo.Rsa ? "RSA 2048 bits" : "EC P-256 (secp256r1)",
                    firma = c == CodigosAlgoritmo.Rsa ? FirmaManifiesto.AlgoritmoRsa : FirmaManifiesto.AlgoritmoEcc,
                };
            }),
        });

        api.MapGet("/certificado/{codigo}", (string codigo, IdentidadNodo id) =>
            CodigosAlgoritmo.LoImplementaEsteNodo(codigo.ToUpperInvariant())
                ? Results.File(Encoding.ASCII.GetBytes(id.CertificadoPem(codigo.ToUpperInvariant())),
                    "application/x-pem-file", $"{NombrePaquete.NormalizarNodo(id.NodoId)}_{codigo.ToUpperInvariant()}.pem")
                : Results.NotFound());

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
                    // Espera un evento o 15 s; si no hay eventos manda un "latido" para que
                    // proxies y navegadores no cierren la conexión por inactividad.
                    using var latido = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
                    latido.CancelAfter(TimeSpan.FromSeconds(15));
                    try
                    {
                        var e = await lector.ReadAsync(latido.Token);
                        var json = JsonSerializer.Serialize(e.Datos, OpcionesWeb);
                        await ctx.Response.WriteAsync($"event: {e.Tipo}\ndata: {json}\n\n", ctx.RequestAborted);
                    }
                    catch (OperationCanceledException) when (!ctx.RequestAborted.IsCancellationRequested)
                    {
                        await ctx.Response.WriteAsync(": latido\n\n", ctx.RequestAborted);
                    }
                    await ctx.Response.Body.FlushAsync(ctx.RequestAborted);
                }
            }
            catch (OperationCanceledException) { /* el navegador cerró la pestaña */ }
            finally
            {
                bus.Desuscribir(id);
            }
        });

        // ------------------------------------------------------------------ Solicitudes (bandeja)

        api.MapGet("/solicitudes", (RepositorioNodo repo, string? estado) =>
            repo.ListarSolicitudes(string.IsNullOrWhiteSpace(estado) ? null : estado).Select(VistaSolicitud));

        api.MapGet("/solicitudes/{id}", (string id, RepositorioNodo repo) =>
            repo.ObtenerSolicitud(id) is { } s
                ? Results.Ok(new { solicitud = VistaSolicitud(s), detalle = JsonNode.Parse(s.DetalleJson) })
                : Results.NotFound());

        api.MapPost("/solicitudes/{id}/aceptar", (string id, RepositorioNodo repo, BusEventos bus) =>
        {
            var s = repo.ObtenerSolicitud(id);
            if (s is null) return Results.NotFound(new { error = "No existe la solicitud." });
            var c = repo.Aceptar(id);
            if (c is null) return Results.Conflict(new { error = $"La solicitud ya estaba {s.Estado}." });
            repo.Registrar("aceptada", $"Aceptada {s.NombreZip} de {s.NodoOrigen} → Consultas", s.RallyId, s.Salto);
            bus.Publicar("decision", new { id, estado = EstadosSolicitud.Aceptada, consultaId = c.Id, pendientes = repo.ContarPendientes() });
            return Results.Ok(new { consultaId = c.Id });
        });

        api.MapPost("/solicitudes/{id}/rechazar", (string id, RepositorioNodo repo, BusEventos bus) =>
        {
            var s = repo.ObtenerSolicitud(id);
            if (s is null) return Results.NotFound(new { error = "No existe la solicitud." });
            if (!repo.Rechazar(id)) return Results.Conflict(new { error = $"La solicitud ya estaba {s.Estado}." });
            repo.Registrar("rechazada", $"Rechazada {s.NombreZip} de {s.NodoOrigen}", s.RallyId, s.Salto);
            bus.Publicar("decision", new { id, estado = EstadosSolicitud.Rechazada, pendientes = repo.ContarPendientes() });
            return Results.Ok();
        });

        // ------------------------------------------------------------------ Consultas (archivo)

        api.MapGet("/consultas", (RepositorioNodo repo) => repo.ListarConsultas());

        api.MapGet("/consultas/{id}", (string id, RepositorioNodo repo, AlmacenPaquetes almacen, IdentidadNodo yo) =>
        {
            var c = repo.ObtenerConsulta(id);
            if (c is null) return Results.NotFound();
            var leido = EmpaquetadorZip.Leer(almacen.Leer(c.RutaZip));
            var validacion = ValidadorPaquete.Validar(leido, c.NombreZip);
            var m = leido.Manifiesto;
            return Results.Ok(new
            {
                consulta = c,
                manifiesto = JsonNode.Parse(leido.ManifiestoJson),
                validacion,
                certificadoPem = Encoding.UTF8.GetString(leido.CertificadoPem),
                paraMi = yo.EsMiHuella(m.Parametro("recipientThumbprintSha256")),
                descifrable = CodigosAlgoritmo.LoImplementaEsteNodo(m.AlgorithmCode),
            });
        });

        api.MapGet("/consultas/{id}/zip", (string id, RepositorioNodo repo, AlmacenPaquetes almacen) =>
            repo.ObtenerConsulta(id) is { } c
                ? Results.File(almacen.Leer(c.RutaZip), "application/zip", c.NombreZip)
                : Results.NotFound());

        api.MapPost("/consultas/{id}/descifrar", (string id, RepositorioNodo repo, AlmacenPaquetes almacen,
            IdentidadNodo yo, AjustesNodo ajustes) =>
        {
            var c = repo.ObtenerConsulta(id);
            if (c is null) return Results.NotFound();
            if (!ajustes.PuedeDescifrar(c.AlgoritmoCodigo))
                return Results.BadRequest(new { error = $"El descifrado de {c.AlgoritmoCodigo} no está habilitado en Ajustes." });
            try
            {
                var plano = ServicioPaquetes.Abrir(EmpaquetadorZip.Leer(almacen.Leer(c.RutaZip)), yo);
                return Results.Ok(new
                {
                    modo = plano.Modo,
                    nombre = plano.NombreArchivo,
                    mime = Mime(plano.NombreArchivo, plano.Modo),
                    tamano = plano.Bytes.Length,
                    texto = plano.Modo == ModosCarga.Texto ? Encoding.UTF8.GetString(plano.Bytes) : null,
                    base64 = Convert.ToBase64String(plano.Bytes),
                });
            }
            catch (Exception ex) when (ex is DestinatarioIncorrectoException or NotSupportedException or CryptographicException)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });

        api.MapPost("/consultas/{id}/reenviar", async (string id, PeticionDireccion p, ServicioEnvio envio, CancellationToken ct) =>
            await Ejecutar(() => envio.Reenviar(id, p.Direccion, ct)));

        api.MapPost("/consultas/{id}/rebotar", async (string id, ServicioEnvio envio, CancellationToken ct) =>
            await Ejecutar(() => envio.Rebotar(id, ct)));

        // ------------------------------------------------------------------ Enviar (Modo Emisor)

        api.MapPost("/enviar", async (HttpRequest req, ServicioEnvio envio, CancellationToken ct) =>
        {
            if (!req.HasFormContentType) return Results.BadRequest(new { error = "Se esperaba un formulario." });
            var f = await req.ReadFormAsync(ct);

            var modo = ModosCarga.Normalizar(f["modo"]);
            ContenidoPlano contenido;
            if (modo == ModosCarga.Texto)
            {
                var texto = f["texto"].ToString();
                contenido = new ContenidoPlano(Encoding.UTF8.GetBytes(texto), modo, "mensaje.txt");
            }
            else
            {
                var archivo = f.Files.GetFile("archivo");
                if (archivo is null) return Results.BadRequest(new { error = "Falta el archivo o imagen." });
                using var ms = new MemoryStream();
                await archivo.CopyToAsync(ms, ct);
                contenido = new ContenidoPlano(ms.ToArray(), modo, Path.GetFileName(archivo.FileName));
            }

            string? pem = null;
            if (f.Files.GetFile("certificado") is { } certArchivo)
            {
                using var lector = new StreamReader(certArchivo.OpenReadStream());
                pem = await lector.ReadToEndAsync(ct);
            }

            var destinatario = f["destinatario"].ToString().ToLowerInvariant() switch
            {
                "remoto" => DestinatarioCifrado.Remoto,
                "pem" => DestinatarioCifrado.Pem,
                _ => DestinatarioCifrado.Propio,
            };

            return await Ejecutar(() => envio.Enviar(new PeticionEnvio(
                contenido, f["algoritmo"].ToString().ToUpperInvariant(), destinatario,
                f["direccion"].ToString().NullSiVacio(), pem, f["soloGenerar"] == "true"), ct));
        });

        // ------------------------------------------------------------------ Verificador

        api.MapPost("/verificar", async (HttpRequest req, CancellationToken ct) =>
        {
            if (!req.HasFormContentType) return Results.BadRequest(new { error = "Sube un .zip." });
            var f = await req.ReadFormAsync(ct);
            var archivo = f.Files.FirstOrDefault();
            if (archivo is null) return Results.BadRequest(new { error = "Sube un .zip." });
            using var ms = new MemoryStream();
            await archivo.CopyToAsync(ms, ct);
            try
            {
                var leido = EmpaquetadorZip.Leer(ms.ToArray());
                var v = ValidadorPaquete.Validar(leido, archivo.FileName);
                return Results.Ok(new
                {
                    estructura = true,
                    nombre = archivo.FileName,
                    nombreValido = NombrePaquete.EsValido(archivo.FileName),
                    validacion = v,
                    manifiesto = JsonNode.Parse(leido.ManifiestoJson),
                    tamanoDatos = leido.DatosEnc.Length,
                });
            }
            catch (PaqueteMalformadoException ex)
            {
                return Results.Ok(new { estructura = false, nombre = archivo.FileName, error = ex.Message });
            }
        });

        // ------------------------------------------------------------------ Directorio de nodos

        api.MapGet("/nodos", (RepositorioNodo repo) => repo.ListarNodos().Select(n => new
        {
            n.Direccion, n.NodoId, n.Estado, n.VistoUtc,
            tieneRsa = n.CertificadoRsaPem is not null, tieneEcc = n.CertificadoEccPem is not null,
        }));

        api.MapPost("/nodos", async (PeticionDireccion p, RepositorioNodo repo, ClienteNodos cliente, CancellationToken ct) =>
        {
            Uri url;
            try { url = ClienteNodos.UrlBase(p.Direccion); }
            catch (ArgumentException ex) { return Results.BadRequest(new { error = ex.Message }); }
            var direccion = $"{url.Host}:{url.Port}";

            var estado = await cliente.ConsultarEstado(direccion, ct);
            var rsa = estado is null ? null : await cliente.ObtenerCertificado(direccion, CodigosAlgoritmo.Rsa, ct);
            var ecc = estado is null ? null : await cliente.ObtenerCertificado(direccion, CodigosAlgoritmo.Ecc, ct);
            var nodo = new NodoConocido
            {
                Direccion = direccion,
                NodoId = estado?.NodeId ?? repo.ObtenerNodo(direccion)?.NodoId ?? "¿?",
                Estado = estado is null ? "sin respuesta" : estado.AcceptingPackages ? "en línea" : "no acepta paquetes",
                VistoUtc = estado is null ? null : DateTime.UtcNow,
                CertificadoRsaPem = rsa, CertificadoEccPem = ecc,
            };
            repo.GuardarNodo(nodo);
            return Results.Ok(new { nodo.Direccion, nodo.NodoId, nodo.Estado, tieneRsa = rsa is not null, tieneEcc = ecc is not null });
        });

        api.MapDelete("/nodos", (string direccion, RepositorioNodo repo) =>
        {
            repo.EliminarNodo(direccion);
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

    /// <summary>JSON camelCase, igual que el resto de la API.</summary>
    private static readonly JsonSerializerOptions OpcionesWeb = new(JsonSerializerDefaults.Web);

    /// <summary>Cuerpo JSON con una dirección "IP:Puerto".</summary>
    public sealed record PeticionDireccion(string Direccion);

    /// <summary>Convierte errores de negocio en respuestas 400 legibles.</summary>
    private static async Task<IResult> Ejecutar(Func<Task<ResultadoEnvio>> accion)
    {
        try
        {
            var r = await accion();
            return Results.Ok(r);
        }
        catch (ErrorEnvioException ex) { return Results.BadRequest(new { error = ex.Message }); }
        catch (InvalidOperationException ex) { return Results.BadRequest(new { error = ex.Message }); }
        catch (ArgumentException ex) { return Results.BadRequest(new { error = ex.Message }); }
        catch (PaqueteMalformadoException ex) { return Results.BadRequest(new { error = ex.Message }); }
    }

    private static object VistaSolicitud(Solicitud s) => new
    {
        s.Id, s.PacketId, s.NombreZip, s.OrigenIp, s.NodoOrigen, s.DireccionRespuesta, s.AlgoritmoCodigo,
        s.Algoritmo, s.Modo, s.NombreOriginal, s.TamanoOriginal, s.Sha256, s.Verificacion, s.Estado,
        s.RecibidoUtc, s.DecididoUtc, s.Salto, s.RallyId,
        algoritmoDescripcion = CodigosAlgoritmo.Describir(s.AlgoritmoCodigo),
    };

    /// <summary>Tipo MIME aproximado para previsualizar en el navegador.</summary>
    private static string Mime(string nombre, string modo) => Path.GetExtension(nombre).ToLowerInvariant() switch
    {
        ".png" => "image/png",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".bmp" => "image/bmp",
        ".svg" => "image/svg+xml",
        ".pdf" => "application/pdf",
        ".txt" => "text/plain; charset=utf-8",
        _ => modo == ModosCarga.Texto ? "text/plain; charset=utf-8" : "application/octet-stream",
    };

    private static string? NullSiVacio(this string s) => string.IsNullOrWhiteSpace(s) ? null : s;
}

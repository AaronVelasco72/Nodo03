using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;
using Nodo03.Web.Servicios;

namespace Nodo03.Web.Endpoints;

/// <summary>
/// Endpoints PÚBLICOS del estándar v2.0 (sección 10). Son los que usan los demás equipos.
/// </summary>
/// <remarks>
/// <code>
/// GET  /api/status                 10.3  estado, puertos, algoritmos y huella
/// GET  /api/certificate            7     certificado X.509 de identidad (PEM)
/// GET  /api/algorithms             10.4  perfil de RSA y ECC
/// POST /api/requests/receive       10.5  bandeja (rol Receptor)
/// POST /api/crypto/forward         10.6  cifrar con RSA/ECC (rol Proveedor)
/// POST /api/crypto/inverse         10.6  descifrar RSA/ECC
/// GET  /api/jobs/{jobId}[/result]  10.7  trabajos que pasaron de 30 s
/// GET  /api/keys/{keyId}           12.7  llave PÚBLICA de un keyId
/// </code>
/// Todos los errores salen como <c>application/problem+json</c> con el código del Anexo B.
/// </remarks>
public static class ProtocoloEndpoints
{
    public static void Mapear(WebApplication app)
    {
        // Encabezados de identificación también en las respuestas (cortesía; el estándar los pide en peticiones).
        app.Use(async (ctx, siguiente) =>
        {
            if (ctx.Request.Path.StartsWithSegments("/api") && !ctx.Request.Path.StartsWithSegments("/api/local"))
            {
                var op = ctx.RequestServices.GetRequiredService<OpcionesNodo>();
                ctx.Response.Headers["X-CC-Node"] = op.NodoId;
                ctx.Response.Headers["X-CC-Protocol"] = Identificadores.VersionProtocolo;
            }
            await siguiente(ctx);
        });

        // ------------------------------------------------------------- 10.3
        app.MapGet("/api/status", (IdentidadNodo yo, AjustesNodo ajustes, DireccionPropia dir) => Results.Ok(new
        {
            nodeId = yo.NodoId,
            teamNumber = yo.Equipo,
            protocolVersion = Identificadores.VersionProtocolo,
            status = "online",
            acceptingPackages = ajustes.Actual.AceptandoPaquetes,
            httpPort = dir.PuertoReal(),
            httpsPort = (int?)null,
            algorithms = Diccionario.ProvistosPor(yo.Equipo).Select(a => new { algorithmId = a.Id, algorithmCode = a.Codigo }),
            certificateThumbprintSha256 = yo.Huella,
            serverTimeUtc = Identificadores.FormatoFecha(DateTime.UtcNow),
        }));

        // ------------------------------------------------------------- 7 / 10.2
        app.MapGet("/api/certificate", (IdentidadNodo yo) =>
            Results.Text(yo.CertificadoPem, "application/x-pem-file", Encoding.ASCII));

        // ------------------------------------------------------------- 10.4
        app.MapGet("/api/algorithms", (IdentidadNodo yo, OpcionesNodo op) => Results.Ok(new
        {
            nodeId = yo.NodoId,
            algorithms = Diccionario.ProvistosPor(yo.Equipo).Select(a => Perfil(a, op)),
        }));

        // ------------------------------------------------------------- 10.5
        app.MapPost("/api/requests/receive", async (HttpContext ctx, ServicioRecepcion recepcion, OpcionesNodo op) =>
        {
            var requestId = ctx.Request.Headers["X-CC-Request-Id"].FirstOrDefault();
            try
            {
                var form = await LeerFormulario(ctx, op);
                var archivo = form.Files.GetFile("package") ?? form.Files.FirstOrDefault()
                    ?? throw new ErrorProtocolo("E-ZIP-INVALID", "Falta el archivo en el campo 'package'.");
                var zip = await Bytes(archivo, op, ctx.RequestAborted);
                var s = await recepcion.Recibir(zip, archivo.FileName, IpDe(ctx), ctx.RequestAborted);
                return Results.Json(new
                {
                    packetId = s.PacketId,
                    status = s.Estado,
                    receivedAtUtc = Identificadores.FormatoFecha(s.RecibidoUtc),
                    verification = s.Verificacion,
                }, statusCode: StatusCodes.Status202Accepted);
            }
            catch (ErrorProtocolo e) { return Problemas.De(e, op.NodoId, requestId); }
        });

        // ------------------------------------------------------------- 10.6
        app.MapPost("/api/crypto/forward", (HttpContext ctx, ServicioProveedor p, OpcionesNodo op) => Cripto(ctx, Operaciones.Forward, p, op));
        app.MapPost("/api/crypto/inverse", (HttpContext ctx, ServicioProveedor p, OpcionesNodo op) => Cripto(ctx, Operaciones.Inverse, p, op));

        // ------------------------------------------------------------- 10.7
        app.MapGet("/api/jobs/{jobId}", (string jobId, ServicioProveedor p, OpcionesNodo op) =>
        {
            var t = p.Trabajo(jobId);
            if (t is null) return Problemas.De("E-JOB-NOT-FOUND", $"No existe el trabajo {jobId} (o ya expiró).", op.NodoId);
            return Results.Ok(new
            {
                jobId = t.JobId,
                state = t.Estado,
                progressPercent = t.Progreso,
                resultUrl = t.Estado == "done" ? $"/api/jobs/{t.JobId}/result" : null,
                error = t.Error is null ? null : new { code = t.Error.Codigo, detail = t.Error.Message },
            });
        });

        app.MapGet("/api/jobs/{jobId}/result", (string jobId, HttpContext ctx, ServicioProveedor p, OpcionesNodo op) =>
        {
            var t = p.Trabajo(jobId);
            // Solo el solicitante original puede descargarlo (X-CC-Node). Para los demás, "no existe".
            if (t is null || t.Resultado is null || ctx.Request.Headers["X-CC-Node"].FirstOrDefault() != t.Solicitante)
                return Problemas.De("E-JOB-NOT-FOUND", $"No hay resultado disponible para {jobId}.", op.NodoId);
            return Results.File(t.Resultado.Zip, "application/zip", t.Resultado.NombreZip);
        });

        // ------------------------------------------------------------- 12.7
        app.MapGet("/api/keys/{keyId}", (string keyId, RepositorioNodo repo, IdentidadNodo yo) =>
        {
            var k = repo.ObtenerLlave(keyId);
            if (k is null) return Problemas.De("E-KEY-NOT-FOUND", $"keyId {keyId} desconocido.", yo.NodoId);
            return Results.Ok(new
            {
                keyId = k.KeyId,
                ownerNode = yo.NodoId,
                algorithmCode = k.Algoritmo,
                keyType = k.Algoritmo == Diccionario.Rsa ? "RSA-2048" : "EC P-256",
                publicKeySpkiBase64 = k.PublicaSpkiBase64,
                restricted = !string.IsNullOrWhiteSpace(k.Permitidos),
                createdUtc = Identificadores.FormatoFecha(k.CreadaUtc),
            });
        });
    }

    /// <summary>Perfil 10.4 de RSA o ECC.</summary>
    private static object Perfil(AlgoritmoOficial a, OpcionesNodo op) => new
    {
        algorithmId = a.Id,
        algorithmCode = a.Codigo,
        variants = a.Codigo == Diccionario.Rsa ? new[] { CifradorRsa.Esquema } : new[] { $"{CifradorEcc.Esquema} {CifradorEcc.Curva}" },
        operations = new
        {
            forward = new { name = a.Forward, inputs = new[] { "payload" } },
            inverse = new { name = a.Inverse, inputs = new[] { "package" } },
        },
        secretParameters = Array.Empty<object>(),
        keyId = new
        {
            forward = "Opcional. Sin keyId EQ03 genera un par nuevo (EQ03-KEY-<uuid>) y lo devuelve en keyRef.",
            inverse = "Se toma de keyRef / publicParameters.keyId del paquete.",
        },
        options = new object[]
        {
            new { name = "allowedNodes", type = "string", description = "nodeId separados por comas que podrán usar la llave nueva. Vacío = cualquiera.", required = false },
            new { name = "hop", type = "string", description = "Extensión EQ03 (ping-pong): número de rebote. Se copia a publicParameters.", required = false },
            new { name = "rallyId", type = "string", description = "Extensión EQ03 (ping-pong): id del rally. Se copia a publicParameters.", required = false },
        },
        publicParameters = a.Codigo == Diccionario.Rsa
            ? new[] { "keyId", "scheme", "wrappedKeyBase64", "nonceBase64", "tagBase64" }
            : new[] { "keyId", "curve", "scheme", "ephemeralPublicKeyBase64", "kdf", "hkdfInfo", "nonceBase64", "tagBase64" },
        payloadModes = new[] { ModosCarga.Texto, ModosCarga.Archivo, ModosCarga.Imagen },
        maxPayloadBytes = op.LimiteZipBytes,
        notes = a.Codigo == Diccionario.Rsa
            ? "Híbrido: AES-256-GCM (AAD vacío) con CEK envuelta en RSA-OAEP-SHA256 con la llave del keyId."
            : "ECIES: ECDH P-256 efímero + HKDF-SHA256 (info 'EQ03-ECIES-v1', sin sal) → AES-256-GCM (AAD vacío).",
    };

    // ------------------------------------------------------------------ /api/crypto/*

    private static async Task<IResult> Cripto(HttpContext ctx, string operacion, ServicioProveedor proveedor, OpcionesNodo op)
    {
        var requestId = ctx.Request.Headers["X-CC-Request-Id"].FirstOrDefault();
        try
        {
            var form = await LeerFormulario(ctx, op);
            var partes = new PartesCripto(
                await Parte(form, "request", op, ctx.RequestAborted) ?? [],
                Encoding.UTF8.GetString(await Parte(form, "requestSignature", op, ctx.RequestAborted) ?? []),
                Encoding.UTF8.GetString(await Parte(form, "requesterCertificate", op, ctx.RequestAborted) ?? []),
                await Parte(form, "payload", op, ctx.RequestAborted),
                form.Files.GetFile("payload")?.FileName,
                await Parte(form, "cover", op, ctx.RequestAborted),
                await Parte(form, "package", op, ctx.RequestAborted));
            var r = await proveedor.Atender(operacion, partes, ctx.RequestAborted);
            if (r.Paquete is { } p) return Results.File(p.Zip, "application/zip", p.NombreZip);
            return Results.Json(new
            {
                jobId = r.Trabajo!.JobId,
                statusUrl = $"/api/jobs/{r.Trabajo.JobId}",
                retryAfterSeconds = 2,
            }, statusCode: StatusCodes.Status202Accepted);
        }
        catch (ErrorProtocolo e) { return Problemas.De(e, op.NodoId, requestId); }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            ctx.RequestServices.GetRequiredService<ILogger<ServicioProveedor>>().LogError(e, "Error en /api/crypto/{Op}", operacion);
            return Problemas.De("E-INTERNAL", "Error interno del proveedor: " + e.Message, op.NodoId, requestId);
        }
    }

    /// <summary>Una parte puede venir como archivo (con filename) o como campo de texto: se aceptan ambas.</summary>
    private static async Task<byte[]?> Parte(IFormCollection form, string nombre, OpcionesNodo op, CancellationToken ct)
    {
        if (form.Files.GetFile(nombre) is { } f) return await Bytes(f, op, ct);
        return form.TryGetValue(nombre, out var v) && v.Count > 0 ? Encoding.UTF8.GetBytes(v.ToString()) : null;
    }

    // ------------------------------------------------------------------ utilidades

    private static async Task<IFormCollection> LeerFormulario(HttpContext ctx, OpcionesNodo op)
    {
        var req = ctx.Request;
        // E-SIZE temprano: si el cliente declara un tamaño mayor, ni siquiera leemos el cuerpo.
        if (req.ContentLength > op.LimiteZipBytes + 1024 * 1024)
            throw new ErrorProtocolo("E-SIZE", $"El cuerpo supera {op.LimiteZipMb} MB.");
        if (!req.HasFormContentType)
            throw new ErrorProtocolo("E-UNSUPPORTED-MEDIA", "Se esperaba multipart/form-data.");
        try { return await req.ReadFormAsync(ctx.RequestAborted); }
        catch (Exception ex) when (EsExcesoDeTamano(ex)) { throw new ErrorProtocolo("E-SIZE", $"El cuerpo supera {op.LimiteZipMb} MB."); }
        catch (Exception ex) when (ex is InvalidDataException or IOException) { throw new ErrorProtocolo("E-REQUEST", "Cuerpo multipart inválido: " + ex.Message); }
    }

    private static async Task<byte[]> Bytes(IFormFile f, OpcionesNodo op, CancellationToken ct)
    {
        if (f.Length > op.LimiteZipBytes) throw new ErrorProtocolo("E-SIZE", $"'{f.Name}' supera {op.LimiteZipMb} MB.");
        using var ms = new MemoryStream((int)f.Length);
        await f.CopyToAsync(ms, ct);
        return ms.ToArray();
    }

    private static string IpDe(HttpContext ctx) => ctx.Connection.RemoteIpAddress?.MapToIPv4().ToString() ?? "desconocida";

    private static bool EsExcesoDeTamano(Exception ex) =>
        ex is BadHttpRequestException { StatusCode: 413 } ||
        (ex is InvalidDataException && ex.Message.Contains("limit", StringComparison.OrdinalIgnoreCase));

    /// <summary>Límites de Kestrel y del lector de formularios (10.1: 50 MB).</summary>
    public static void ConfigurarLimites(WebApplicationBuilder builder, OpcionesNodo op)
    {
        builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = op.LimiteZipBytes + 2 * 1024 * 1024);
        builder.Services.Configure<FormOptions>(f =>
        {
            f.MultipartBodyLengthLimit = op.LimiteZipBytes + 1024 * 1024;
            f.ValueCountLimit = 64;
        });
    }
}

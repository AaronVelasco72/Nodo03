using Microsoft.AspNetCore.Http.Features;
using Nodo03.Core.Cripto;
using Nodo03.Core.Protocolo;
using Nodo03.Web.Servicios;

namespace Nodo03.Web.Endpoints;

/// <summary>
/// Endpoints PÚBLICOS del protocolo del grupo (sección 3). Son los que usan los demás equipos.
/// </summary>
public static class ProtocoloEndpoints
{
    public const string VersionProtocolo = "1.0";

    public static void Mapear(WebApplication app)
    {
        // -------------------------------------------------------------
        // 3.1  GET /api/status  (descubrimiento)
        // -------------------------------------------------------------
        app.MapGet("/api/status", (OpcionesNodo op, AjustesNodo ajustes) => Results.Ok(new
        {
            nodeId = op.NodoId,
            protocolVersion = VersionProtocolo,
            status = "online",
            acceptingPackages = ajustes.Actual.AceptandoPaquetes,
            // Extensiones informativas (los demás nodos pueden ignorarlas):
            algorithms = new[] { CodigosAlgoritmo.Rsa, CodigosAlgoritmo.Ecc },
            certificateEndpoint = "/api/certificate?algorithm={RSA|ECC}",
        }));

        // -------------------------------------------------------------
        // EXTENSIÓN  GET /api/certificate?algorithm=RSA|ECC
        // Para cifrar con RSA o ECC se necesita la llave pública del DESTINO. Este endpoint
        // la publica en PEM. Es información pública, igual que el certificado del zip.
        // -------------------------------------------------------------
        app.MapGet("/api/certificate", (string? algorithm, IdentidadNodo identidad) =>
        {
            var codigo = (algorithm ?? CodigosAlgoritmo.Rsa).ToUpperInvariant();
            if (!CodigosAlgoritmo.LoImplementaEsteNodo(codigo))
                return Results.NotFound(new { error = $"Este nodo solo tiene certificados RSA y ECC." });
            return Results.Text(identidad.CertificadoPem(codigo), "application/x-pem-file");
        });

        // -------------------------------------------------------------
        // 3.2  POST /api/requests/receive  (Modo Receptor)
        // multipart/form-data, campo "package" con el .zip
        // -------------------------------------------------------------
        app.MapPost("/api/requests/receive", async (HttpContext ctx, ServicioRecepcion recepcion, OpcionesNodo op) =>
        {
            var req = ctx.Request;
            var ip = ctx.Connection.RemoteIpAddress?.MapToIPv4().ToString() ?? "desconocida";

            // 413 temprano: si el cliente declara un tamaño mayor, ni siquiera leemos el cuerpo.
            if (req.ContentLength > op.LimiteZipBytes + 64 * 1024)
                return Error(413, "El .zip supera el límite configurado.", op);

            if (!req.HasFormContentType)
                return Error(400, "Se esperaba multipart/form-data con el campo 'package'.", op);

            IFormCollection form;
            try
            {
                form = await req.ReadFormAsync(ctx.RequestAborted);
            }
            catch (Exception ex) when (EsExcesoDeTamano(ex))
            {
                return Error(413, "El .zip supera el límite configurado.", op);
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException)
            {
                return Error(400, "Cuerpo multipart inválido: " + ex.Message, op);
            }

            // Campo oficial "package"; por tolerancia aceptamos el primer archivo si viene con otro nombre.
            var archivo = form.Files.GetFile("package") ?? form.Files.FirstOrDefault();
            if (archivo is null || archivo.Length == 0)
                return Error(400, "Falta el archivo en el campo 'package'.", op);
            if (archivo.Length > op.LimiteZipBytes)
                return Error(413, "El .zip supera el límite configurado.", op);

            using var ms = new MemoryStream((int)archivo.Length);
            await archivo.CopyToAsync(ms, ctx.RequestAborted);

            var r = await recepcion.Recibir(ms.ToArray(), archivo.FileName, ip, ctx.RequestAborted);

            var cuerpo = new
            {
                status = r.Solicitud?.Estado,
                message = r.Mensaje,
                requestId = r.Solicitud?.Id,
                packetId = r.Solicitud?.PacketId,
                verification = r.Solicitud?.Verificacion,
                duplicate = r.Duplicado,
                errors = r.Validacion?.Errores,
                warnings = r.Validacion?.Avisos,
            };
            return Results.Json(cuerpo, statusCode: r.CodigoHttp);
        });
    }

    private static IResult Error(int codigo, string mensaje, OpcionesNodo op) =>
        Results.Json(new { status = (string?)null, message = mensaje, limitMb = op.LimiteZipMb }, statusCode: codigo);

    /// <summary>Kestrel y el lector multipart avisan del exceso de tamaño con excepciones distintas.</summary>
    private static bool EsExcesoDeTamano(Exception ex) =>
        ex is BadHttpRequestException { StatusCode: 413 } ||
        (ex is InvalidDataException && ex.Message.Contains("limit", StringComparison.OrdinalIgnoreCase));

    /// <summary>Ajusta los límites de Kestrel y del lector de formularios al límite del nodo.</summary>
    public static void ConfigurarLimites(WebApplicationBuilder builder, OpcionesNodo op)
    {
        builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = op.LimiteZipBytes + 1024 * 1024);
        builder.Services.Configure<FormOptions>(f =>
        {
            f.MultipartBodyLengthLimit = op.LimiteZipBytes + 512 * 1024;
            f.ValueCountLimit = 64;
        });
    }
}

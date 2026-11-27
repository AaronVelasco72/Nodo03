using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Nodo03.Core.Cripto;
using Nodo03.Core.Datos;
using Nodo03.Core.Protocolo;
using Nodo03.Core.Servicios;

namespace Nodo03.Web.Servicios;

/// <summary>Objeto <c>request</c> de <c>/api/crypto/*</c> (sección 10.6).</summary>
public sealed class PeticionCripto
{
    [JsonPropertyName("version")] public string Version { get; set; } = Identificadores.VersionProtocolo;
    [JsonPropertyName("requestId")] public string RequestId { get; set; } = Identificadores.NuevoUuid();
    [JsonPropertyName("requesterNode")] public string RequesterNode { get; set; } = "";
    [JsonPropertyName("targetNode")] public string TargetNode { get; set; } = "";
    [JsonPropertyName("timestampUtc")] public string TimestampUtc { get; set; } = Identificadores.FormatoFecha(DateTime.UtcNow);
    [JsonPropertyName("algorithmCode")] public string AlgorithmCode { get; set; } = "";
    [JsonPropertyName("operation")] public string Operation { get; set; } = Operaciones.Forward;
    [JsonPropertyName("payloadMode")] public string PayloadMode { get; set; } = ModosCarga.Archivo;
    [JsonPropertyName("originalFileName")] public string OriginalFileName { get; set; } = "";
    [JsonPropertyName("options")] public Dictionary<string, string> Options { get; set; } = new(StringComparer.Ordinal);
    [JsonPropertyName("keyId")] public string? KeyId { get; set; }
    [JsonPropertyName("secrets")] public SobreCc? Secrets { get; set; }

    public static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.Never };
}

/// <summary>Partes ya leídas del multipart de <c>/api/crypto/*</c>.</summary>
public sealed record PartesCripto(byte[] Request, string Firma, string CertificadoPem, byte[]? Payload, string? NombrePayload, byte[]? Cover, byte[]? Package);

/// <summary>Trabajo asíncrono (10.6 paso 4 y 10.7).</summary>
public sealed class Trabajo
{
    public string JobId { get; } = Identificadores.NuevoUuid();
    public required string Solicitante { get; init; }
    public string Estado { get; set; } = "running";
    public int Progreso { get; set; } = 10;
    public PaqueteGenerado? Resultado { get; set; }
    public ErrorProtocolo? Error { get; set; }
    public DateTime CreadoUtc { get; } = DateTime.UtcNow;
}

/// <summary>Respuesta del proveedor: el zip (200) o el trabajo pendiente (202).</summary>
public sealed record RespuestaProveedor(PaqueteGenerado? Paquete, Trabajo? Trabajo);

/// <summary>
/// ROL PROVEEDOR por red: atiende <c>POST /api/crypto/forward</c> y <c>/inverse</c> de otros
/// nodos para RSA y ECC (los algoritmos del Equipo 3).
/// </summary>
/// <remarks>
/// <code>
/// 13.2  1 tamaño (+13.1 sobre package en inverse)   5 timestamp ±10 min y requestId no repetido
///       2 certificado válido, CN = requesterNode    6 algoritmo propio (404 E-ALGORITHM-NOT-PROVIDED)
///       3 requestSignature sobre los bytes exactos  7 sobre secrets para este nodo (401)
///       4 targetNode = EQ03                          8 secretos y opciones válidos (400 E-PARAMS)
/// 13.3  máximo 10 peticiones simultáneas → 503 E-BUSY
/// 10.6  tope de 30 s; si no termina → 202 { jobId, statusUrl, retryAfterSeconds }
/// </code>
/// </remarks>
public sealed class ServicioProveedor(
    IdentidadNodo yo, ProveedorLocal proveedor, RepositorioNodo repo, ServicioDirectorio directorio,
    AjustesNodo ajustes, OpcionesNodo opciones, DireccionPropia direccion)
{
    private readonly SemaphoreSlim Cupos = new(10, 10);   // por nodo (13.3)
    private readonly ConcurrentDictionary<string, Trabajo> _trabajos = new();

    /// <summary>Resultados asíncronos se conservan al menos 1 h (10.7); aquí 2 h.</summary>
    public static readonly TimeSpan Retencion = TimeSpan.FromHours(2);

    public async Task<RespuestaProveedor> Atender(string operacion, PartesCripto partes, CancellationToken ct)
    {
        if (!Cupos.Wait(0)) throw new ErrorProtocolo("E-BUSY", $"{yo.NodoId} ya atiende 10 peticiones /api/crypto/*; reintenta en unos segundos.");
        try
        {
            var (peticion, cert, paquete) = Validar(operacion, partes);
            var solicitante = peticion.RequesterNode;
            repo.Registrar("proveedor", $"{solicitante} pidió {peticion.AlgorithmCode} {operacion} (requestId {peticion.RequestId[..8]}…)");

            // Ejecución con tope síncrono. La tarea sigue aunque se responda 202.
            var tarea = Task.Run(() => Ejecutar(operacion, peticion, partes, cert, paquete), CancellationToken.None);
            var tope = Task.Delay(TimeSpan.FromSeconds(Math.Max(0, opciones.TopeSincronoSegundos)), ct);
            if (await Task.WhenAny(tarea, tope) == tarea) return new RespuestaProveedor(await tarea, null);

            var t = new Trabajo { Solicitante = solicitante };
            _trabajos[t.JobId] = t;
            _ = tarea.ContinueWith(r =>
            {
                if (r.IsCompletedSuccessfully) { t.Resultado = r.Result; t.Estado = "done"; t.Progreso = 100; }
                else { t.Error = r.Exception?.InnerException as ErrorProtocolo ?? new ErrorProtocolo("E-INTERNAL", r.Exception?.InnerException?.Message ?? "Error interno"); t.Estado = "failed"; }
            }, TaskScheduler.Default);
            Limpiar();
            return new RespuestaProveedor(null, t);
        }
        finally { Cupos.Release(); }
    }

    /// <summary>Estado de un trabajo; null si no existe o expiró.</summary>
    public Trabajo? Trabajo(string jobId) => _trabajos.TryGetValue(jobId, out var t) ? t : null;

    // ------------------------------------------------------------------ 13.2

    private (PeticionCripto, X509Certificate2, PaqueteLeido?) Validar(string operacion, PartesCripto partes)
    {
        // Partes obligatorias
        if (partes.Request.Length == 0 || string.IsNullOrWhiteSpace(partes.Firma) || string.IsNullOrWhiteSpace(partes.CertificadoPem))
            throw new ErrorProtocolo("E-REQUEST", "Faltan partes: request, requestSignature y requesterCertificate son obligatorias.");
        if (operacion == Operaciones.Forward && partes.Payload is null)
            throw new ErrorProtocolo("E-REQUEST", "forward requiere la parte 'payload'.");
        if (operacion == Operaciones.Inverse && partes.Package is null)
            throw new ErrorProtocolo("E-REQUEST", "inverse requiere la parte 'package'.");

        PeticionCripto p;
        try { p = JsonSerializer.Deserialize<PeticionCripto>(partes.Request, PeticionCripto.Json) ?? throw new JsonException("vacío"); }
        catch (JsonException ex) { throw new ErrorProtocolo("E-REQUEST", "La parte 'request' no es JSON válido: " + ex.Message); }
        if (p.Version != Identificadores.VersionProtocolo) throw new ErrorProtocolo("E-VERSION", $"request.version '{p.Version}' no soportada.");
        if (!Identificadores.Uuid4().IsMatch(p.RequestId ?? "") || !Identificadores.NodeId().IsMatch(p.RequesterNode ?? "") ||
            !Identificadores.Timestamp().IsMatch(p.TimestampUtc ?? "") || p.Operation != operacion || p.Options is null)
            throw new ErrorProtocolo("E-REQUEST", "request mal formado (requestId, requesterNode, timestampUtc, operation u options).");
        p.RequesterNode ??= ""; p.RequestId ??= ""; p.AlgorithmCode ??= ""; p.OriginalFileName ??= "";

        // 1. 13.1 sobre el package de inverse
        PaqueteLeido? paquete = null;
        if (operacion == Operaciones.Inverse)
        {
            paquete = EmpaquetadorZip.Leer(partes.Package!);
            // La ventana de tiempo de 13.1 no aplica al package de un inverse: puede ser un
            // paquete viejo de Consultas. Se valida todo lo demás.
            var info = ValidadorPaquete.Validar(paquete, Identificadores.LeerFecha(paquete.Manifiesto.TimestampUtc) ?? DateTime.UtcNow);
            directorio.ConfianzaDe(paquete.Manifiesto.SourceNode, info.Huella);
            if (paquete.Manifiesto.AlgorithmCode != p.AlgorithmCode)
                throw new ErrorProtocolo("E-REQUEST", "request.algorithmCode no coincide con el del package.");
        }

        // 2. Certificado del solicitante
        X509Certificate2 cert;
        try { cert = IdentidadNodo.LeerPem(partes.CertificadoPem); }
        catch (CryptographicException) { throw new ErrorProtocolo("E-CERT", "requesterCertificate no es un X.509 PEM válido."); }
        if (IdentidadNodo.ProblemaCertificado(cert, p.RequesterNode, DateTime.UtcNow) is { } problema)
            throw new ErrorProtocolo("E-CERT", "requesterCertificate: " + problema);
        directorio.ConfianzaDe(p.RequesterNode, Huellas.HuellaCertificado(cert)); // 403 si está fijado con otra huella

        // 3. Firma de la petición
        byte[] firma;
        try { firma = Convert.FromBase64String(partes.Firma.Trim()); }
        catch (FormatException) { throw new ErrorProtocolo("E-REQUEST-SIGNATURE", "requestSignature no es Base64."); }
        if (!FirmaManifiesto.VerificarBytes(partes.Request, firma, cert))
            throw new ErrorProtocolo("E-REQUEST-SIGNATURE", "requestSignature no corresponde a los bytes de 'request'.");

        // 4. Destino
        if (p.TargetNode != yo.NodoId) throw new ErrorProtocolo("E-REQUEST", $"targetNode es {p.TargetNode}, pero este nodo es {yo.NodoId}.");

        // 5. Tiempo y repetición
        if (!Identificadores.DentroDeVentana(p.TimestampUtc, DateTime.UtcNow))
            throw new ErrorProtocolo("E-TIMESTAMP", "request.timestampUtc fuera de la ventana de ±10 min.");
        if (!repo.RegistrarPeticion(p.RequestId))
            throw new ErrorProtocolo("E-DUPLICATE", $"El requestId {p.RequestId} ya se había atendido.");

        // 6. Algoritmo propio (y habilitado en Ajustes)
        if (!proveedor.Provee(p.AlgorithmCode) || !ajustes.Habilitado(p.AlgorithmCode))
            throw new ErrorProtocolo("E-ALGORITHM-NOT-PROVIDED", $"{yo.NodoId} no provee {p.AlgorithmCode}.");

        // 7. Sobre de secretos: RSA y ECC no usan secretos, pero si llega uno se valida igual.
        if (p.Secrets is not null)
        {
            var abierto = p.Secrets.Abrir(yo, p.RequestId);
            Dictionary<string, string>? secretos;
            try { secretos = JsonSerializer.Deserialize<Dictionary<string, string>>(abierto); }
            catch (JsonException) { throw new ErrorProtocolo("E-PARAMS", "El contenido del sobre no es un JSON de cadenas."); }
            finally { CryptographicOperations.ZeroMemory(abierto); }
            if (secretos is { Count: > 0 })
                throw new ErrorProtocolo("E-PARAMS", $"{p.AlgorithmCode} no usa secretos (la llave la guarda {yo.NodoId} con keyId).");
        }

        // 8. Opciones y modo
        if (!ModosCarga.EsValido(p.PayloadMode) && operacion == Operaciones.Forward)
            throw new ErrorProtocolo("E-PARAMS", $"payloadMode '{p.PayloadMode}' no válido.");
        if (operacion == Operaciones.Forward && p.PayloadMode == ModosCarga.Multiparte)
            throw new ErrorProtocolo("E-PARAMS", "RSA y ECC no aceptan multipart.");
        return (p, cert, paquete);
    }

    // ------------------------------------------------------------------ Ejecución

    private PaqueteGenerado Ejecutar(string operacion, PeticionCripto p, PartesCripto partes, X509Certificate2 cert, PaqueteLeido? paquete)
    {
        using (cert)
        {
            if (operacion == Operaciones.Forward)
            {
                var nombre = string.IsNullOrWhiteSpace(p.OriginalFileName) ? partes.NombrePayload ?? "mensaje.txt" : p.OriginalFileName;
                var r = proveedor.Forward(new PeticionForward(p.AlgorithmCode, partes.Payload!, p.PayloadMode, nombre,
                    p.KeyId, p.Options, p.RequestId, p.RequesterNode), direccion.Obtener());
                repo.Registrar("proveedor", $"forward {p.AlgorithmCode} para {p.RequesterNode} → {r.NombreZip} (keyId {r.Manifiesto.KeyRef?.KeyId})");
                return r;
            }
            var original = proveedor.Inverse(paquete!, p.RequesterNode);
            try
            {
                var r = proveedor.EmpaquetarResultado(original, paquete!.Manifiesto, cert, p.RequesterNode, p.RequestId, direccion.Obtener());
                repo.Registrar("proveedor", $"inverse {p.AlgorithmCode} para {p.RequesterNode} → {r.NombreZip}");
                return r;
            }
            finally { CryptographicOperations.ZeroMemory(original); }
        }
    }

    private void Limpiar()
    {
        foreach (var (id, t) in _trabajos)
            if (t.CreadoUtc < DateTime.UtcNow - Retencion) _trabajos.TryRemove(id, out _);
    }
}

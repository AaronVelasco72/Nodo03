using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nodo03.Core.Protocolo;

/// <summary>
/// <c>manifest.json</c> versión 2.0 (sección 9.5 del estándar). Los nombres JSON son exactamente
/// los del estándar; los campos que aceptan <c>null</c> se escriben como <c>null</c> (no se omiten),
/// porque el estándar los marca como obligatorios.
/// </summary>
public sealed class Manifiesto
{
    [JsonPropertyName("version")] public string Version { get; set; } = Identificadores.VersionProtocolo;
    [JsonPropertyName("packetType")] public string PacketType { get; set; } = TiposPaquete.Package;
    [JsonPropertyName("packetId")] public string PacketId { get; set; } = Identificadores.NuevoUuid();
    [JsonPropertyName("requestId")] public string? RequestId { get; set; }
    [JsonPropertyName("sourceNode")] public string SourceNode { get; set; } = "";
    [JsonPropertyName("sourceTeam")] public int SourceTeam { get; set; }
    [JsonPropertyName("sourceIp")] public string SourceIp { get; set; } = "";
    [JsonPropertyName("producerNode")] public string ProducerNode { get; set; } = "";
    [JsonPropertyName("timestampUtc")] public string TimestampUtc { get; set; } = "";
    [JsonPropertyName("algorithmId")] public int AlgorithmId { get; set; }
    [JsonPropertyName("algorithmCode")] public string AlgorithmCode { get; set; } = "";
    [JsonPropertyName("algorithmName")] public string AlgorithmName { get; set; } = "";
    [JsonPropertyName("operation")] public string Operation { get; set; } = Operaciones.Forward;
    [JsonPropertyName("operationName")] public string OperationName { get; set; } = "";
    [JsonPropertyName("payloadMode")] public string PayloadMode { get; set; } = ModosCarga.Archivo;
    [JsonPropertyName("originalFileName")] public string OriginalFileName { get; set; } = "";
    [JsonPropertyName("originalExtension")] public string OriginalExtension { get; set; } = "";
    [JsonPropertyName("originalSizeBytes")] public long OriginalSizeBytes { get; set; }
    [JsonPropertyName("contentType")] public string ContentType { get; set; } = "application/octet-stream";
    [JsonPropertyName("encryptedSha256")] public string EncryptedSha256 { get; set; } = "";
    [JsonPropertyName("encryptedSizeBytes")] public long EncryptedSizeBytes { get; set; }
    [JsonPropertyName("parts")] public List<ParteMultiarchivo>? Parts { get; set; }
    [JsonPropertyName("keyRef")] public RefLlave? KeyRef { get; set; }

    /// <summary>Objeto PLANO con valores cadena (sección 8.5). Nunca secretos.</summary>
    [JsonPropertyName("publicParameters")] public Dictionary<string, string> PublicParameters { get; set; } = new(StringComparer.Ordinal);

    [JsonPropertyName("publicParametersSha256")] public string PublicParametersSha256 { get; set; } = "";
    [JsonPropertyName("verification")] public Verificacion? Verification { get; set; }
    [JsonPropertyName("resultEnvelope")] public Cripto.SobreCc? ResultEnvelope { get; set; }
    [JsonPropertyName("certificateThumbprintSha256")] public string CertificateThumbprintSha256 { get; set; } = "";
    [JsonPropertyName("signatureAlgorithm")] public string SignatureAlgorithm { get; set; } = Cripto.FirmaManifiesto.Algoritmo;
    [JsonPropertyName("manifestSignatureBase64")] public string ManifestSignatureBase64 { get; set; } = "";

    /// <summary>Campos desconocidos: se ignoran (regla de 9.5), pero se conservan al leer.</summary>
    [JsonExtensionData] public Dictionary<string, JsonElement>? CamposExtra { get; set; }

    /// <summary>Campos que DEBEN existir en el JSON (aunque su valor sea null).</summary>
    public static readonly string[] Obligatorios =
    [
        "version", "packetType", "packetId", "requestId", "sourceNode", "sourceTeam", "sourceIp", "producerNode",
        "timestampUtc", "algorithmId", "algorithmCode", "algorithmName", "operation", "operationName", "payloadMode",
        "originalFileName", "originalExtension", "originalSizeBytes", "contentType", "encryptedSha256",
        "encryptedSizeBytes", "parts", "keyRef", "publicParameters", "publicParametersSha256",
        "certificateThumbprintSha256", "signatureAlgorithm", "manifestSignatureBase64",
    ];

    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    /// <summary>JSON UTF-8 sin BOM.</summary>
    public byte[] ABytes() => JsonSerializer.SerializeToUtf8Bytes(this, Json);

    /// <summary>Copia profunda (para reempaquetar sin tocar el original).</summary>
    public Manifiesto Clonar() => JsonSerializer.Deserialize<Manifiesto>(ABytes(), Json)!;

    /// <summary>
    /// Lee y valida el FORMATO del manifiesto (validación 5 de la sección 13.1).
    /// Lanza <see cref="ErrorProtocolo"/> E-MANIFEST con el detalle del problema.
    /// </summary>
    public static Manifiesto Leer(byte[] json)
    {
        ReadOnlySpan<byte> datos = json;
        if (datos.Length >= 3 && datos[0] == 0xEF && datos[1] == 0xBB && datos[2] == 0xBF) datos = datos[3..];

        Manifiesto m;
        try
        {
            using var doc = JsonDocument.Parse(datos.ToArray());
            if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new ErrorProtocolo("E-MANIFEST", "manifest.json no es un objeto JSON.");
            var faltan = Obligatorios.Where(c => !doc.RootElement.TryGetProperty(c, out _)).ToList();
            if (faltan.Count > 0) throw new ErrorProtocolo("E-MANIFEST", "Faltan campos obligatorios: " + string.Join(", ", faltan));
            if (doc.RootElement.GetProperty("publicParameters").ValueKind != JsonValueKind.Object)
                throw new ErrorProtocolo("E-MANIFEST", "publicParameters debe ser un objeto plano.");
            m = JsonSerializer.Deserialize<Manifiesto>(datos, Json)!;
        }
        catch (JsonException ex)
        {
            throw new ErrorProtocolo("E-MANIFEST", "manifest.json inválido (¿publicParameters con valores que no son cadena?): " + ex.Message);
        }
        ValidarFormatos(m);
        return m;
    }

    private static void ValidarFormatos(Manifiesto m)
    {
        var e = new List<string>();
        if (m.PacketType is not (TiposPaquete.Package or TiposPaquete.Result)) e.Add("packetType");
        if (!Identificadores.Uuid4().IsMatch(m.PacketId ?? "")) e.Add("packetId");
        if (m.RequestId is not null && !Identificadores.Uuid4().IsMatch(m.RequestId)) e.Add("requestId");
        if (!Identificadores.NodeId().IsMatch(m.SourceNode ?? "")) e.Add("sourceNode");
        if (Identificadores.EquipoDeNodo(m.SourceNode) != m.SourceTeam) e.Add("sourceTeam");
        if (!Identificadores.NodeId().IsMatch(m.ProducerNode ?? "")) e.Add("producerNode");
        if (!Identificadores.Timestamp().IsMatch(m.TimestampUtc ?? "")) e.Add("timestampUtc");
        if (!Operaciones.EsValida(m.Operation)) e.Add("operation");
        if (!ModosCarga.EsValido(m.PayloadMode)) e.Add("payloadMode");
        if (!Identificadores.HashContenido().IsMatch(m.EncryptedSha256 ?? "")) e.Add("encryptedSha256");
        if (!Identificadores.HashContenido().IsMatch(m.PublicParametersSha256 ?? "")) e.Add("publicParametersSha256");
        if (!Identificadores.Huella().IsMatch(m.CertificateThumbprintSha256 ?? "")) e.Add("certificateThumbprintSha256");
        if (m.SignatureAlgorithm != Cripto.FirmaManifiesto.Algoritmo) e.Add("signatureAlgorithm");
        if (string.IsNullOrEmpty(m.ManifestSignatureBase64)) e.Add("manifestSignatureBase64");
        if (m.PayloadMode == ModosCarga.Multiparte && (m.Parts is null || m.Parts.Count == 0)) e.Add("parts");
        if (m.KeyRef is not null && !Identificadores.KeyId().IsMatch(m.KeyRef.KeyId ?? "")) e.Add("keyRef.keyId");
        if (e.Count > 0) throw new ErrorProtocolo("E-MANIFEST", "Formato inválido en: " + string.Join(", ", e));
    }

    /// <summary>Parámetro público o null.</summary>
    public string? Parametro(string nombre) => PublicParameters.TryGetValue(nombre, out var v) ? v : null;
}

/// <summary>Elemento de <c>parts</c> en paquetes multiparte (9.4).</summary>
public sealed record ParteMultiarchivo(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("sizeBytes")] long SizeBytes,
    [property: JsonPropertyName("sha256")] string Sha256);

/// <summary><c>keyRef</c>: llave guardada por el dueño del algoritmo (sección 12).</summary>
public sealed record RefLlave(
    [property: JsonPropertyName("keyId")] string KeyId,
    [property: JsonPropertyName("ownerNode")] string OwnerNode);

/// <summary><c>verification</c> en paquetes result de hash, MAC y firma.</summary>
public sealed record Verificacion(
    [property: JsonPropertyName("valid")] bool Valid,
    [property: JsonPropertyName("detail")] string Detail);

/// <summary>Valores de <c>payloadMode</c>.</summary>
public static class ModosCarga
{
    public const string Texto = "text";
    public const string Imagen = "image";
    public const string Archivo = "file";
    public const string Multiparte = "multipart";

    public static bool EsValido(string? m) => m is Texto or Imagen or Archivo or Multiparte;

    public static string Normalizar(string? modo) => modo?.Trim().ToLowerInvariant() switch
    {
        "text" or "texto" => Texto,
        "image" or "imagen" => Imagen,
        "multipart" => Multiparte,
        _ => Archivo,
    };

    /// <summary>Tipo MIME a partir de la extensión.</summary>
    public static string Mime(string nombre, string modo) => Path.GetExtension(nombre).ToLowerInvariant() switch
    {
        ".png" => "image/png",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".bmp" => "image/bmp",
        ".webp" => "image/webp",
        ".pdf" => "application/pdf",
        ".txt" => "text/plain",
        ".json" => "application/json",
        ".zip" => "application/zip",
        _ => modo == Texto ? "text/plain" : "application/octet-stream",
    };
}

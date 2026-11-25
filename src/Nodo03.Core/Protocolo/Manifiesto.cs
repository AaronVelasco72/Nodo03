using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Nodo03.Core.Protocolo;

/// <summary>
/// Representa el archivo <c>manifest.json</c> definido en la sección 2.1 de la propuesta.
/// </summary>
/// <remarks>
/// <para>
/// Los nombres JSON se fijan con <see cref="JsonPropertyNameAttribute"/> para que sean
/// EXACTAMENTE los del estándar (camelCase en inglés), sin importar cómo se llamen
/// las propiedades en C#. Así un nodo en Java, Node.js o Python lee lo mismo.
/// </para>
/// <para>
/// Campos que otros equipos agreguen y que este nodo no conoce NO se pierden:
/// quedan en <see cref="CamposExtra"/> y se vuelven a escribir tal cual
/// (<see cref="JsonExtensionDataAttribute"/>).
/// </para>
/// </remarks>
public sealed class Manifiesto
{
    /// <summary>Versión del protocolo. Hoy siempre "1.0".</summary>
    [JsonPropertyName("version")] public string Version { get; set; } = "1.0";

    /// <summary>Identificador único del paquete (UUID). Sirve para detectar duplicados.</summary>
    [JsonPropertyName("packetId")] public string PacketId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>Nodo emisor tal como se presenta, ej. "NODO-03".</summary>
    [JsonPropertyName("sourceNode")] public string SourceNode { get; set; } = "";

    /// <summary>"IP:Puerto" donde el emisor escucha. Es a donde se regresa la pelota en el ping-pong.</summary>
    [JsonPropertyName("sourceIp")] public string SourceIp { get; set; } = "";

    /// <summary>
    /// Marca de tiempo UTC en formato ISO-8601 sin fracciones: "2026-11-24T20:15:00Z".
    /// Se guarda como TEXTO (no como DateTime) porque forma parte de la cadena firmada:
    /// si se reformateara, la firma dejaría de coincidir.
    /// </summary>
    [JsonPropertyName("timestampUtc")] public string TimestampUtc { get; set; } = "";

    /// <summary>Nombre técnico legible, ej. "RSA-OAEP-SHA256+AES-256-GCM".</summary>
    [JsonPropertyName("algorithm")] public string Algorithm { get; set; } = "";

    /// <summary>Código corto oficial de la tabla 1.1, ej. "RSA" o "ECC".</summary>
    [JsonPropertyName("algorithmCode")] public string AlgorithmCode { get; set; } = "";

    /// <summary>"text", "image" o "file".</summary>
    [JsonPropertyName("payloadMode")] public string PayloadMode { get; set; } = ModosCarga.Archivo;

    /// <summary>Nombre del archivo original (para texto: "mensaje.txt").</summary>
    [JsonPropertyName("originalFileName")] public string OriginalFileName { get; set; } = "";

    /// <summary>Extensión original con punto, ej. ".png".</summary>
    [JsonPropertyName("originalExtension")] public string OriginalExtension { get; set; } = "";

    /// <summary>Tamaño en bytes del contenido ANTES de cifrar.</summary>
    [JsonPropertyName("originalSizeBytes")] public long OriginalSizeBytes { get; set; }

    /// <summary>SHA-256 en hexadecimal minúsculas (64 caracteres) de los bytes exactos de datos.enc.</summary>
    [JsonPropertyName("encryptedSha256")] public string EncryptedSha256 { get; set; } = "";

    /// <summary>
    /// Parámetros públicos para descifrar (IV, tag, llave efímera, etc.).
    /// NUNCA contiene llaves privadas ni contraseñas.
    /// Se modela como <see cref="JsonObject"/> porque cada algoritmo usa campos distintos.
    /// </summary>
    [JsonPropertyName("publicParameters")] public JsonObject PublicParameters { get; set; } = new();

    /// <summary>SHA-256 (hex MAYÚSCULAS) del certificado DER incluido en certificado.pem.</summary>
    [JsonPropertyName("certificateThumbprintSha256")] public string CertificateThumbprintSha256 { get; set; } = "";

    /// <summary>"RSA-PSS-SHA256" o "ECDSA-P256-SHA256" en este nodo.</summary>
    [JsonPropertyName("signatureAlgorithm")] public string SignatureAlgorithm { get; set; } = "";

    /// <summary>Firma en Base64 de <c>Cripto.FirmaManifiesto.CadenaAFirmar</c>.</summary>
    [JsonPropertyName("manifestSignatureBase64")] public string ManifestSignatureBase64 { get; set; } = "";

    /// <summary>Campos desconocidos que vengan de otros equipos (se conservan).</summary>
    [JsonExtensionData] public Dictionary<string, JsonElement>? CamposExtra { get; set; }

    // ------------------------------------------------------------------
    // Serialización
    // ------------------------------------------------------------------

    /// <summary>
    /// Opciones compartidas: JSON con sangría (legible al abrir el zip), sin escapar
    /// acentos (UTF-8 real) y tolerante a mayúsculas/minúsculas al LEER, por si
    /// otro equipo escribió "PacketId" en lugar de "packetId".
    /// </summary>
    public static readonly JsonSerializerOptions OpcionesJson = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
    };

    /// <summary>Convierte a JSON UTF-8 sin BOM (el BOM rompe algunos parsers de otros lenguajes).</summary>
    public byte[] ABytes() => JsonSerializer.SerializeToUtf8Bytes(this, OpcionesJson);

    /// <summary>Lee un manifest.json. Lanza <see cref="PaqueteMalformadoException"/> si no es JSON válido.</summary>
    public static Manifiesto DesdeBytes(byte[] json)
    {
        try
        {
            // Quitamos un posible BOM UTF-8 que algún editor haya agregado.
            ReadOnlySpan<byte> datos = json;
            if (datos.Length >= 3 && datos[0] == 0xEF && datos[1] == 0xBB && datos[2] == 0xBF) datos = datos[3..];
            return JsonSerializer.Deserialize<Manifiesto>(datos, OpcionesJson)
                   ?? throw new PaqueteMalformadoException("manifest.json está vacío.");
        }
        catch (JsonException ex)
        {
            throw new PaqueteMalformadoException($"manifest.json no es JSON válido: {ex.Message}");
        }
    }

    // ------------------------------------------------------------------
    // Ayudantes para leer publicParameters sin pelear con JsonNode
    // ------------------------------------------------------------------

    /// <summary>Lee un parámetro público como texto (o null si no existe).</summary>
    public string? Parametro(string nombre) =>
        PublicParameters.TryGetPropertyValue(nombre, out var n) && n is not null ? n.ToString() : null;

    /// <summary>Lee un parámetro público entero (o el valor por defecto).</summary>
    public int ParametroEntero(string nombre, int porDefecto = 0) =>
        int.TryParse(Parametro(nombre), out var v) ? v : porDefecto;
}

/// <summary>Valores permitidos para <see cref="Manifiesto.PayloadMode"/>.</summary>
public static class ModosCarga
{
    public const string Texto = "text";
    public const string Imagen = "image";
    public const string Archivo = "file";

    /// <summary>Normaliza lo que venga del usuario u otro nodo a uno de los tres valores.</summary>
    public static string Normalizar(string? modo) => modo?.Trim().ToLowerInvariant() switch
    {
        "text" or "texto" => Texto,
        "image" or "imagen" => Imagen,
        _ => Archivo,
    };
}

/// <summary>
/// Se lanza cuando el paquete no respeta la ESTRUCTURA del estándar
/// (no es zip, faltan archivos, JSON roto...). El receptor responde 400 Bad Request.
/// </summary>
public sealed class PaqueteMalformadoException(string mensaje) : Exception(mensaje);

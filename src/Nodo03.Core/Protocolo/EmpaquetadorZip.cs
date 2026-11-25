using System.IO.Compression;
using System.Text;

namespace Nodo03.Core.Protocolo;

/// <summary>
/// Arma y abre el .zip del estándar (sección 2): EXACTAMENTE tres archivos en la raíz.
/// </summary>
/// <remarks>
/// <code>
/// NODO03_RSA_20261124_201500_9F86D081.zip
///  ├── datos.enc        contenido cifrado (binario)
///  ├── certificado.pem  certificado X.509 público del emisor
///  └── manifest.json    metadatos + huellas + firma
/// </code>
/// <para><b>Seguridad al abrir zips ajenos:</b></para>
/// <list type="bullet">
///   <item>Solo se aceptan esos tres nombres exactos: así es imposible un ataque
///   "zip slip" (rutas como <c>../../windows/system32/x.dll</c>).</item>
///   <item>Se limita el tamaño DESCOMPRIMIDO de cada archivo y se lee con tope, para que una
///   "bomba zip" (pocos KB que se inflan a GB) no tumbe el nodo.</item>
///   <item>Nunca se escribe nada del zip en disco durante la validación: todo es en memoria.</item>
/// </list>
/// </remarks>
public static class EmpaquetadorZip
{
    public const string ArchivoDatos = "datos.enc";
    public const string ArchivoCertificado = "certificado.pem";
    public const string ArchivoManifiesto = "manifest.json";

    /// <summary>Los tres nombres obligatorios.</summary>
    public static readonly string[] Obligatorios = [ArchivoDatos, ArchivoCertificado, ArchivoManifiesto];

    /// <summary>Crea el .zip en memoria con los tres archivos.</summary>
    public static byte[] Crear(byte[] datosEnc, string certificadoPem, Manifiesto manifiesto)
    {
        using var memoria = new MemoryStream();
        using (var zip = new ZipArchive(memoria, ZipArchiveMode.Create, leaveOpen: true))
        {
            // datos.enc ya está cifrado (parece ruido aleatorio): comprimirlo no ahorra nada.
            Escribir(zip, ArchivoDatos, datosEnc, CompressionLevel.NoCompression);
            Escribir(zip, ArchivoCertificado, Encoding.ASCII.GetBytes(certificadoPem), CompressionLevel.Optimal);
            Escribir(zip, ArchivoManifiesto, manifiesto.ABytes(), CompressionLevel.Optimal);
        }
        return memoria.ToArray();
    }

    private static void Escribir(ZipArchive zip, string nombre, byte[] contenido, CompressionLevel nivel)
    {
        var entrada = zip.CreateEntry(nombre, nivel);
        // Fecha fija en UTC del momento: no afecta la firma, solo es informativa.
        entrada.LastWriteTime = DateTimeOffset.UtcNow;
        using var s = entrada.Open();
        s.Write(contenido);
    }

    /// <summary>
    /// Abre un .zip recibido y valida su ESTRUCTURA (no la criptografía; eso lo hace
    /// <see cref="ValidadorPaquete"/>).
    /// </summary>
    /// <param name="zipBytes">Bytes del archivo recibido.</param>
    /// <param name="maxBytesPorArchivo">Tope descomprimido por archivo (defensa anti bomba zip).</param>
    /// <exception cref="PaqueteMalformadoException">Si no cumple el estándar (=> HTTP 400).</exception>
    public static PaqueteLeido Leer(byte[] zipBytes, long maxBytesPorArchivo = 64L * 1024 * 1024)
    {
        ZipArchive zip;
        try
        {
            zip = new ZipArchive(new MemoryStream(zipBytes, writable: false), ZipArchiveMode.Read);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException or IOException)
        {
            throw new PaqueteMalformadoException("El archivo recibido no es un .zip válido.");
        }

        using (zip)
        {
            var nombres = zip.Entries.Select(e => e.FullName).ToList();

            // Regla: exactamente 3 archivos en la raíz, sin carpetas.
            var conCarpeta = nombres.Where(n => n.Contains('/') || n.Contains('\\')).ToList();
            if (conCarpeta.Count > 0)
                throw new PaqueteMalformadoException(
                    $"El .zip no debe tener subcarpetas (se encontró: {string.Join(", ", conCarpeta)}).");

            var faltantes = Obligatorios.Except(nombres, StringComparer.Ordinal).ToList();
            if (faltantes.Count > 0)
                throw new PaqueteMalformadoException($"Falta(n) en el .zip: {string.Join(", ", faltantes)}.");

            var sobrantes = nombres.Except(Obligatorios, StringComparer.Ordinal).ToList();
            if (sobrantes.Count > 0 || nombres.Count != 3)
                throw new PaqueteMalformadoException(
                    $"El .zip debe contener exactamente 3 archivos; sobran: {string.Join(", ", sobrantes)}.");

            byte[] LeerEntrada(string nombre)
            {
                var e = zip.GetEntry(nombre)!;
                if (e.Length > maxBytesPorArchivo)
                    throw new PaqueteMalformadoException($"{nombre} excede el tamaño permitido.");
                using var s = e.Open();
                using var destino = new MemoryStream();
                // Copia con tope: no confiamos en el tamaño declarado en el encabezado del zip.
                var buffer = new byte[81920];
                int leidos;
                long total = 0;
                while ((leidos = s.Read(buffer, 0, buffer.Length)) > 0)
                {
                    total += leidos;
                    if (total > maxBytesPorArchivo)
                        throw new PaqueteMalformadoException($"{nombre} excede el tamaño permitido.");
                    destino.Write(buffer, 0, leidos);
                }
                return destino.ToArray();
            }

            byte[] datos, cert, json;
            try
            {
                datos = LeerEntrada(ArchivoDatos);
                cert = LeerEntrada(ArchivoCertificado);
                json = LeerEntrada(ArchivoManifiesto);
            }
            catch (InvalidDataException)
            {
                throw new PaqueteMalformadoException("El .zip está dañado (no se pudo descomprimir).");
            }

            var manifiesto = Manifiesto.DesdeBytes(json);
            ValidarCamposObligatorios(manifiesto);
            return new PaqueteLeido(datos, cert, json, manifiesto);
        }
    }

    /// <summary>Campos sin los cuales no se puede ni verificar el paquete (=> 400).</summary>
    private static void ValidarCamposObligatorios(Manifiesto m)
    {
        var faltan = new List<string>();
        if (string.IsNullOrWhiteSpace(m.PacketId)) faltan.Add("packetId");
        if (string.IsNullOrWhiteSpace(m.TimestampUtc)) faltan.Add("timestampUtc");
        if (string.IsNullOrWhiteSpace(m.EncryptedSha256)) faltan.Add("encryptedSha256");
        if (string.IsNullOrWhiteSpace(m.CertificateThumbprintSha256)) faltan.Add("certificateThumbprintSha256");
        if (string.IsNullOrWhiteSpace(m.ManifestSignatureBase64)) faltan.Add("manifestSignatureBase64");
        if (faltan.Count > 0)
            throw new PaqueteMalformadoException($"manifest.json incompleto, falta: {string.Join(", ", faltan)}.");
    }
}

/// <summary>Contenido de un .zip ya abierto y con estructura correcta.</summary>
/// <param name="DatosEnc">Bytes de datos.enc.</param>
/// <param name="CertificadoPem">Bytes de certificado.pem.</param>
/// <param name="ManifiestoJson">Bytes originales de manifest.json (se guardan tal cual).</param>
/// <param name="Manifiesto">manifest.json ya interpretado.</param>
public sealed record PaqueteLeido(byte[] DatosEnc, byte[] CertificadoPem, byte[] ManifiestoJson, Manifiesto Manifiesto);

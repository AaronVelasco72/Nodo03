using System.IO.Compression;
using System.Text;

namespace Nodo03.Core.Protocolo;

/// <summary>
/// Arma y abre los .zip de la sección 9 del estándar v2.0.
/// <code>
/// package: datos.enc     + certificado.pem + manifest.json
/// result:  resultado.enc + certificado.pem + manifest.json
/// </code>
/// Al abrir aplica las validaciones 2–5 de la sección 13.1 (zip válido, estructura, bomba zip y
/// formato del manifiesto) y lanza <see cref="ErrorProtocolo"/> con el código del Anexo B.
/// </summary>
public static class EmpaquetadorZip
{
    public const string Datos = "datos.enc";
    public const string Resultado = "resultado.enc";
    public const string Certificado = "certificado.pem";
    public const string ManifiestoJson = "manifest.json";

    public const long MaxDescomprimido = 200L * 1024 * 1024; // 13.1 paso 4
    public const double MaxRazonCompresion = 100;            // 100:1
    public const int MaxPartes = 64;                         // 9.4

    /// <summary>Crea el zip con los 3 archivos.</summary>
    public static byte[] Crear(byte[] datos, string certificadoPem, Manifiesto m)
    {
        var nombreDatos = m.PacketType == TiposPaquete.Result ? Resultado : Datos;
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true, entryNameEncoding: Encoding.UTF8))
        {
            Agregar(zip, nombreDatos, datos, CompressionLevel.NoCompression); // ya cifrado: comprimir no ahorra
            Agregar(zip, Certificado, Encoding.ASCII.GetBytes(certificadoPem), CompressionLevel.Optimal);
            Agregar(zip, ManifiestoJson, m.ABytes(), CompressionLevel.Optimal);
        }
        return ms.ToArray();
    }

    private static void Agregar(ZipArchive zip, string nombre, byte[] contenido, CompressionLevel nivel)
    {
        using var s = zip.CreateEntry(nombre, nivel).Open();
        s.Write(contenido);
    }

    /// <summary>Abre y valida la estructura. No verifica criptografía (eso es <see cref="ValidadorPaquete"/>).</summary>
    public static PaqueteLeido Leer(byte[] zipBytes)
    {
        ZipArchive zip;
        try { zip = new ZipArchive(new MemoryStream(zipBytes, writable: false), ZipArchiveMode.Read, false, Encoding.UTF8); }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException or IOException)
        { throw new ErrorProtocolo("E-ZIP-INVALID", "El cuerpo recibido no es un .zip válido."); }

        using (zip)
        {
            var entradas = zip.Entries.ToList();
            var nombres = entradas.Select(e => e.FullName).ToList();

            // Paso 3: exactamente 3 entradas planas con los nombres exactos.
            if (nombres.Any(n => n.Contains('/') || n.Contains('\\') || n.Contains("..") || n.StartsWith('.')))
                throw new ErrorProtocolo("E-ZIP-STRUCTURE", "El zip contiene carpetas, rutas o archivos ocultos: " + string.Join(", ", nombres));
            var esResultado = nombres.Contains(Resultado);
            var esperados = new[] { esResultado ? Resultado : Datos, Certificado, ManifiestoJson };
            if (nombres.Count != 3 || esperados.Except(nombres, StringComparer.Ordinal).Any())
                throw new ErrorProtocolo("E-ZIP-STRUCTURE",
                    $"Se esperaban exactamente {string.Join(", ", esperados)}; el zip trae: {string.Join(", ", nombres)}.");

            // Paso 4: bomba zip.
            long total = entradas.Sum(e => e.Length), comprimido = entradas.Sum(e => e.CompressedLength);
            if (total > MaxDescomprimido || (comprimido > 0 && (double)total / comprimido > MaxRazonCompresion))
                throw new ErrorProtocolo("E-ZIP-BOMB", $"Descomprimido {total} bytes con razón {(double)total / Math.Max(1, comprimido):0.#}:1.");

            byte[] Leer(string nombre)
            {
                var e = zip.GetEntry(nombre)!;
                try
                {
                    using var s = e.Open();
                    using var destino = new MemoryStream();
                    var buffer = new byte[81920];
                    int n; long leidos = 0;
                    while ((n = s.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        leidos += n;
                        if (leidos > e.Length || leidos > MaxDescomprimido) // no confiamos en el encabezado
                            throw new ErrorProtocolo("E-ZIP-BOMB", $"{nombre} se infla más de lo declarado.");
                        destino.Write(buffer, 0, n);
                    }
                    return destino.ToArray();
                }
                catch (InvalidDataException) { throw new ErrorProtocolo("E-ZIP-INVALID", $"No se pudo descomprimir {nombre} (¿zip dañado o con contraseña?)."); }
            }

            var datos = Leer(esperados[0]);
            var cert = Leer(Certificado);
            var json = Leer(ManifiestoJson);

            // Paso 5: formato del manifiesto.
            var m = Manifiesto.Leer(json);
            if ((m.PacketType == TiposPaquete.Result) != esResultado)
                throw new ErrorProtocolo("E-MANIFEST", $"packetType '{m.PacketType}' no corresponde al archivo {esperados[0]}.");
            return new PaqueteLeido(datos, cert, json, m);
        }
    }

    /// <summary>Lee las partes de un datos.enc multiparte (9.4): zip interno plano, máx. 64 entradas.</summary>
    public static List<(string Nombre, byte[] Bytes)> LeerPartes(byte[] datos)
    {
        try
        {
            using var zip = new ZipArchive(new MemoryStream(datos, false), ZipArchiveMode.Read);
            if (zip.Entries.Count > MaxPartes) throw new ErrorProtocolo("E-ZIP-STRUCTURE", "El zip interno tiene más de 64 partes.");
            if (zip.Entries.Sum(e => e.Length) > MaxDescomprimido) throw new ErrorProtocolo("E-ZIP-BOMB", "Zip interno demasiado grande.");
            return zip.Entries.Select(e =>
            {
                if (e.FullName.Contains('/') || e.FullName.Contains('\\') || e.FullName.Contains(".."))
                    throw new ErrorProtocolo("E-ZIP-STRUCTURE", "El zip interno tiene rutas.");
                using var s = e.Open();
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                return (e.FullName, ms.ToArray());
            }).ToList();
        }
        catch (InvalidDataException) { throw new ErrorProtocolo("E-ZIP-STRUCTURE", "datos.enc multiparte no es un zip válido."); }
    }
}

/// <summary>Contenido de un zip ya abierto.</summary>
/// <param name="Datos">datos.enc o resultado.enc.</param>
/// <param name="CertificadoPem">certificado.pem.</param>
/// <param name="ManifiestoJson">Bytes originales de manifest.json.</param>
/// <param name="Manifiesto">Manifiesto interpretado.</param>
public sealed record PaqueteLeido(byte[] Datos, byte[] CertificadoPem, byte[] ManifiestoJson, Manifiesto Manifiesto);

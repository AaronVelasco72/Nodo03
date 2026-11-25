using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Nodo03.Core.Cripto;

namespace Nodo03.Core.Protocolo;

/// <summary>
/// Validación CRIPTOGRÁFICA de un paquete (pasos 3 y 4 de "Validaciones automáticas al recibir").
/// Funciona con paquetes de CUALQUIER equipo, sin importar con qué algoritmo cifraron datos.enc.
/// </summary>
/// <remarks>
/// Orden de las revisiones:
/// <list type="number">
///   <item><b>Integridad</b>: SHA-256(datos.enc) == manifest.encryptedSha256.</item>
///   <item><b>Certificado</b>: certificado.pem se puede leer como X.509.</item>
///   <item><b>Huella</b>: SHA-256(certificado DER) == manifest.certificateThumbprintSha256.
///   Evita que alguien cambie el certificado por otro.</item>
///   <item><b>Firma</b>: manifestSignatureBase64 verificada con la llave pública del certificado.</item>
/// </list>
/// Además se generan AVISOS (no bloquean): nombre fuera de formato, código de algoritmo
/// no oficial, certificado vencido, etc. Así se reporta el detalle sin rechazar por
/// cuestiones de forma a un equipo que, por ejemplo, nombró mal el archivo.
/// </remarks>
public static class ValidadorPaquete
{
    public static ResultadoValidacion Validar(PaqueteLeido p, string? nombreZip = null)
    {
        var r = new ResultadoValidacion();
        var m = p.Manifiesto;

        // 1) Integridad de datos.enc
        r.Sha256Calculado = Huellas.Sha256Hex(p.DatosEnc);
        r.IntegridadOk = string.Equals(r.Sha256Calculado, m.EncryptedSha256?.Trim(), StringComparison.OrdinalIgnoreCase);
        if (!r.IntegridadOk)
            r.Errores.Add($"SHA-256 de datos.enc no coincide (manifiesto {Corto(m.EncryptedSha256)}…, calculado {Corto(r.Sha256Calculado)}…).");

        // 2) Certificado legible
        X509Certificate2? cert = null;
        try
        {
            cert = IdentidadNodo.LeerCertificadoPem(p.CertificadoPem);
        }
        catch (CryptographicException)
        {
            r.Errores.Add("certificado.pem no es un certificado X.509 PEM válido.");
        }

        if (cert is not null)
        {
            var ahora = DateTime.UtcNow;
            r.Certificado = new InfoCertificado(
                cert.Subject, cert.Issuer, cert.NotBefore.ToUniversalTime(), cert.NotAfter.ToUniversalTime(),
                IdentidadNodo.TipoDeLlave(cert) ?? "?", Huellas.HuellaCertificado(cert),
                cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData),
                ahora >= cert.NotBefore.ToUniversalTime() && ahora <= cert.NotAfter.ToUniversalTime());

            if (!r.Certificado.Vigente)
                r.Avisos.Add($"El certificado no está vigente ({r.Certificado.NoAntes:yyyy-MM-dd} a {r.Certificado.NoDespues:yyyy-MM-dd}).");

            // 3) Huella del certificado
            r.HuellaOk = Huellas.HuellasIguales(r.Certificado.Huella, m.CertificateThumbprintSha256);
            if (!r.HuellaOk)
                r.Errores.Add("certificateThumbprintSha256 no corresponde al certificado incluido.");

            // 4) Firma
            var firma = FirmaManifiesto.Verificar(m, cert, p.ManifiestoJson);
            r.FirmaOk = firma.Valida;
            r.DetalleFirma = firma.Detalle;
            if (!firma.Valida) r.Errores.Add(firma.Detalle);
            cert.Dispose();
        }

        // Avisos de forma (no invalidan el paquete)
        if (!CodigosAlgoritmo.EsOficial(m.AlgorithmCode))
            r.Avisos.Add($"algorithmCode '{m.AlgorithmCode}' no está en la tabla 1.1.");
        if (nombreZip is not null)
        {
            if (!NombrePaquete.TryParse(nombreZip, out var partes))
                r.Avisos.Add($"El nombre '{nombreZip}' no sigue NODO_ALGORITMO_YYYYMMDD_HHMMSS_SHA8.zip.");
            else
            {
                if (!r.Sha256Calculado.StartsWith(partes.Sha8, StringComparison.OrdinalIgnoreCase))
                    r.Avisos.Add("El SHA8 del nombre no coincide con el SHA-256 real de datos.enc.");
                if (!string.IsNullOrEmpty(m.AlgorithmCode) && partes.Algoritmo != m.AlgorithmCode)
                    r.Avisos.Add("El algoritmo del nombre no coincide con algorithmCode del manifiesto.");
            }
        }
        if (!DateTime.TryParse(m.TimestampUtc, null, System.Globalization.DateTimeStyles.AdjustToUniversal, out _))
            r.Avisos.Add("timestampUtc no es una fecha ISO-8601 válida.");

        return r;
    }

    private static string Corto(string? s) => string.IsNullOrEmpty(s) ? "(vacío)" : s[..Math.Min(8, s.Length)];
}

/// <summary>Resultado completo de la validación (se guarda y se muestra en la interfaz).</summary>
public sealed class ResultadoValidacion
{
    public bool IntegridadOk { get; set; }
    public string Sha256Calculado { get; set; } = "";
    public bool HuellaOk { get; set; }
    public bool FirmaOk { get; set; }
    public string DetalleFirma { get; set; } = "";
    public InfoCertificado? Certificado { get; set; }
    public List<string> Errores { get; } = [];
    public List<string> Avisos { get; } = [];

    /// <summary>Paquete íntegro y auténtico: los tres chequeos criptográficos pasaron.</summary>
    public bool Valido => IntegridadOk && HuellaOk && FirmaOk;

    /// <summary>Texto corto que pide la propuesta para la bandeja: "X.509 OK" / "Inválida".</summary>
    public string Etiqueta => Valido ? "X.509 OK" : "Inválida";
}

/// <summary>Datos legibles del certificado del emisor.</summary>
public sealed record InfoCertificado(
    string Sujeto, string Emisor, DateTime NoAntes, DateTime NoDespues,
    string TipoLlave, string Huella, bool Autofirmado, bool Vigente);

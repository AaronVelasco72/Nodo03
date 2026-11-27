using System.Security.Cryptography;
using Nodo03.Core.Cripto;

namespace Nodo03.Core.Protocolo;

/// <summary>
/// Validaciones 6 a 13 de la sección 13.1 del estándar v2.0, en orden y deteniéndose en la
/// primera falla. (Las 1–5 las hace <see cref="EmpaquetadorZip.Leer"/> y la 14, duplicados,
/// la base de datos.) Sirve para paquetes de CUALQUIER equipo y algoritmo.
/// </summary>
public static class ValidadorPaquete
{
    /// <summary>Valida y lanza <see cref="ErrorProtocolo"/> en la primera falla.</summary>
    public static InfoCertificado Validar(PaqueteLeido p, DateTime ahoraUtc)
    {
        var m = p.Manifiesto;

        // 6. Versión
        if (m.Version != Identificadores.VersionProtocolo)
            throw new ErrorProtocolo("E-VERSION", $"Versión '{m.Version}' no soportada; se espera 2.0.");

        // 7. Algoritmo según la tabla 4.1
        if (!Diccionario.Coinciden(m.AlgorithmId, m.AlgorithmCode))
            throw new ErrorProtocolo("E-ALGORITHM", $"algorithmId {m.AlgorithmId} y algorithmCode '{m.AlgorithmCode}' no coinciden con la tabla 4.1.");

        // 8. Integridad del contenido (y de cada parte si es multiparte)
        if (!Huellas.IgualesConstante(Huellas.Sha256Hex(p.Datos), m.EncryptedSha256))
            throw new ErrorProtocolo("E-HASH", "El SHA-256 del archivo de datos no coincide con encryptedSha256.");
        if (m.EncryptedSizeBytes != p.Datos.LongLength)
            throw new ErrorProtocolo("E-HASH", "encryptedSizeBytes no coincide con el tamaño real.");
        if (m.PayloadMode == ModosCarga.Multiparte)
        {
            var partes = EmpaquetadorZip.LeerPartes(p.Datos);
            foreach (var esperada in m.Parts!)
            {
                var real = partes.FirstOrDefault(x => x.Nombre == esperada.Name);
                if (real.Bytes is null || real.Bytes.LongLength != esperada.SizeBytes || !Huellas.IgualesConstante(Huellas.Sha256Hex(real.Bytes), esperada.Sha256))
                    throw new ErrorProtocolo("E-HASH", $"La parte {esperada.Name} no coincide con su SHA-256 o tamaño.");
            }
        }

        // 9. Hash canónico de publicParameters (8.5)
        if (!Huellas.IgualesConstante(ParametrosCanonicos.Hash(m.PublicParameters), m.PublicParametersSha256))
            throw new ErrorProtocolo("E-PARAMS-HASH", "publicParametersSha256 no corresponde al texto canónico de publicParameters.");

        // 10. Certificado: X.509 RSA-2048, CN = sourceNode, vigente
        System.Security.Cryptography.X509Certificates.X509Certificate2 cert;
        try { cert = IdentidadNodo.LeerPem(p.CertificadoPem); }
        catch (CryptographicException) { throw new ErrorProtocolo("E-CERT", "certificado.pem no es un X.509 PEM válido."); }
        using (cert)
        {
            if (IdentidadNodo.ProblemaCertificado(cert, m.SourceNode, ahoraUtc) is { } problema)
                throw new ErrorProtocolo("E-CERT", problema);

            // 11. Huella
            var huella = Huellas.HuellaCertificado(cert);
            if (!Huellas.IgualesConstante(huella, m.CertificateThumbprintSha256))
                throw new ErrorProtocolo("E-CERT-THUMBPRINT", "certificateThumbprintSha256 no corresponde a certificado.pem.");

            // 12. Firma sobre la cadena 8.4
            if (!FirmaManifiesto.Verificar(m, cert))
                throw new ErrorProtocolo("E-SIGNATURE", "La firma RSA-PSS-SHA256 no corresponde a la cadena de firma 8.4.");

            // 13. Ventana de ±10 minutos
            if (!Identificadores.DentroDeVentana(m.TimestampUtc, ahoraUtc))
                throw new ErrorProtocolo("E-TIMESTAMP", $"timestampUtc {m.TimestampUtc} está fuera de ±10 min del reloj del receptor.");

            return new InfoCertificado(cert.Subject, huella, cert.NotBefore.ToUniversalTime(), cert.NotAfter.ToUniversalTime());
        }
    }

    /// <summary>
    /// Igual que <see cref="Validar"/> pero devuelve el resultado en vez de lanzar (para el
    /// Verificador de la interfaz, que muestra la lista completa).
    /// </summary>
    public static ResultadoValidacion Revisar(byte[] zip, DateTime ahoraUtc)
    {
        try
        {
            var p = EmpaquetadorZip.Leer(zip);
            var info = Validar(p, ahoraUtc);
            return new ResultadoValidacion(true, null, null, "Paquete íntegro y firmado correctamente.", p.Manifiesto, info);
        }
        catch (ErrorProtocolo e)
        {
            Manifiesto? m = null;
            try { m = EmpaquetadorZip.Leer(zip).Manifiesto; } catch (ErrorProtocolo) { }
            return new ResultadoValidacion(false, e.Codigo, e.Status, e.Message, m, null);
        }
    }
}

/// <summary>Datos legibles del certificado del emisor.</summary>
public sealed record InfoCertificado(string Sujeto, string Huella, DateTime NoAntes, DateTime NoDespues);

/// <summary>Resultado completo para mostrar.</summary>
public sealed record ResultadoValidacion(bool Valido, string? Codigo, int? Status, string Detalle, Manifiesto? Manifiesto, InfoCertificado? Certificado);

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Nodo03.Core.Cripto;

/// <summary>
/// Identidad del nodo según la sección 7 del estándar v2.0: UN certificado X.509 RSA-2048
/// autofirmado con <c>CN=EQ03, OU=Equipo 03, O=Centro de Ciberseguridad, C=MX</c>.
/// </summary>
/// <remarks>
/// <para>Esta llave sirve para tres cosas: firmar manifiestos y peticiones (RSA-PSS), recibir
/// sobres CC-ENV-1 (RSA-OAEP) y, opcionalmente, HTTPS. Es DISTINTA de las llaves de algoritmo
/// (<c>keyId</c>, sección 12) que el nodo guarda como dueño de RSA y ECC.</para>
/// <para>Se guarda en <c>datos/identidad/identidad.cert.pem</c> y <c>identidad.key.pem</c>; la
/// privada va cifrada (PKCS#8 + AES-256-CBC + PBKDF2-SHA256, 100 000 iteraciones).</para>
/// <para><b>Concurrencia:</b> se guardan los PARÁMETROS de la llave y cada operación crea su
/// propia instancia de <see cref="RSA"/>, así varios hilos pueden firmar a la vez sin candados.</para>
/// </remarks>
public sealed class IdentidadNodo
{
    public string NodoId { get; }
    public int Equipo { get; }
    public X509Certificate2 Certificado { get; }

    /// <summary>Huella SHA-256 del certificado (hex MAYÚSCULAS).</summary>
    public string Huella { get; }

    private readonly RSAParameters _privada;

    private IdentidadNodo(int equipo, X509Certificate2 cert, RSAParameters privada)
    {
        Equipo = equipo;
        NodoId = Protocolo.Identificadores.NodoDeEquipo(equipo);
        Certificado = cert;
        Huella = Huellas.HuellaCertificado(cert);
        _privada = privada;
    }

    private static readonly object Candado = new();

    private static readonly PbeParameters CifradoLlave = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);

    /// <summary>Carga la identidad o la genera. Si el CN guardado no es el del equipo, genera una nueva.</summary>
    public static IdentidadNodo CargarOCrear(string carpeta, int equipo, string contrasena)
    {
        lock (Candado)
        {
            Directory.CreateDirectory(carpeta);
            var rutaCert = Path.Combine(carpeta, "identidad.cert.pem");
            var rutaLlave = Path.Combine(carpeta, "identidad.key.pem");
            var nodo = Protocolo.Identificadores.NodoDeEquipo(equipo);

            if (File.Exists(rutaCert) && File.Exists(rutaLlave))
            {
                var cert = X509Certificate2.CreateFromPem(File.ReadAllText(rutaCert));
                if (cert.GetNameInfo(X509NameType.SimpleName, false) == nodo && cert.NotAfter.ToUniversalTime() > DateTime.UtcNow)
                {
                    using var rsa = RSA.Create();
                    rsa.ImportFromEncryptedPem(File.ReadAllText(rutaLlave), contrasena);
                    return new IdentidadNodo(equipo, cert, rsa.ExportParameters(true));
                }
            }

            using var nueva = RSA.Create(2048);
            var certificado = CrearCertificado(nodo, equipo, nueva);
            File.WriteAllText(rutaCert, certificado.ExportCertificatePem() + "\n");
            File.WriteAllText(rutaLlave, nueva.ExportEncryptedPkcs8PrivateKeyPem(contrasena, CifradoLlave));
            return new IdentidadNodo(equipo, certificado, nueva.ExportParameters(true));
        }
    }

    /// <summary>Identidad solo en memoria (pruebas).</summary>
    public static IdentidadNodo CrearEnMemoria(int equipo)
    {
        using var rsa = RSA.Create(2048);
        return new IdentidadNodo(equipo, CrearCertificado(Protocolo.Identificadores.NodoDeEquipo(equipo), equipo, rsa), rsa.ExportParameters(true));
    }

    /// <summary>Certificado con todos los atributos obligatorios de la tabla de la sección 7.</summary>
    private static X509Certificate2 CrearCertificado(string nodo, int equipo, RSA rsa)
    {
        var sujeto = new X500DistinguishedName($"CN={nodo}, OU=Equipo {equipo:D2}, O=Centro de Ciberseguridad, C=MX");
        var req = new CertificateRequest(sujeto, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); // sha256WithRSAEncryption
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        // Número de serie aleatorio de 128 bits (≥ 64 bits), positivo y sin cero inicial.
        var serie = RandomNumberGenerator.GetBytes(16);
        serie[0] = (byte)((serie[0] & 0x7F) | 0x40);

        var ahora = DateTimeOffset.UtcNow;
        // Se adelanta el inicio 10 min para tolerar relojes de otros equipos (ventana de ±10 min).
        return req.Create(sujeto, X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            ahora.AddMinutes(-10), ahora.AddDays(365), serie);
    }

    public string CertificadoPem => Certificado.ExportCertificatePem() + "\n";

    /// <summary>Firma RSA-PSS-SHA256 (sal de 32 bytes) con la llave de identidad.</summary>
    public byte[] Firmar(byte[] datos)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(_privada);
        return rsa.SignData(datos, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    /// <summary>Abre la CEK de un sobre CC-ENV-1 (RSA-OAEP-SHA256).</summary>
    public byte[] Desenvolver(byte[] envuelta)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(_privada);
        return rsa.Decrypt(envuelta, RSAEncryptionPadding.OaepSHA256);
    }

    /// <summary>Lee un certificado PEM (texto o bytes).</summary>
    public static X509Certificate2 LeerPem(string pem) => X509Certificate2.CreateFromPem(pem.Trim('﻿', ' ', '\r', '\n', '\t'));
    public static X509Certificate2 LeerPem(byte[] pem) => LeerPem(Encoding.UTF8.GetString(pem));

    /// <summary>
    /// Revisa que un certificado ajeno cumpla la sección 7 (validación 10 de 13.1):
    /// X.509 RSA-2048, CN = <paramref name="nodoEsperado"/>, vigente. Devuelve el problema o null.
    /// </summary>
    public static string? ProblemaCertificado(X509Certificate2 cert, string nodoEsperado, DateTime ahoraUtc)
    {
        using var rsa = cert.GetRSAPublicKey();
        if (rsa is null) return "La llave del certificado no es RSA.";
        if (rsa.KeySize != 2048) return $"La llave es RSA-{rsa.KeySize}; el estándar pide RSA-2048.";
        var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
        if (cn != nodoEsperado) return $"El CN del certificado es '{cn}' y debería ser '{nodoEsperado}'.";
        if (ahoraUtc < cert.NotBefore.ToUniversalTime() || ahoraUtc > cert.NotAfter.ToUniversalTime())
            return "El certificado no está vigente.";
        return null;
    }
}

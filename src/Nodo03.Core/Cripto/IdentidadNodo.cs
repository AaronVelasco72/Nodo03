using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Nodo03.Core.Protocolo;

namespace Nodo03.Core.Cripto;

/// <summary>
/// La "identidad digital" del nodo: dos pares de llaves y sus certificados X.509.
/// </summary>
/// <remarks>
/// <para><b>¿Por qué dos certificados?</b> Un certificado X.509 solo puede llevar UNA llave
/// pública. Como al Equipo 3 le tocaron RSA y ECC, el nodo tiene:</para>
/// <list type="bullet">
///   <item><b>Certificado RSA-2048</b>: firma con RSA-PSS y recibe datos cifrados con RSA-OAEP.</item>
///   <item><b>Certificado EC P-256</b>: firma con ECDSA y recibe datos cifrados con ECDH (ECIES).</item>
/// </list>
/// <para>Cada paquete lleva en <c>certificado.pem</c> el certificado que corresponde a su
/// algoritmo, así el receptor sabe con qué llave pública verificar la firma.</para>
///
/// <para><b>Persistencia.</b> La primera vez que arranca el nodo se generan las llaves y se
/// guardan en <c>datos/identidad/</c>:</para>
/// <code>
///   rsa.cert.pem  rsa.key.pem   (llave privada PKCS#8 CIFRADA con AES-256 + contraseña)
///   ecc.cert.pem  ecc.key.pem
/// </code>
/// <para>Así la huella del certificado no cambia entre ejecuciones y los demás equipos
/// pueden reconocer al Nodo 03.</para>
///
/// <para><b>Concurrencia.</b> Las instancias de <see cref="RSA"/> y <see cref="ECDsa"/> no
/// garantizan ser seguras entre hilos. En lugar de compartir un objeto con candados, se
/// guardan los PARÁMETROS de la llave y cada operación crea su propia instancia
/// (<see cref="CrearRsaPrivada"/>, <see cref="CrearEcdsaPrivada"/>). Es barato y elimina
/// condiciones de carrera cuando llegan muchos paquetes a la vez.</para>
/// </remarks>
public sealed class IdentidadNodo
{
    /// <summary>Id lógico del nodo, ej. "NODO-03".</summary>
    public string NodoId { get; }

    /// <summary>Certificado público RSA.</summary>
    public X509Certificate2 CertificadoRsa { get; }

    /// <summary>Certificado público de curva elíptica (P-256).</summary>
    public X509Certificate2 CertificadoEcc { get; }

    // Parámetros privados en memoria (nunca salen del proceso ni van en el .zip).
    private readonly RSAParameters _rsaPrivada;
    private readonly ECParameters _eccPrivada;

    private IdentidadNodo(string nodoId, X509Certificate2 certRsa, RSAParameters rsa,
                          X509Certificate2 certEcc, ECParameters ecc)
    {
        NodoId = nodoId;
        CertificadoRsa = certRsa;
        CertificadoEcc = certEcc;
        _rsaPrivada = rsa;
        _eccPrivada = ecc;
    }

    // Candado de proceso: evita que dos hilos generen llaves al mismo tiempo en el arranque.
    private static readonly object CandadoCreacion = new();

    /// <summary>
    /// Carga la identidad desde <paramref name="carpeta"/> o la crea si no existe.
    /// </summary>
    /// <param name="carpeta">Carpeta donde viven los .pem (se crea si no existe).</param>
    /// <param name="nodoId">Id del nodo; va en el CN del certificado.</param>
    /// <param name="contrasena">Contraseña con la que se cifran las llaves privadas en disco.</param>
    public static IdentidadNodo CargarOCrear(string carpeta, string nodoId, string contrasena)
    {
        lock (CandadoCreacion)
        {
            Directory.CreateDirectory(carpeta);
            var (certRsa, rsa) = CargarOCrearRsa(carpeta, nodoId, contrasena);
            var (certEcc, ecc) = CargarOCrearEcc(carpeta, nodoId, contrasena);
            return new IdentidadNodo(nodoId, certRsa, rsa, certEcc, ecc);
        }
    }

    /// <summary>Crea una identidad solo en memoria (pruebas unitarias).</summary>
    public static IdentidadNodo CrearEnMemoria(string nodoId)
    {
        using var rsa = RSA.Create(2048);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new IdentidadNodo(nodoId,
            CrearCertificadoRsa(nodoId, rsa), rsa.ExportParameters(true),
            CrearCertificadoEcc(nodoId, ecdsa), ecdsa.ExportParameters(true));
    }

    // ------------------------------------------------------------------
    // Acceso por código de algoritmo
    // ------------------------------------------------------------------

    /// <summary>Certificado que corresponde al algoritmo ("RSA" o "ECC").</summary>
    public X509Certificate2 Certificado(string codigo) => codigo switch
    {
        CodigosAlgoritmo.Rsa => CertificadoRsa,
        CodigosAlgoritmo.Ecc => CertificadoEcc,
        _ => throw new NotSupportedException($"El Nodo 03 no tiene certificado para '{codigo}'."),
    };

    /// <summary>Certificado en formato PEM (-----BEGIN CERTIFICATE-----), listo para certificado.pem.</summary>
    public string CertificadoPem(string codigo) => Certificado(codigo).ExportCertificatePem() + "\n";

    /// <summary>Huella SHA-256 del certificado del algoritmo indicado.</summary>
    public string Huella(string codigo) => Huellas.HuellaCertificado(Certificado(codigo));

    /// <summary>¿La huella dada corresponde a alguno de mis certificados?</summary>
    public bool EsMiHuella(string? huella) =>
        Huellas.HuellasIguales(huella, Huella(CodigosAlgoritmo.Rsa)) ||
        Huellas.HuellasIguales(huella, Huella(CodigosAlgoritmo.Ecc));

    /// <summary>Nueva instancia RSA con la llave privada (el que llama debe hacer Dispose).</summary>
    public RSA CrearRsaPrivada()
    {
        var rsa = RSA.Create();
        rsa.ImportParameters(_rsaPrivada);
        return rsa;
    }

    /// <summary>Nueva instancia ECDSA con la llave privada (para firmar).</summary>
    public ECDsa CrearEcdsaPrivada() => ECDsa.Create(_eccPrivada);

    /// <summary>
    /// La MISMA llave EC vista como ECDH (para el acuerdo de claves al descifrar).
    /// Por eso el certificado EC declara KeyUsage = DigitalSignature + KeyAgreement.
    /// </summary>
    public ECDiffieHellman CrearEcdhPrivada() => ECDiffieHellman.Create(_eccPrivada);

    // ------------------------------------------------------------------
    // Generación y persistencia
    // ------------------------------------------------------------------

    /// <summary>
    /// Nombre distintivo (DN) del certificado. Va en el Subject y en el Issuer
    /// (es autofirmado). Cualquier lenguaje puede leerlo.
    /// </summary>
    private static X500DistinguishedName NombreDistintivo(string nodoId, string tipo) =>
        new($"CN={nodoId} {tipo}, OU=Equipo 3, O=Centro de Ciberseguridad UPIICSA, C=MX");

    private static X509Certificate2 CrearCertificadoRsa(string nodoId, RSA rsa)
    {
        // La autofirma del certificado usa PKCS#1 v1.5 (sha256WithRSAEncryption): es el
        // formato que TODAS las librerías saben leer. RSA-PSS se usa para el manifiesto.
        var req = new CertificateRequest(NombreDistintivo(nodoId, "RSA"), rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        AgregarExtensiones(req, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
    }

    private static X509Certificate2 CrearCertificadoEcc(string nodoId, ECDsa ecdsa)
    {
        var req = new CertificateRequest(NombreDistintivo(nodoId, "ECC"), ecdsa, HashAlgorithmName.SHA256);
        AgregarExtensiones(req, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
    }

    private static void AgregarExtensiones(CertificateRequest req, X509KeyUsageFlags usos)
    {
        // No es una CA: no puede firmar otros certificados.
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        // Para qué sirve la llave (crítica = el verificador debe respetarla).
        req.CertificateExtensions.Add(new X509KeyUsageExtension(usos, true));
        // Identificador de la llave (útil para depurar y para cadenas futuras).
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
    }

    /// <summary>Parámetros de cifrado de la llave privada en disco: AES-256-CBC + PBKDF2-SHA256 (100 000 iteraciones).</summary>
    private static readonly PbeParameters CifradoLlave =
        new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);

    private static (X509Certificate2, RSAParameters) CargarOCrearRsa(string carpeta, string nodoId, string pass)
    {
        var rutaCert = Path.Combine(carpeta, "rsa.cert.pem");
        var rutaLlave = Path.Combine(carpeta, "rsa.key.pem");
        if (File.Exists(rutaCert) && File.Exists(rutaLlave))
        {
            using var rsa = RSA.Create();
            rsa.ImportFromEncryptedPem(File.ReadAllText(rutaLlave), pass);
            return (X509Certificate2.CreateFromPem(File.ReadAllText(rutaCert)), rsa.ExportParameters(true));
        }
        using var nueva = RSA.Create(2048);
        var cert = CrearCertificadoRsa(nodoId, nueva);
        File.WriteAllText(rutaCert, cert.ExportCertificatePem());
        File.WriteAllText(rutaLlave, nueva.ExportEncryptedPkcs8PrivateKeyPem(pass, CifradoLlave));
        return (cert, nueva.ExportParameters(true));
    }

    private static (X509Certificate2, ECParameters) CargarOCrearEcc(string carpeta, string nodoId, string pass)
    {
        var rutaCert = Path.Combine(carpeta, "ecc.cert.pem");
        var rutaLlave = Path.Combine(carpeta, "ecc.key.pem");
        if (File.Exists(rutaCert) && File.Exists(rutaLlave))
        {
            using var ec = ECDsa.Create();
            ec.ImportFromEncryptedPem(File.ReadAllText(rutaLlave), pass);
            return (X509Certificate2.CreateFromPem(File.ReadAllText(rutaCert)), ec.ExportParameters(true));
        }
        using var nueva = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var cert = CrearCertificadoEcc(nodoId, nueva);
        File.WriteAllText(rutaCert, cert.ExportCertificatePem());
        File.WriteAllText(rutaLlave, nueva.ExportEncryptedPkcs8PrivateKeyPem(pass, CifradoLlave));
        return (cert, nueva.ExportParameters(true));
    }

    /// <summary>
    /// Lee un certificado PEM de otro nodo. Acepta el texto con o sin saltos de línea
    /// al final y con BOM. Lanza <see cref="CryptographicException"/> si no es válido.
    /// </summary>
    public static X509Certificate2 LeerCertificadoPem(string pem)
    {
        var limpio = pem.Trim('﻿', ' ', '\r', '\n', '\t');
        return X509Certificate2.CreateFromPem(limpio);
    }

    /// <summary>Lee un certificado PEM desde bytes UTF-8.</summary>
    public static X509Certificate2 LeerCertificadoPem(byte[] pem) => LeerCertificadoPem(Encoding.UTF8.GetString(pem));

    /// <summary>"RSA", "ECC" o null según el tipo de llave pública del certificado.</summary>
    public static string? TipoDeLlave(X509Certificate2 cert)
    {
        if (cert.GetRSAPublicKey() is { } r) { r.Dispose(); return CodigosAlgoritmo.Rsa; }
        if (cert.GetECDsaPublicKey() is { } e) { e.Dispose(); return CodigosAlgoritmo.Ecc; }
        return null;
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nodo03.Core.Protocolo;

namespace Nodo03.Core.Cripto;

/// <summary>
/// Firma digital del manifiesto (campo <c>manifestSignatureBase64</c>).
/// </summary>
/// <remarks>
/// <para><b>¿Qué se firma?</b> La propuesta permite dos opciones; para que TODOS los
/// lenguajes coincidan sin pelear con la serialización JSON, el Nodo 03 FIRMA siempre la
/// opción simple (texto UTF-8):</para>
/// <code>encryptedSha256 + "|" + certificateThumbprintSha256 + "|" + timestampUtc</code>
/// <para>Al VERIFICAR paquetes ajenos se aceptan ambas opciones: primero la cadena simple
/// y, si no cuadra, el "contenido canónico" del manifiesto (JSON sin el campo de firma,
/// llaves ordenadas alfabéticamente y sin espacios).</para>
///
/// <para><b>¿Qué garantiza?</b> Como <c>encryptedSha256</c> es la huella de datos.enc, firmar
/// esa huella equivale a firmar el contenido cifrado. Si alguien cambia un solo bit de
/// datos.enc, el SHA-256 cambia y la firma ya no corresponde. Si alguien cambia el
/// certificado por otro, la huella del certificado cambia y la firma tampoco corresponde.</para>
///
/// <para><b>Formatos de firma</b> (campo <c>signatureAlgorithm</c>):</para>
/// <list type="bullet">
///   <item><c>RSA-PSS-SHA256</c>: PSS con MGF1-SHA256 y salt de 32 bytes.</item>
///   <item><c>ECDSA-P256-SHA256</c>: firma en DER (secuencia ASN.1 r,s), que es lo que
///   Java, OpenSSL, Node y Python producen por defecto. .NET por defecto usa r||s
///   (IEEE P1363), por eso se pide DER explícitamente. Al verificar se aceptan ambos.</item>
/// </list>
/// </remarks>
public static class FirmaManifiesto
{
    public const string AlgoritmoRsa = "RSA-PSS-SHA256";
    public const string AlgoritmoEcc = "ECDSA-P256-SHA256";

    /// <summary>La cadena exacta que se firma (opción simple de la propuesta).</summary>
    public static string CadenaAFirmar(Manifiesto m) =>
        $"{m.EncryptedSha256}|{m.CertificateThumbprintSha256}|{m.TimestampUtc}";

    /// <summary>
    /// Firma el manifiesto con la llave del algoritmo indicado y llena
    /// <see cref="Manifiesto.SignatureAlgorithm"/> y <see cref="Manifiesto.ManifestSignatureBase64"/>.
    /// Requiere que <c>EncryptedSha256</c>, <c>CertificateThumbprintSha256</c> y
    /// <c>TimestampUtc</c> ya estén llenos.
    /// </summary>
    public static void Firmar(Manifiesto m, IdentidadNodo identidad, string codigo)
    {
        var datos = Encoding.UTF8.GetBytes(CadenaAFirmar(m));
        if (codigo == CodigosAlgoritmo.Rsa)
        {
            using var rsa = identidad.CrearRsaPrivada();
            m.SignatureAlgorithm = AlgoritmoRsa;
            m.ManifestSignatureBase64 = Convert.ToBase64String(
                rsa.SignData(datos, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        }
        else if (codigo == CodigosAlgoritmo.Ecc)
        {
            using var ecdsa = identidad.CrearEcdsaPrivada();
            m.SignatureAlgorithm = AlgoritmoEcc;
            m.ManifestSignatureBase64 = Convert.ToBase64String(
                ecdsa.SignData(datos, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        }
        else throw new NotSupportedException($"No se puede firmar con '{codigo}'.");
    }

    /// <summary>
    /// Verifica la firma de un manifiesto con la llave pública de <paramref name="certificado"/>.
    /// </summary>
    /// <param name="m">Manifiesto ya leído.</param>
    /// <param name="certificado">Certificado que venía en certificado.pem.</param>
    /// <param name="jsonOriginal">Bytes originales de manifest.json (para la variante canónica).</param>
    public static ResultadoFirma Verificar(Manifiesto m, X509Certificate2 certificado, byte[]? jsonOriginal = null)
    {
        byte[] firma;
        try { firma = Convert.FromBase64String(m.ManifestSignatureBase64 ?? ""); }
        catch (FormatException) { return ResultadoFirma.Falla("manifestSignatureBase64 no es Base64 válido."); }
        if (firma.Length == 0) return ResultadoFirma.Falla("El manifiesto no trae firma.");

        // Mensajes candidatos, en orden de preferencia.
        var candidatos = new List<(string nombre, byte[] datos)>
        {
            ("cadena sha|huella|fecha", Encoding.UTF8.GetBytes(CadenaAFirmar(m))),
        };
        if (jsonOriginal is not null && FormaCanonica(jsonOriginal) is { } canonica)
            candidatos.Add(("manifiesto canónico", canonica));

        var hash = HashSegunNombre(m.SignatureAlgorithm);

        using var rsa = certificado.GetRSAPublicKey();
        if (rsa is not null)
        {
            // PSS es lo estándar; PKCS#1 v1.5 se tolera por si otro equipo lo usó ("SHA256withRSA").
            foreach (var (nombre, datos) in candidatos)
            {
                if (rsa.VerifyData(datos, firma, hash, RSASignaturePadding.Pss))
                    return ResultadoFirma.Ok($"RSA-PSS-{hash.Name} sobre {nombre}");
                if (rsa.VerifyData(datos, firma, hash, RSASignaturePadding.Pkcs1))
                    return ResultadoFirma.Ok($"RSA-PKCS1-{hash.Name} sobre {nombre}");
            }
            return ResultadoFirma.Falla("La firma RSA no corresponde al certificado incluido.");
        }

        using var ecdsa = certificado.GetECDsaPublicKey();
        if (ecdsa is not null)
        {
            foreach (var (nombre, datos) in candidatos)
            {
                if (ecdsa.VerifyData(datos, firma, hash, DSASignatureFormat.Rfc3279DerSequence))
                    return ResultadoFirma.Ok($"ECDSA-{hash.Name} (DER) sobre {nombre}");
                if (ecdsa.VerifyData(datos, firma, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    return ResultadoFirma.Ok($"ECDSA-{hash.Name} (P1363) sobre {nombre}");
            }
            return ResultadoFirma.Falla("La firma ECDSA no corresponde al certificado incluido.");
        }

        return ResultadoFirma.Falla("Tipo de llave del certificado no soportado (ni RSA ni EC).");
    }

    /// <summary>Deduce el hash por el nombre ("...SHA512" -> SHA-512). Por defecto SHA-256.</summary>
    private static HashAlgorithmName HashSegunNombre(string? nombre)
    {
        var n = (nombre ?? "").ToUpperInvariant().Replace("-", "");
        if (n.Contains("SHA512")) return HashAlgorithmName.SHA512;
        if (n.Contains("SHA384")) return HashAlgorithmName.SHA384;
        return HashAlgorithmName.SHA256;
    }

    /// <summary>
    /// Forma canónica: el JSON sin "manifestSignatureBase64", con las llaves de cada objeto
    /// en orden alfabético (ordinal) y sin espacios. Null si el JSON no se puede leer.
    /// </summary>
    public static byte[]? FormaCanonica(byte[] json)
    {
        try
        {
            if (JsonNode.Parse(json) is not JsonObject raiz) return null;
            raiz.Remove("manifestSignatureBase64");
            var ordenado = Ordenar(raiz);
            return JsonSerializer.SerializeToUtf8Bytes(ordenado, new JsonSerializerOptions
            {
                WriteIndented = false,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            });
        }
        catch (JsonException) { return null; }
    }

    private static JsonNode? Ordenar(JsonNode? nodo) => nodo switch
    {
        JsonObject o => new JsonObject(o.OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => KeyValuePair.Create(p.Key, Ordenar(p.Value)))),
        JsonArray a => new JsonArray(a.Select(Ordenar).ToArray()),
        null => null,
        _ => JsonNode.Parse(nodo.ToJsonString()),
    };
}

/// <summary>Resultado de verificar una firma.</summary>
public sealed record ResultadoFirma(bool Valida, string Detalle)
{
    public static ResultadoFirma Ok(string detalle) => new(true, detalle);
    public static ResultadoFirma Falla(string detalle) => new(false, detalle);
}

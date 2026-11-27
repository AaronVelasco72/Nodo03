using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using Nodo03.Core.Protocolo;

namespace Nodo03.Core.Cripto;

/// <summary>
/// Sobre híbrido <c>CC-ENV-1</c> (sección 8.3): sirve para mandar secretos al proveedor y
/// para devolver resultados al solicitante sin depender de HTTPS.
/// </summary>
/// <remarks>
/// <code>
/// 1. CEK  = 32 bytes aleatorios, nonce = 12 bytes aleatorios
/// 2. AES-256-GCM(CEK, nonce, AAD = requestId o packetId en UTF-8) → cifrado + tag de 16 bytes
/// 3. wrappedKey = RSA-OAEP(SHA-256, MGF1-SHA256, sin etiqueta)(CEK) con la llave pública del DESTINATARIO
/// </code>
/// </remarks>
public sealed class SobreCc
{
    public const string Tipo = "CC-ENV-1";

    [JsonPropertyName("envelope")] public string Envelope { get; set; } = Tipo;
    [JsonPropertyName("recipientNode")] public string RecipientNode { get; set; } = "";
    [JsonPropertyName("recipientThumbprintSha256")] public string RecipientThumbprintSha256 { get; set; } = "";
    [JsonPropertyName("wrappedKeyBase64")] public string WrappedKeyBase64 { get; set; } = "";
    [JsonPropertyName("nonceBase64")] public string NonceBase64 { get; set; } = "";
    [JsonPropertyName("tagBase64")] public string TagBase64 { get; set; } = "";

    /// <summary>Texto cifrado. Se omite cuando va en <c>resultEnvelope</c> (el cifrado va en resultado.enc).</summary>
    [JsonPropertyName("ciphertextBase64")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CiphertextBase64 { get; set; }

    /// <summary>Cierra un sobre para el dueño de <paramref name="certDestino"/>.</summary>
    /// <param name="contenido">Bytes a proteger.</param>
    /// <param name="certDestino">Certificado de IDENTIDAD del destinatario (RSA-2048).</param>
    /// <param name="nodoDestino">nodeId del destinatario.</param>
    /// <param name="aad">requestId (secretos) o packetId (resultados).</param>
    /// <param name="cifradoAparte">Si es true, el cifrado NO se mete en el sobre (va en resultado.enc).</param>
    /// <param name="cifrado">Texto cifrado (siempre se devuelve).</param>
    public static SobreCc Cerrar(byte[] contenido, X509Certificate2 certDestino, string nodoDestino, string aad,
        bool cifradoAparte, out byte[] cifrado)
    {
        using var rsa = certDestino.GetRSAPublicKey() ?? throw new CryptographicException("El certificado destino no es RSA.");
        var cek = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        cifrado = new byte[contenido.Length];
        try
        {
            using (var gcm = new AesGcm(cek, 16))
                gcm.Encrypt(nonce, contenido, cifrado, tag, Encoding.UTF8.GetBytes(aad));
            return new SobreCc
            {
                RecipientNode = nodoDestino,
                RecipientThumbprintSha256 = Huellas.HuellaCertificado(certDestino),
                WrappedKeyBase64 = Convert.ToBase64String(rsa.Encrypt(cek, RSAEncryptionPadding.OaepSHA256)),
                NonceBase64 = Convert.ToBase64String(nonce),
                TagBase64 = Convert.ToBase64String(tag),
                CiphertextBase64 = cifradoAparte ? null : Convert.ToBase64String(cifrado),
            };
        }
        finally { CryptographicOperations.ZeroMemory(cek); }
    }

    /// <summary>
    /// Abre el sobre con la llave privada de identidad de <paramref name="yo"/>.
    /// Lanza E-ENV-RECIPIENT si no es para este nodo y E-ENV-DECRYPT si no se puede abrir.
    /// </summary>
    public byte[] Abrir(IdentidadNodo yo, string aad, byte[]? cifradoExterno = null)
    {
        if (Envelope != Tipo || RecipientNode != yo.NodoId || !Huellas.IgualesConstante(RecipientThumbprintSha256, yo.Huella))
            throw new ErrorProtocolo("E-ENV-RECIPIENT", $"El sobre está dirigido a {RecipientNode}, no a {yo.NodoId}.");
        byte[]? cek = null;
        try
        {
            var cifrado = cifradoExterno ?? Convert.FromBase64String(CiphertextBase64 ?? "");
            cek = yo.Desenvolver(Convert.FromBase64String(WrappedKeyBase64));
            var plano = new byte[cifrado.Length];
            using var gcm = new AesGcm(cek, 16);
            gcm.Decrypt(Convert.FromBase64String(NonceBase64), cifrado, Convert.FromBase64String(TagBase64), plano, Encoding.UTF8.GetBytes(aad));
            return plano;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            throw new ErrorProtocolo("E-ENV-DECRYPT", "No se pudo abrir el sobre CC-ENV-1: " + ex.Message);
        }
        finally { if (cek is not null) CryptographicOperations.ZeroMemory(cek); }
    }

    /// <summary>Copia sin el texto cifrado (lo que va en resultEnvelope).</summary>
    public SobreCc SinCifrado() => new()
    {
        Envelope = Envelope, RecipientNode = RecipientNode, RecipientThumbprintSha256 = RecipientThumbprintSha256,
        WrappedKeyBase64 = WrappedKeyBase64, NonceBase64 = NonceBase64, TagBase64 = TagBase64, CiphertextBase64 = null,
    };
}
